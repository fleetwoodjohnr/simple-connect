//! A session's remote desktops (see [`crate::desktop`]): starting the server,
//! the forward through the master, sign-in, and streaming to the webview with
//! backpressure.

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Notify, mpsc, oneshot};

use super::{AppError, Manager, Pending, SaveTarget, SecretPromptKind, Session, UiEvent};
use crate::desktop::probe::{self, PortKind, Probe, WindowsFacts};
use crate::desktop::{self, DesktopError, OpenRequest, Plan, Target, rdp, rfb};
use crate::profiles;
use crate::ssh::mux::Master;
use crate::ssh::shell::quote;

/// Output the webview hasn't acknowledged yet, before reading pauses.
const HIGH_WATER: usize = 4 * 1024 * 1024;
const LOW_WATER: usize = 1024 * 1024;

pub type Sink = crate::desktop::rdp::Sink;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DesktopState {
    /// `starting` (the server), `connecting` (the forward) or `signingIn`.
    Connecting {
        step: &'static str,
    },
    /// `latency_ms`: from opening the forward to the server's first byte.
    Connected {
        protocol: &'static str,
        latency_ms: u32,
    },
    Closed {
        error: Option<DesktopError>,
    },
}

pub(super) enum Cmd {
    /// Bytes from noVNC.
    Data(Vec<u8>),
    Rdp(rdp::Cmd),
}

pub(super) struct Conn {
    tx: mpsc::UnboundedSender<Cmd>,
    flow: Arc<Flow>,
    task: tokio::task::AbortHandle,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Soft flow control, as for terminals: once the webview is `HIGH_WATER` bytes
/// behind, reading waits for acknowledgements (at most 2 s at a time).
#[derive(Default)]
pub(super) struct Flow {
    unacked: AtomicUsize,
    acked: Notify,
}

impl Flow {
    fn sent(&self, n: usize) {
        self.unacked.fetch_add(n, Ordering::SeqCst);
    }

    fn ack(&self, n: usize) {
        let mut cur = self.unacked.load(Ordering::SeqCst);
        let left = loop {
            match self.unacked.compare_exchange_weak(cur, cur.saturating_sub(n), Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break cur.saturating_sub(n),
                Err(now) => cur = now,
            }
        };
        if left <= LOW_WATER {
            self.acked.notify_one();
        }
    }

    fn behind(&self) -> usize {
        self.unacked.load(Ordering::SeqCst)
    }

    async fn throttle(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while self.unacked.load(Ordering::SeqCst) > HIGH_WATER {
            if tokio::time::timeout_at(deadline, self.acked.notified()).await.is_err() {
                return;
            }
        }
    }
}

/// An `ssh -W` stdio forward through the master.
struct Forward {
    _child: Child,
    master: Arc<Master>,
    /// Where the master's log stood when the forward started.
    mark: u64,
    reader: ChildStdout,
    writer: ChildStdin,
}

/// Removes a prompt that's no longer awaited (the connection was closed).
struct PromptGuard<'a> {
    m: &'a Manager,
    id: u64,
}

impl Drop for PromptGuard<'_> {
    fn drop(&mut self) {
        let removed = self.m.prompts.lock().ok().and_then(|mut p| p.remove(&self.id)).is_some();
        if removed {
            self.m.emit(UiEvent::PromptClosed { id: self.id });
        }
    }
}

fn not_connected() -> DesktopError {
    DesktopError::new("disconnected", "The SSH connection was lost. Remote desktop reconnects when it's back.")
}

/// `DOMAIN\user` and `user@domain` → `user`, for comparing accounts.
fn account_name(u: &str) -> String {
    let u = u.rsplit('\\').next().unwrap_or(u);
    u.split('@').next().unwrap_or(u).to_lowercase()
}

impl Manager {
    fn desktop_event(&self, session: &str, desktop: &str, state: DesktopState) {
        self.emit(UiEvent::Desktop { session: session.into(), desktop: desktop.into(), state });
    }

    // ---- probing -------------------------------------------------------------

    /// Detects the remote desktop options of a connected session.
    pub async fn desktop_probe(&self, session: &str) -> Result<Probe, AppError> {
        let s = self.session(session)?;
        let master = s.master().ok_or(AppError::NotConnected)?;
        let windows = master.info.server_software.as_deref().is_some_and(|v| v.contains("Windows"));

        let checks = probe::RDP_PORTS.iter().map(|p| (*p, true)).chain(probe::VNC_PORTS.iter().map(|p| (*p, false)));
        let ports = futures_util::future::join_all(checks.map(|(p, rdp)| self.check_port(&s, p, rdp)));
        let facts = async {
            let run = |cmd: String| async move {
                self.remote_exec(session, cmd, Duration::from_secs(20))
                    .await
                    .map(|o| String::from_utf8_lossy(&o.stdout[..o.stdout.len().min(64 * 1024)]).into_owned())
                    .unwrap_or_default()
            };
            if windows {
                let (ts, ed, who) =
                    tokio::join!(run(probe::WINDOWS_RDP_QUERY.into()), run(probe::WINDOWS_EDITION_QUERY.into()), run("whoami".into()));
                let user = who.lines().next().map(|l| account_name(l.trim())).filter(|u| desktop::plain_name(u));
                let w = WindowsFacts {
                    rdp_enabled: probe::parse_windows_reg(&ts, "fDenyTSConnections").map(|v| v == "0x0"),
                    edition: probe::parse_windows_reg(&ed, "EditionID"),
                };
                (probe::Facts { user, ..Default::default() }, Some(w))
            } else {
                (probe::parse_posix(&run(format!("sh -c {}", quote(probe::POSIX_SCRIPT))).await), None)
            }
        };
        let (ports, (facts, win)) = tokio::join!(ports, facts);
        let ports: Vec<(u16, PortKind)> = ports.into_iter().flatten().collect();
        if let (Some(u), Ok(mut slot)) = (&facts.user, s.remote_user.lock()) {
            *slot = Some(u.clone());
        }
        Ok(probe::build(&facts, &ports, win.as_ref()))
    }

    async fn check_port(&self, s: &Session, port: u16, rdp: bool) -> Option<(u16, PortKind)> {
        let f = self.forward(s, &Target::Tcp(port)).await.ok()?;
        let mut io = tokio::io::join(f.reader, f.writer);
        let check = async { if rdp { probe::check_rdp(&mut io).await } else { probe::check_vnc(&mut io).await.then_some(PortKind::Vnc) } };
        tokio::time::timeout(Duration::from_secs(4), check).await.ok().flatten().map(|k| (port, k))
    }

    // ---- connections ---------------------------------------------------------

    /// Opens a remote desktop; progress arrives as [`UiEvent::Desktop`] and the
    /// stream (RFB bytes for VNC) through `sink`. Returns the desktop's id.
    pub fn desktop_open(
        self: &Arc<Self>,
        session: &str,
        req: OpenRequest,
        sink: impl Fn(Vec<u8>) + Send + Sync + 'static,
    ) -> Result<String, AppError> {
        let s = self.session(session)?;
        if s.master().is_none() {
            return Err(AppError::NotConnected);
        }
        let plan = req.validate().map_err(|e| AppError::Invalid(e.message))?;
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = mpsc::unbounded_channel();
        let flow = Arc::new(Flow::default());
        let (go_tx, go_rx) = oneshot::channel::<()>();
        let (me, s2, id2, flow2, sink): (_, _, _, _, Sink) = (self.clone(), s.clone(), id.clone(), flow.clone(), Arc::new(sink));
        let task = tokio::spawn(async move {
            if go_rx.await.is_err() {
                return;
            }
            let result = me.run_desktop(&s2, &id2, plan, sink, rx, flow2).await;
            // Dropping the entry aborts this task at its next await; there is none left.
            drop(s2.desktops.lock().ok().and_then(|mut d| d.remove(&id2)));
            me.desktop_event(&s2.id, &id2, DesktopState::Closed { error: result.err() });
        });
        if let Ok(mut d) = s.desktops.lock() {
            d.insert(id.clone(), Conn { tx, flow, task: task.abort_handle() });
        }
        let _ = go_tx.send(());
        Ok(id)
    }

    fn desktop_conn<T>(&self, session: &str, desktop: &str, f: impl FnOnce(&Conn) -> T) -> Result<T, AppError> {
        let s = self.session(session)?;
        let d = s.desktops.lock().map_err(|_| AppError::NotConnected)?;
        d.get(desktop).map(f).ok_or(AppError::NotConnected)
    }

    /// Bytes from the VNC viewer.
    pub fn desktop_write(&self, session: &str, desktop: &str, data: Vec<u8>) -> Result<(), AppError> {
        self.desktop_conn(session, desktop, |c| c.tx.send(Cmd::Data(data)).map_err(|_| AppError::NotConnected))?
    }

    /// RDP input events (at most 256 per call, checked by the caller).
    pub fn desktop_input(&self, session: &str, desktop: &str, events: Vec<rdp::Input>) -> Result<(), AppError> {
        self.desktop_rdp(session, desktop, rdp::Cmd::Input(events))
    }

    /// Asks an RDP server to change the desktop size (where it supports that).
    pub fn desktop_resize(&self, session: &str, desktop: &str, width: u32, height: u32) -> Result<(), AppError> {
        let clamp = |v: u32| u16::try_from(v.clamp(200, 8192)).unwrap_or(1024);
        self.desktop_rdp(session, desktop, rdp::Cmd::Resize(clamp(width), clamp(height)))
    }

    /// Offers text to the RDP server as the clipboard.
    pub fn desktop_clipboard(&self, session: &str, desktop: &str, text: String) -> Result<(), AppError> {
        self.desktop_rdp(session, desktop, rdp::Cmd::Clipboard(text))
    }

    fn desktop_rdp(&self, session: &str, desktop: &str, cmd: rdp::Cmd) -> Result<(), AppError> {
        self.desktop_conn(session, desktop, |c| c.tx.send(Cmd::Rdp(cmd)).map_err(|_| AppError::NotConnected))?
    }

    /// The webview has handled `bytes` of output.
    pub fn desktop_ack(&self, session: &str, desktop: &str, bytes: usize) {
        let _ = self.desktop_conn(session, desktop, |c| c.flow.ack(bytes));
    }

    pub fn desktop_close(&self, session: &str, desktop: &str) {
        let conn = self.session(session).ok().and_then(|s| s.desktops.lock().ok().and_then(|mut d| d.remove(desktop)));
        if conn.is_some() {
            self.desktop_event(session, desktop, DesktopState::Closed { error: None });
        }
    }

    /// Signs out of the virtual desktop: ends its session and programs.
    pub async fn desktop_end_virtual(&self, session: &str) -> Result<(), AppError> {
        let out = self.remote_exec(session, format!("sh -c {}", quote(desktop::END_VIRTUAL)), Duration::from_secs(15)).await?;
        if out.status.success() {
            return Ok(());
        }
        let err = String::from_utf8_lossy(&out.stderr);
        tracing::warn!(session, status = ?out.status, "ending the virtual desktop failed: {}", err.trim());
        Err(AppError::Invalid(format!("The virtual desktop couldn't be ended. {}", desktop::sanitize(&err, 200))))
    }

    async fn run_desktop(
        self: &Arc<Self>,
        s: &Arc<Session>,
        id: &str,
        plan: Plan,
        sink: Sink,
        rx: mpsc::UnboundedReceiver<Cmd>,
        flow: Arc<Flow>,
    ) -> Result<(), DesktopError> {
        let (target, _launcher) = self.desktop_target(s, id, &plan).await?;
        self.desktop_event(&s.id, id, DesktopState::Connecting { step: "connecting" });
        if plan.method.is_rdp() {
            self.run_rdp(s, id, &plan, target, sink, rx, flow).await
        } else {
            self.run_vnc(s, id, &plan, target, sink, rx, flow).await
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_rdp(
        &self,
        s: &Arc<Session>,
        id: &str,
        plan: &Plan,
        target: Target,
        sink: Sink,
        mut rx: mpsc::UnboundedReceiver<Cmd>,
        flow: Arc<Flow>,
    ) -> Result<(), DesktopError> {
        let user = self.desktop_user(s, plan.user.as_deref()).ok_or_else(|| {
            DesktopError::new("invalid", "Set the user name to sign in with in this connection's Remote desktop settings.")
        })?;
        let (master, mark, args) = self.forward_args(s, &target)?;
        let params =
            rdp::Params { width: plan.width, height: plan.height, quality: plan.quality, server_name: s.req.dest.host.as_str().into() };
        let send: rdp::Sink = {
            let flow = flow.clone();
            Arc::new(move |m: Vec<u8>| {
                flow.sent(m.len());
                sink(m);
            })
        };
        let behind = {
            let flow = flow.clone();
            Arc::new(move || flow.behind())
        };
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, mut events) = mpsc::unbounded_channel();
        let mut done = rdp::spawn(self.engine.ossh.ssh.clone(), args, params, user.clone(), send, behind, cmd_rx, event_tx);

        let autofilled = AtomicBool::new(false);
        let mut signed_in = false;
        let host = s.req.dest.host.for_destination();
        loop {
            tokio::select! {
                r = &mut done => {
                    let r = r.unwrap_or_else(|_| Err(DesktopError::new("protocol", "The Remote Desktop session stopped unexpectedly.")));
                    if !signed_in {
                        let rejected = matches!(&r, Err(e) if e.code == "auth") && autofilled.load(Ordering::SeqCst);
                        self.desktop_auth_done(s, false, rejected).await;
                    }
                    return match r {
                        // A stream that ended may be explained by the SSH side.
                        Err(e) if e.code == "ended" || e.code == "protocol" => {
                            let why = self.ended(s, &master, mark).await;
                            Err(if why.code == "ended" { e } else { why })
                        }
                        r => r,
                    };
                }
                Some(ev) = events.recv() => match ev {
                    rdp::Event::NeedPassword(reply) => {
                        self.desktop_event(&s.id, id, DesktopState::Connecting { step: "signingIn" });
                        let pw = self.desktop_secret(s, format!("Password for {user} on {host}"), Some(&user), &autofilled).await;
                        let _ = reply.send(pw);
                    }
                    rdp::Event::Connected { latency } => {
                        signed_in = true;
                        self.desktop_auth_done(s, true, false).await;
                        let latency_ms = u32::try_from(latency.as_millis()).unwrap_or(u32::MAX);
                        self.desktop_event(&s.id, id, DesktopState::Connected { protocol: "rdp", latency_ms });
                    }
                },
                Some(c) = rx.recv() => {
                    if let Cmd::Rdp(c) = c {
                        let _ = cmd_tx.send(c);
                    }
                }
            }
        }
    }

    /// Where to connect: given, or reported by the launch script that starts
    /// the server. The launcher's `ssh` must outlive the connection: closing
    /// its stdin is what stops a screen share.
    async fn desktop_target(&self, s: &Session, id: &str, plan: &Plan) -> Result<(Target, Option<Child>), DesktopError> {
        if let Some(t) = &plan.target {
            return Ok((t.clone(), None));
        }
        self.desktop_event(&s.id, id, DesktopState::Connecting { step: "starting" });
        let name = format!("share-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let Some(cmd) = desktop::launch_command(&plan.launch, plan.width, plan.height, &name) else {
            return Err(DesktopError::new("invalid", "Nothing to start."));
        };
        let master = s.master().ok_or_else(not_connected)?;
        let mut args = master.client_args(&s.req.dest);
        args.extend(["-T".into(), "--".into(), s.req.dest.host.as_str().into(), cmd.into()]);
        let mut child = Command::new(&self.engine.ossh.ssh)
            .args(args)
            .envs(master.env.clone())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| DesktopError::new("server", "OpenSSH could not be started.").with_details(e.to_string()))?;
        let stdout = child.stdout.take().ok_or_else(|| DesktopError::new("server", "OpenSSH could not be started."))?;
        let mut lines = BufReader::new(stdout).lines();
        let status = tokio::select! {
            _ = master.closed() => return Err(not_connected()),
            status = tokio::time::timeout(Duration::from_secs(30), lines.next_line()) => status,
        };
        match status {
            Ok(Ok(Some(line))) => Ok((desktop::parse_status(&line)?, Some(child))),
            Err(_) => Err(DesktopError::new("server", "The remote desktop server took too long to start.")),
            Ok(_) => {
                let mut err = Vec::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = tokio::time::timeout(Duration::from_secs(2), (&mut e).take(4096).read_to_end(&mut err)).await;
                }
                let err = String::from_utf8_lossy(&err).into_owned();
                if s.master().is_none() {
                    return Err(not_connected());
                }
                let unix = !err.contains("is not recognized") && !err.contains("CommandNotFound");
                let message = if unix {
                    "The remote desktop server couldn't be started."
                } else {
                    "This computer can't start a desktop server for you. Use its own remote desktop service instead."
                };
                Err(DesktopError::new("server", message).with_details(err))
            }
        }
    }

    /// `ssh -W` through the master, and where the master's log stood.
    fn forward_args(&self, s: &Session, target: &Target) -> Result<(Arc<Master>, u64, Vec<std::ffi::OsString>), DesktopError> {
        let master = s.master().ok_or_else(not_connected)?;
        let mark = master.log_mark();
        let mut args = master.client_args(&s.req.dest);
        args.extend(["-W".into(), target.forward_arg().into(), "--".into(), s.req.dest.host.as_str().into()]);
        Ok((master, mark, args))
    }

    async fn forward(&self, s: &Session, target: &Target) -> Result<Forward, DesktopError> {
        let (master, mark, args) = self.forward_args(s, target)?;
        let mut child = Command::new(&self.engine.ossh.ssh)
            .args(args)
            .envs(master.env.clone())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| DesktopError::new("server", "OpenSSH could not be started.").with_details(e.to_string()))?;
        let (Some(reader), Some(writer)) = (child.stdout.take(), child.stdin.take()) else {
            return Err(DesktopError::new("server", "OpenSSH could not be started."));
        };
        Ok(Forward { _child: child, master, mark, reader, writer })
    }

    /// Why a forward or stream ended. Only the master's log lines since the
    /// forward started (`mark`) count; concurrent forwards may add their own.
    async fn ended(&self, s: &Session, master: &Master, mark: u64) -> DesktopError {
        // The master logs the reason, and notices a dead connection, shortly after.
        tokio::time::sleep(Duration::from_millis(300)).await;
        if s.master().is_none() || s.closing.load(Ordering::SeqCst) {
            return not_connected();
        }
        let log = master.log_since(mark);
        if log.iter().any(|l| l.contains("open failed:")) {
            return desktop::forward_failure(&log);
        }
        DesktopError::new("ended", "The remote desktop session ended.")
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_vnc(
        &self,
        s: &Arc<Session>,
        id: &str,
        plan: &Plan,
        target: Target,
        sink: Sink,
        mut rx: mpsc::UnboundedReceiver<Cmd>,
        flow: Arc<Flow>,
    ) -> Result<(), DesktopError> {
        let Forward { _child: _forward, master, mark, mut reader, writer } = self.forward(s, &target).await?;
        let started = Instant::now();
        let mut first = [0u8; 12];
        if reader.read_exact(&mut first).await.is_err() {
            return Err(match self.ended(s, &master, mark).await {
                e if e.code == "ended" => DesktopError::new("unreachable", "The VNC server closed the connection before it started."),
                e => e,
            });
        }
        let latency_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);

        let mut io = tokio::io::join(std::io::Cursor::new(first.to_vec()).chain(reader), writer);
        let autofilled = AtomicBool::new(false);
        let user = plan.user.clone();
        let result = rfb::handshake(&mut io, |need| self.vnc_credentials(s, id, need, user.as_deref(), &autofilled)).await;
        match result {
            Ok(_) => self.desktop_auth_done(s, true, false).await,
            Err(e) => {
                let auth = matches!(e, rfb::RfbError::AuthFailed(_));
                self.desktop_auth_done(s, false, auth && autofilled.load(Ordering::SeqCst)).await;
                return Err(match e {
                    rfb::RfbError::AuthFailed(_) => DesktopError::new("auth", e.to_string()),
                    rfb::RfbError::Cancelled => DesktopError::new("cancelled", e.to_string()),
                    rfb::RfbError::Unsupported(_) => DesktopError::new("unsupported", e.to_string()),
                    rfb::RfbError::Refused(_) => DesktopError::new("server", e.to_string()),
                    rfb::RfbError::Version(_) | rfb::RfbError::Protocol(_) => DesktopError::new("protocol", e.to_string()),
                    rfb::RfbError::Io(_) => self.ended(s, &master, mark).await,
                });
            }
        }
        let (mut reader, mut writer) = io.into_inner();

        sink(rfb::HELLO.to_vec());
        self.desktop_event(&s.id, id, DesktopState::Connected { protocol: "vnc", latency_ms });

        let reading = async {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        sink(buf[..n].to_vec());
                        flow.sent(n);
                        flow.throttle().await;
                    }
                }
            }
        };
        let writing = async {
            let mut shim = rfb::ClientShim::default();
            while let Some(cmd) = rx.recv().await {
                let Cmd::Data(d) = cmd else { continue };
                let (reply, pass) = shim.feed(&d);
                if !reply.is_empty() {
                    sink(reply);
                }
                if !pass.is_empty() && (writer.write_all(pass).await.is_err() || writer.flush().await.is_err()) {
                    return;
                }
            }
        };
        tokio::select! {
            () = reading => {}
            () = writing => {}
        }
        Err(self.ended(s, &master, mark).await)
    }

    // ---- sign-in ---------------------------------------------------------------

    async fn vnc_credentials(
        &self,
        s: &Session,
        id: &str,
        need: rfb::Need,
        user: Option<&str>,
        autofilled: &AtomicBool,
    ) -> Option<rfb::Credentials> {
        self.desktop_event(&s.id, id, DesktopState::Connecting { step: "signingIn" });
        let host = s.req.dest.host.for_destination();
        match need {
            rfb::Need::VncPassword => {
                let password = self.desktop_secret(s, format!("VNC password for {host}"), None, autofilled).await?;
                Some(rfb::Credentials { user: String::new(), password })
            }
            rfb::Need::Account => {
                let user = self.desktop_user(s, user)?;
                let password = self.desktop_secret(s, format!("Password for {user} on {host}"), Some(&user), autofilled).await?;
                Some(rfb::Credentials { user, password })
            }
        }
    }

    /// The account to sign in as: the profile's remote desktop user, else the SSH user.
    pub(super) fn desktop_user(&self, s: &Session, requested: Option<&str>) -> Option<String> {
        requested
            .map(str::to_owned)
            .or_else(|| s.req.dest.user.as_ref().map(|u| u.as_str().to_owned()))
            .or_else(|| s.remote_user.lock().ok().and_then(|u| u.clone()))
    }

    /// A password for the remote desktop: the saved one; for the SSH account
    /// itself, the SSH password (when reuse is on: the same computer already
    /// received it); otherwise asked for. After a failed automatic attempt the
    /// next attempt asks.
    pub(super) async fn desktop_secret(
        &self,
        s: &Session,
        prompt: String,
        account: Option<&str>,
        autofilled: &AtomicBool,
    ) -> Option<SecretString> {
        let retry = s.desktop_autofill_failed.swap(false, Ordering::SeqCst);
        if !retry {
            let saved_ref = |desktop: bool| {
                let pid = s.req.profile_id.as_ref()?;
                let c = self.db.lock().ok()?;
                if desktop { profiles::desktop_secret_ref(&c, pid) } else { profiles::secret_ref(&c, pid) }.ok().flatten()
            };
            if let Some(r) = saved_ref(true)
                && let Some(secret) = self.get_secret(crate::security::desktop_secret_id(&r, account.is_some())).await
            {
                autofilled.store(true, Ordering::SeqCst);
                return Some(secret);
            }
            let ssh_user = self.desktop_user(s, None);
            let same = account.zip(ssh_user).is_some_and(|(a, b)| account_name(a) == account_name(&b));
            if same && self.reuse_enabled(s) {
                let login = s.login_password.lock().ok().and_then(|p| p.clone());
                let secret = match login {
                    Some(l) => Some(l),
                    None => match saved_ref(false) {
                        Some(r) => self.get_secret(r).await,
                        None => None,
                    },
                };
                if secret.is_some() {
                    autofilled.store(true, Ordering::SeqCst);
                    return secret;
                }
            }
        }

        let id = self.next_id();
        let (reply, answer) = oneshot::channel();
        let save = s.req.profile_id.clone().map(|pid| SaveTarget::DesktopPassword(pid, account.is_some()));
        let can_save = save.is_some() && self.store().is_ok();
        if let Ok(mut p) = self.prompts.lock() {
            p.insert(id, Pending::Secret { session: s.id.clone(), save, login: false, reply });
        }
        let _guard = PromptGuard { m: self, id };
        self.emit(UiEvent::SecretPrompt { id, session: s.id.clone(), kind: SecretPromptKind::Password, prompt, can_save });
        let value = answer.await.ok().flatten()?;
        Some(SecretString::from(value.as_str().to_owned()))
    }

    /// Saves a password the user asked to remember once it worked, or drops it.
    pub(super) async fn desktop_auth_done(&self, s: &Session, ok: bool, autofill_failed: bool) {
        let pending: Vec<_> = s
            .save_on_success
            .lock()
            .map(|mut v| {
                let (desk, rest): (Vec<_>, Vec<_>) =
                    std::mem::take(&mut *v).into_iter().partition(|(t, _)| matches!(t, SaveTarget::DesktopPassword(..)));
                *v = rest;
                desk
            })
            .unwrap_or_default();
        s.desktop_autofill_failed.store(autofill_failed, Ordering::SeqCst);
        if ok {
            for (target, secret) in pending {
                if let Err(e) = self.save_secret(target, secret).await {
                    tracing::warn!(session = %s.id, "could not save remote desktop password: {e}");
                }
            }
        }
    }
}

pub(super) type Desktops = Mutex<std::collections::HashMap<String, Conn>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_compare_by_name() {
        assert_eq!(account_name("CORP\\Alice"), "alice");
        assert_eq!(account_name("alice@corp.example"), "alice");
        assert_eq!(account_name("alice"), "alice");
    }

    #[tokio::test]
    async fn flow_waits_for_acks() {
        let flow = Arc::new(Flow::default());
        flow.sent(HIGH_WATER + 1);
        let f2 = flow.clone();
        let waiter = tokio::spawn(async move {
            let t = Instant::now();
            f2.throttle().await;
            t.elapsed()
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        flow.ack(HIGH_WATER);
        let waited = waiter.await.unwrap();
        assert!(waited >= Duration::from_millis(90) && waited < Duration::from_secs(1), "{waited:?}");
    }
}
