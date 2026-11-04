//! Remote desktop end to end against real servers in podman (tests/desktop):
//! x0vncserver, wayvnc and Xvnc started over SSH, an existing VNC server with a
//! password, and the failure cases.
//! Run with: `cargo test -p simple-connect-core --test desktop_it -- --ignored`
#![allow(clippy::unwrap_used)]

mod support;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::ExposeSecret;
use simple_connect_core::app::desktop::DesktopState;
use simple_connect_core::app::{ConnectRequest, Manager, Ui, UiEvent};
use simple_connect_core::desktop::{Method, OpenRequest, Quality};
use simple_connect_core::paths::AppPaths;
use simple_connect_core::profiles::{self, AuthMethod, ProfileDraft};
use simple_connect_core::security::{CredentialStore, MemoryStore};
use simple_connect_core::settings::Settings;
use simple_connect_core::ssh::engine::Engine;
use simple_connect_core::ssh::mux::Destination;
use simple_connect_core::validate::{Host, User};
use support::{Sshd, assert_no_process_args_contain};
use tokio::sync::mpsc;

struct TestUi(mpsc::UnboundedSender<UiEvent>);
impl Ui for TestUi {
    fn emit(&self, e: UiEvent) {
        let _ = self.0.send(e);
    }
}

#[derive(Default)]
struct Log {
    connected: bool,
    statuses: Vec<String>,
    /// desktop id → latest state
    desktops: Vec<(String, DesktopState)>,
    vnc_prompts: Vec<String>,
}

impl Log {
    fn state(&self, id: &str) -> Option<&DesktopState> {
        self.desktops.iter().rev().find(|(d, _)| d == id).map(|(_, s)| s)
    }
}

async fn wait_for(log: &Arc<Mutex<Log>>, what: &str, f: impl Fn(&Log) -> bool) {
    for _ in 0..300 {
        if f(&log.lock().unwrap()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}; desktops: {:?}", log.lock().unwrap().desktops);
}

struct Env {
    m: Arc<Manager>,
    log: Arc<Mutex<Log>>,
    store: Arc<MemoryStore>,
    db: Arc<Mutex<simple_connect_core::storage::rusqlite::Connection>>,
    profile: String,
    /// Answers for remote desktop password prompts, in order.
    answers: Arc<Mutex<VecDeque<(String, bool)>>>,
    _dir: tempfile::TempDir,
}

async fn env(sshd: &Sshd, user: &str) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(dir.path());
    paths.ensure().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let (engine, helper_events) =
        Engine::start_with_home(paths, PathBuf::from(env!("CARGO_BIN_EXE_sc-test-helper")), Some(home)).await.unwrap();
    let mut conn = simple_connect_core::storage::open_in_memory().unwrap();
    let draft = ProfileDraft {
        name: "Desktop box".into(),
        host: "127.0.0.1".into(),
        port: Some(u32::from(sshd.port)),
        username: Some(user.into()),
        auth: AuthMethod::Password,
        ..Default::default()
    };
    let profile = profiles::create(&mut conn, &draft).unwrap().id;
    let db = Arc::new(Mutex::new(conn));
    let settings = Settings { include_user_ssh_config: false, ..Settings::default() };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let m = Manager::new(Arc::new(engine), Arc::new(TestUi(tx)), db.clone(), settings, helper_events);
    let store = Arc::new(MemoryStore::default());
    m.set_store(Some(store.clone()));
    let log: Arc<Mutex<Log>> = Arc::default();
    let answers: Arc<Mutex<VecDeque<(String, bool)>>> = Arc::default();
    {
        let (m, log, answers) = (m.clone(), log.clone(), answers.clone());
        tokio::spawn(async move {
            while let Some(e) = rx.recv().await {
                match e {
                    UiEvent::Session { status, .. } => {
                        let s = format!("{status:?}");
                        let mut l = log.lock().unwrap();
                        l.connected = s == "Connected";
                        l.statuses.push(s);
                    }
                    UiEvent::HostKeyPrompt { id, .. } => m.answer_host_key(id, true, None).await.unwrap(),
                    UiEvent::SecretPrompt { id, prompt, .. } if prompt.ends_with("password: ") => {
                        m.answer_secret(id, Some("correct horse".into()), true).unwrap();
                    }
                    UiEvent::SecretPrompt { id, prompt, .. } => {
                        log.lock().unwrap().vnc_prompts.push(prompt);
                        let a = answers.lock().unwrap().pop_front();
                        if let Some((pw, _)) = &a {
                            assert_no_process_args_contain(pw);
                        }
                        let save = a.as_ref().is_some_and(|a| a.1);
                        m.answer_secret(id, a.map(|a| a.0), save).unwrap();
                    }
                    UiEvent::Desktop { desktop, state, .. } => log.lock().unwrap().desktops.push((desktop, state)),
                    _ => {}
                }
            }
        });
    }
    Env { m, log, store, db, profile, answers, _dir: dir }
}

fn connect(e: &Env, sshd: &Sshd, user: &str) -> String {
    e.m.connect(ConnectRequest {
        dest: Destination {
            host: Host::parse("127.0.0.1").unwrap(),
            user: Some(User::parse(user).unwrap()),
            port: Some(sshd.port),
            jump: Vec::new(),
            identity_file: None,
            auth: AuthMethod::Password,
        },
        label: "Desktop box".into(),
        profile_id: Some(e.profile.clone()),
        legacy_crypto: false,
        keepalive_secs: Some(2),
        start_dir: None,
        reuse_password: None,
    })
}

fn request(method: Method) -> OpenRequest {
    OpenRequest {
        method,
        port: None,
        display: None,
        wayland: None,
        session: None,
        width: 1280,
        height: 800,
        user: None,
        quality: Quality::Auto,
    }
}

/// Collects what the backend streams to the "webview".
#[derive(Clone, Default)]
struct Screen(Arc<Mutex<Vec<u8>>>);

impl Screen {
    fn sink(&self) -> impl Fn(Vec<u8>) + Send + Sync + 'static {
        let buf = self.0.clone();
        move |b| buf.lock().unwrap().extend(b)
    }
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
    async fn wait(&self, n: usize) -> Vec<u8> {
        for _ in 0..100 {
            if self.0.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.take()
    }
}

/// Collects the RDP viewer's messages one by one.
#[derive(Clone, Default)]
struct RdpScreen(Arc<Mutex<Vec<Vec<u8>>>>);

impl RdpScreen {
    fn sink(&self) -> impl Fn(Vec<u8>) + Send + Sync + 'static {
        let msgs = self.0.clone();
        move |m| msgs.lock().unwrap().push(m)
    }
    async fn wait_for(&self, what: &str, f: impl Fn(&[Vec<u8>]) -> bool) {
        for _ in 0..300 {
            if f(&self.0.lock().unwrap()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for {what}");
    }
}

/// Plays noVNC: the synthetic None handshake, ClientInit, and a full update.
/// Returns the remote screen size.
async fn speak_rfb(m: &Manager, sid: &str, id: &str, screen: &Screen) -> (u16, u16) {
    assert_eq!(screen.wait(12).await, b"RFB 003.008\n");
    m.desktop_write(sid, id, b"RFB 003.008\n".to_vec()).unwrap();
    assert_eq!(screen.wait(2).await, [1, 1], "only security None is offered to the webview");
    m.desktop_write(sid, id, vec![1]).unwrap();
    assert_eq!(screen.wait(4).await, [0, 0, 0, 0]);
    m.desktop_write(sid, id, vec![1]).unwrap(); // ClientInit, shared
    let init = screen.wait(24).await;
    assert!(init.len() >= 24, "ServerInit: {init:?}");
    let (w, h) = (u16::from_be_bytes([init[0], init[1]]), u16::from_be_bytes([init[2], init[3]]));
    // FramebufferUpdateRequest for the whole screen: pixels arrive.
    let mut req = vec![3, 0, 0, 0, 0, 0];
    req.extend(w.to_be_bytes());
    req.extend(h.to_be_bytes());
    m.desktop_write(sid, id, req).unwrap();
    let update = screen.wait(1000).await;
    assert_eq!(update.first(), Some(&0), "FramebufferUpdate");
    assert!(update.len() > 1000);
    m.desktop_ack(sid, id, 1 << 30);
    (w, h)
}

fn is_connected(l: &Log, id: &str) -> bool {
    matches!(l.state(id), Some(DesktopState::Connected { .. }))
}

fn closed_code(l: &Log, id: &str) -> Option<String> {
    match l.state(id) {
        Some(DesktopState::Closed { error }) => Some(error.as_ref().map(|e| e.code.to_owned()).unwrap_or_default()),
        _ => None,
    }
}

async fn wait_closed(log: &Arc<Mutex<Log>>, id: &str) -> String {
    wait_for(log, "closed", |l| closed_code(l, id).is_some()).await;
    closed_code(&log.lock().unwrap(), id).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn remote_desktops() {
    let sshd = Sshd::start_desktop();
    let e = env(&sshd, "pw").await;
    let m = e.m.clone();
    let sid = connect(&e, &sshd, "pw");
    wait_for(&e.log, "connected", |l| l.connected).await;

    for _ in 0..50 {
        if sshd.exec("root", "netstat -ltn").contains("127.0.0.1:3389") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Detection: the X11 screen, the Wayland session, xrdp and virtual desktops.
    let probe = m.desktop_probe(&sid).await.unwrap();
    let methods: Vec<_> = probe.offers.iter().map(|o| (o.method, o.display, o.wayland.clone(), o.port)).collect();
    assert_eq!(probe.os, "linux");
    assert!(methods.contains(&(Method::X11, Some(0), None, None)), "{probe:#?}");
    assert!(methods.contains(&(Method::Wayland, None, Some("wayland-1".into()), None)), "{probe:#?}");
    assert!(methods.contains(&(Method::Rdp, None, None, Some(3389))), "{probe:#?}");
    assert!(methods.iter().any(|m| m.0 == Method::Virtual), "{probe:#?}");
    assert_eq!(probe.offers[0].method, Method::X11, "the screen in use comes first");
    assert_eq!(probe.user.as_deref(), Some("pw"));

    // Sharing the X11 screen: x0vncserver over a private socket, gone after closing.
    let screen = Screen::default();
    let mut r = request(Method::X11);
    r.display = Some(0);
    let id = m.desktop_open(&sid, r, screen.sink()).unwrap();
    wait_for(&e.log, "x11 share", |l| is_connected(l, &id)).await;
    assert_eq!(speak_rfb(&m, &sid, &id, &screen).await, (1024, 768));
    assert!(sshd.exec("root", "netstat -ltn").lines().all(|l| !l.contains(":59")), "no VNC port is opened");
    assert!(sshd.exec("pw", "ls -l ~/.cache/simple-connect/rd/").contains("srw-------"));
    m.desktop_close(&sid, &id);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(sshd.exec("root", "pgrep x0vncserver || true"), "", "sharing stops with the connection");

    // Sharing the wlroots session with wayvnc.
    let screen = Screen::default();
    let mut r = request(Method::Wayland);
    r.wayland = Some("wayland-1".into());
    let id = m.desktop_open(&sid, r, screen.sink()).unwrap();
    wait_for(&e.log, "wayland share", |l| is_connected(l, &id)).await;
    assert_eq!(speak_rfb(&m, &sid, &id, &screen).await, (800, 600));
    m.desktop_close(&sid, &id);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(sshd.exec("root", "pgrep wayvnc || true"), "");

    // A virtual desktop at the requested size, which outlives the connection.
    let screen = Screen::default();
    let mut r = request(Method::Virtual);
    r.session = Some("openbox".into());
    let id = m.desktop_open(&sid, r.clone(), screen.sink()).unwrap();
    wait_for(&e.log, "virtual desktop", |l| is_connected(l, &id)).await;
    assert_eq!(speak_rfb(&m, &sid, &id, &screen).await, (1280, 800));
    let xvnc = sshd.exec("root", "pgrep -x Xvnc");
    assert!(!xvnc.is_empty());
    m.desktop_close(&sid, &id);

    // The network drops every SSH connection: SSH reconnects, the virtual desktop is still there.
    sshd.drop_connections();
    wait_for(&e.log, "reconnected", |l| l.statuses.iter().any(|s| s.starts_with("Reconnecting")) && l.connected).await;
    assert!(m.desktop_probe(&sid).await.unwrap().offers.iter().any(|o| o.method == Method::Virtual && o.running));
    let screen = Screen::default();
    let id = m.desktop_open(&sid, r, screen.sink()).unwrap();
    wait_for(&e.log, "reattached", |l| is_connected(l, &id)).await;
    assert_eq!(speak_rfb(&m, &sid, &id, &screen).await, (1280, 800));
    assert_eq!(sshd.exec("root", "pgrep -x Xvnc"), xvnc, "the same desktop");
    // Signing out of it ends the desktop and the open connection.
    m.desktop_end_virtual(&sid).await.unwrap();
    assert_eq!(wait_closed(&e.log, &id).await, "ended");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(sshd.exec("root", "pgrep -x Xvnc || true"), "");

    // An existing VNC server with a password: wrong, then right (and saved).
    sshd.exec(
        "pw",
        "mkdir -p ~/.vnc && echo 'vnc-s3cret' | vncpasswd -f > ~/.vnc/passwd && chmod 600 ~/.vnc/passwd && \
         (Xvnc :31 -rfbport 5931 -localhost -SecurityTypes VncAuth -PasswordFile ~/.vnc/passwd -geometry 640x480 >/dev/null 2>&1 &)",
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut r = request(Method::Vnc);
    r.port = Some(5931);
    e.answers.lock().unwrap().push_back(("wrong-pw".into(), false));
    let id = m.desktop_open(&sid, r.clone(), Screen::default().sink()).unwrap();
    assert_eq!(wait_closed(&e.log, &id).await, "auth");
    e.answers.lock().unwrap().push_back(("vnc-s3cret".into(), true));
    let screen = Screen::default();
    let id = m.desktop_open(&sid, r.clone(), screen.sink()).unwrap();
    wait_for(&e.log, "vnc auth", |l| is_connected(l, &id)).await;
    assert_eq!(speak_rfb(&m, &sid, &id, &screen).await, (640, 480));
    m.desktop_close(&sid, &id);
    let saved = profiles::desktop_secret_ref(&e.db.lock().unwrap(), &e.profile).unwrap().unwrap();
    let saved = simple_connect_core::security::desktop_secret_id(&saved, false);
    assert_eq!(e.store.get(&saved).unwrap().unwrap().expose_secret(), "vnc-s3cret", "saved once it worked");
    // Next time the saved password is used without asking.
    let asked = e.log.lock().unwrap().vnc_prompts.len();
    let screen = Screen::default();
    let id = m.desktop_open(&sid, r, screen.sink()).unwrap();
    wait_for(&e.log, "vnc saved", |l| is_connected(l, &id)).await;
    assert_eq!(e.log.lock().unwrap().vnc_prompts.len(), asked);
    m.desktop_close(&sid, &id);

    // Nothing on the port.
    let mut r = request(Method::Vnc);
    r.port = Some(5999);
    let id = m.desktop_open(&sid, r, Screen::default().sink()).unwrap();
    assert_eq!(wait_closed(&e.log, &id).await, "refused");

    // RDP to xrdp over TLS. The account is the SSH account, so the SSH password
    // is reused (the same computer already received it) and nothing is asked.
    let screen = RdpScreen::default();
    let mut r = request(Method::Rdp);
    (r.port, r.width, r.height) = (Some(3389), 1024, 768);
    let asked = e.log.lock().unwrap().vnc_prompts.len();
    let id = m.desktop_open(&sid, r.clone(), screen.sink()).unwrap();
    wait_for(&e.log, "rdp", |l| is_connected(l, &id)).await;
    assert_eq!(e.log.lock().unwrap().vnc_prompts.len(), asked, "the SSH password was reused");
    screen.wait_for("desktop size", |m| m.first().is_some_and(|f| f.as_slice() == [2, 0x00, 0x04, 0x00, 0x03])).await;
    // Rectangles of opaque RGBA that show the session: xrdp's default xterm, white on black.
    screen
        .wait_for("pixels", |m| {
            let mut colours = std::collections::HashSet::new();
            for r in m.iter().filter(|r| r.first() == Some(&1) && r.len() > 9) {
                let (w, h) = (u16::from_le_bytes([r[5], r[6]]) as usize, u16::from_le_bytes([r[7], r[8]]) as usize);
                assert_eq!(r.len(), 9 + w * h * 4, "rectangle size");
                colours.extend(r[9..].chunks(4).step_by(97).map(|p| (p[0], p[1], p[2], p[3])));
            }
            colours.contains(&(0, 0, 0, 0xff)) && colours.contains(&(0xff, 0xff, 0xff, 0xff))
        })
        .await;
    m.desktop_ack(&sid, &id, 1 << 30);
    let ev: Vec<simple_connect_core::desktop::rdp::Input> = serde_json::from_str(
        r#"[{"type":"mouse","x":100,"y":100},{"type":"button","button":"left","down":true},{"type":"button","button":"left","down":false},
            {"type":"key","scancode":30,"extended":false,"down":true},{"type":"key","scancode":30,"extended":false,"down":false},{"type":"releaseAll"}]"#,
    )
    .unwrap();
    m.desktop_input(&sid, &id, ev).unwrap();
    // Display Control resize: the server reactivates the session at the new size.
    m.desktop_resize(&sid, &id, 1280, 720).unwrap();
    screen.wait_for("resized", |m| m.iter().any(|f| f.as_slice() == [2, 0x00, 0x05, 0xd0, 0x02])).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(is_connected(&e.log.lock().unwrap(), &id), "input and resize keep the session going: {:?}", e.log.lock().unwrap().state(&id));
    m.desktop_close(&sid, &id);

    // An RDP server that only offers the legacy RC4 security is refused.
    sshd.exec(
        "root",
        "sed -i 's/^security_layer=.*/security_layer=rdp/' /etc/xrdp/xrdp.ini && xrdp --kill; sleep 1; rm -f /run/xrdp.pid; xrdp; true",
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(m.desktop_probe(&sid).await.unwrap().notes.iter().any(|n| n.contains("outdated encryption")));
    let id = m.desktop_open(&sid, r, RdpScreen::default().sink()).unwrap();
    assert_eq!(wait_closed(&e.log, &id).await, "unsupported");

    m.disconnect(&sid).await.unwrap();

    // A server that forbids forwarding.
    let e2 = env(&sshd, "nofwd").await;
    let sid2 = connect(&e2, &sshd, "nofwd");
    wait_for(&e2.log, "nofwd connected", |l| l.connected).await;
    let mut r = request(Method::Vnc);
    r.port = Some(5931);
    let id = e2.m.desktop_open(&sid2, r, Screen::default().sink()).unwrap();
    assert_eq!(wait_closed(&e2.log, &id).await, "forwarding");
    e2.m.disconnect(&sid2).await.unwrap();
}
