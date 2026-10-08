//! Bridge between `ssh` and the application for prompts and host-key decisions.
//!
//! `ssh` re-executes this application's binary as `SSH_ASKPASS` and as the
//! `KnownHostsCommand`. In that mode [`run_if_helper`] forwards the request over a
//! Unix socket in the private runtime directory and prints the answer. The server
//! checks the peer's UID and a per-session random token that only that `ssh`
//! process tree knows (it is passed through the child's environment).
//!
//! Every failure path in the helper exits non-zero with no output, which makes
//! `ssh` abort: host verification and prompts fail closed.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use super::known_hosts::OfferedKey;

pub const ENV_SOCK: &str = "SC_HELPER_SOCK";
pub const ENV_TOKEN: &str = "SC_HELPER_TOKEN";
pub const KNOWN_HOSTS_FLAG: &str = "--sc-known-hosts";

const MAX_MESSAGE: u64 = 64 * 1024;
/// sshd's default LoginGraceTime is 120 s; waiting longer than this is pointless.
const DECISION_TIMEOUT: Duration = Duration::from_secs(300);

/// `SSH_ASKPASS_PROMPT`: unset → secret input, `confirm` → yes/no, `none` → notice
/// (e.g. "Confirm user presence for key …" while a security key waits for a touch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptKind {
    Secret,
    Confirm,
    Notify,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Request {
    Askpass { token: String, prompt: String, prompt_kind: PromptKind },
    KnownHost { token: String, invocation: String, host: String, key_type: String, key_b64: String },
}

#[derive(Serialize, Deserialize)]
struct Response {
    ok: bool,
    output: Option<String>,
}

// ---------------------------------------------------------------------------
// Client side: runs inside the short-lived helper process.
// ---------------------------------------------------------------------------

/// Returns `Some(exit_code)` when this process was started by `ssh` as a helper,
/// `None` for a normal application start.
pub fn run_if_helper() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    let token = std::env::var(ENV_TOKEN).ok();
    let req = if args.get(1).map(String::as_str) == Some(KNOWN_HOSTS_FLAG) {
        let (Some(token), [invocation, host, key_type, key_b64]) = (token, &args[2..]) else {
            return Some(1);
        };
        Request::KnownHost {
            token,
            invocation: invocation.clone(),
            host: host.clone(),
            key_type: key_type.clone(),
            key_b64: key_b64.clone(),
        }
    } else if let (Some(token), [_, prompt]) = (token, args.as_slice()) {
        let prompt_kind = match std::env::var("SSH_ASKPASS_PROMPT").as_deref() {
            Ok("confirm") => PromptKind::Confirm,
            Ok("none") => PromptKind::Notify,
            _ => PromptKind::Secret,
        };
        Request::Askpass { token, prompt: prompt.clone(), prompt_kind }
    } else {
        return None;
    };
    Some(exchange(&req).unwrap_or(1))
}

#[cfg(unix)]
fn exchange(req: &Request) -> std::io::Result<i32> {
    use std::os::unix::net::UnixStream;
    let sock = std::env::var_os(ENV_SOCK).ok_or_else(|| std::io::Error::other("no helper socket"))?;
    let mut stream = UnixStream::connect(sock)?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    stream.write_all(&line)?;

    let notify = matches!(req, Request::Askpass { prompt_kind: PromptKind::Notify, .. });
    if notify {
        // Stay alive until ssh kills us once the security key was touched.
        let _ = stream.read(&mut [0u8; 1]);
        return Ok(0);
    }

    let mut reply = Zeroizing::new(String::new());
    BufReader::new(stream.take(MAX_MESSAGE)).read_line(&mut reply)?;
    let resp: Response = serde_json::from_str(&reply)?;
    let output = resp.output.map(Zeroizing::new);
    if let Some(out) = &output {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(out.as_bytes())?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(if resp.ok { 0 } else { 1 })
}

#[cfg(not(unix))]
fn exchange(_req: &Request) -> std::io::Result<i32> {
    // ponytail: named-pipe transport lands with the Windows port.
    Err(std::io::Error::other("helper transport not implemented on this platform"))
}

// ---------------------------------------------------------------------------
// Server side: runs inside the application.
// ---------------------------------------------------------------------------

/// A decision the application must make. Dropping a reply sender counts as "deny".
pub enum HelperEvent {
    Askpass {
        session: String,
        prompt: String,
        kind: PromptKind,
        reply: oneshot::Sender<Option<Zeroizing<String>>>,
    },
    /// `reply`: `Ok(None)` = nothing to add, `Ok(Some(line))` = trusted line, `Err(())` = abort.
    KnownHost {
        session: String,
        invocation: String,
        key: OfferedKey,
        reply: oneshot::Sender<Result<Option<String>, ()>>,
    },
    Notify {
        session: String,
        id: u64,
        prompt: String,
    },
    NotifyDone {
        session: String,
        id: u64,
    },
}

#[derive(Clone)]
pub struct HelperServer {
    pub sock_path: PathBuf,
    routes: Arc<Mutex<HashMap<String, String>>>,
}

pub fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl HelperServer {
    /// Environment for an `ssh` process acting for `session`.
    pub fn env_for(&self, session: &str, exe: &Path) -> Vec<(String, String)> {
        let token = random_token();
        if let Ok(mut r) = self.routes.lock() {
            r.insert(token.clone(), session.to_owned());
        }
        vec![
            (ENV_SOCK.into(), self.sock_path.to_string_lossy().into_owned()),
            (ENV_TOKEN.into(), token),
            ("SSH_ASKPASS".into(), exe.to_string_lossy().into_owned()),
            ("SSH_ASKPASS_REQUIRE".into(), "force".into()),
        ]
    }

    pub fn forget_session(&self, session: &str) {
        if let Ok(mut r) = self.routes.lock() {
            r.retain(|_, s| s != session);
        }
    }

    fn session_for(&self, token: &str) -> Option<String> {
        self.routes.lock().ok()?.get(token).cloned()
    }
}

#[cfg(unix)]
pub async fn start(runtime_dir: &Path) -> std::io::Result<(HelperServer, mpsc::Receiver<HelperEvent>)> {
    use tokio::net::UnixListener;
    let sock_path = runtime_dir.join(format!("helper-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)?;
    std::fs::set_permissions(&sock_path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let server = HelperServer { sock_path, routes: Arc::default() };
    let (tx, rx) = mpsc::channel(32);
    let srv = server.clone();
    tokio::spawn(async move {
        let mut next_id = 0u64;
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            next_id += 1;
            let (srv, tx) = (srv.clone(), tx.clone());
            tokio::spawn(async move {
                if let Err(e) = handle(stream, &srv, &tx, next_id).await {
                    tracing::warn!("helper request rejected: {e}");
                }
            });
        }
    });
    Ok((server, rx))
}

#[cfg(unix)]
async fn handle(stream: tokio::net::UnixStream, srv: &HelperServer, tx: &mpsc::Sender<HelperEvent>, id: u64) -> std::io::Result<()> {
    let uid = stream.peer_cred()?.uid();
    if uid != rustix::process::getuid().as_raw() {
        return Err(std::io::Error::other("peer has a different uid"));
    }
    let (read, mut write) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read.take(MAX_MESSAGE));
    let mut line = Zeroizing::new(String::new());
    reader.read_line(&mut line).await?;
    let req: Request = serde_json::from_str(&line)?;

    let deny = Response { ok: false, output: None };
    let token = match &req {
        Request::Askpass { token, .. } | Request::KnownHost { token, .. } => token,
    };
    let Some(session) = srv.session_for(token) else {
        return Err(std::io::Error::other("unknown helper token"));
    };

    let resp = match req {
        Request::Askpass { prompt, prompt_kind: PromptKind::Notify, .. } => {
            let _ = tx.send(HelperEvent::Notify { session: session.clone(), id, prompt }).await;
            // The helper keeps the socket open until ssh kills it.
            let _ = reader.read(&mut [0u8; 1]).await;
            let _ = tx.send(HelperEvent::NotifyDone { session, id }).await;
            return Ok(());
        }
        Request::Askpass { prompt, prompt_kind, .. } => {
            let (reply, rx) = oneshot::channel();
            let _ = tx.send(HelperEvent::Askpass { session, prompt, kind: prompt_kind, reply }).await;
            match tokio::time::timeout(DECISION_TIMEOUT, rx).await {
                Ok(Ok(Some(answer))) => Response { ok: true, output: Some(answer.to_string()) },
                _ => deny,
            }
        }
        Request::KnownHost { invocation, host, key_type, key_b64, .. } => {
            if invocation == "ORDER" {
                Response { ok: true, output: None }
            } else if let Some(key) = OfferedKey::parse(&host, &key_type, &key_b64) {
                let (reply, rx) = oneshot::channel();
                let _ = tx.send(HelperEvent::KnownHost { session, invocation, key, reply }).await;
                match tokio::time::timeout(DECISION_TIMEOUT, rx).await {
                    Ok(Ok(Ok(output))) => Response { ok: true, output },
                    _ => deny,
                }
            } else {
                deny
            }
        }
    };
    let mut out = Zeroizing::new(serde_json::to_vec(&resp)?);
    out.push(b'\n');
    write.write_all(&out).await?;
    write.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_long() {
        let (a, b) = (random_token(), random_token());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_unknown_tokens_and_routes_known_ones() {
        use tokio::net::UnixStream;
        let dir = tempfile::tempdir().unwrap();
        let (srv, mut rx) = start(dir.path()).await.unwrap();
        let env = srv.env_for("session-1", Path::new("/bin/true"));
        let token = env.iter().find(|(k, _)| k == ENV_TOKEN).unwrap().1.clone();

        async fn send(sock: &Path, req: &Request) -> Option<Response> {
            let mut s = UnixStream::connect(sock).await.unwrap();
            let mut line = serde_json::to_vec(req).unwrap();
            line.push(b'\n');
            s.write_all(&line).await.unwrap();
            let mut buf = String::new();
            tokio::io::BufReader::new(s).read_line(&mut buf).await.ok()?;
            serde_json::from_str(&buf).ok()
        }

        // Wrong token: connection dropped without an answer.
        let bad = Request::Askpass { token: "nope".into(), prompt: "p".into(), prompt_kind: PromptKind::Secret };
        assert!(send(&srv.sock_path, &bad).await.is_none());

        // Right token: event reaches the app, answer reaches the helper.
        let sock = srv.sock_path.clone();
        let req = Request::Askpass { token: token.clone(), prompt: "pw@h's password: ".into(), prompt_kind: PromptKind::Secret };
        let client = tokio::spawn(async move { send(&sock, &req).await });
        match rx.recv().await.unwrap() {
            HelperEvent::Askpass { session, reply, .. } => {
                assert_eq!(session, "session-1");
                reply.send(Some(Zeroizing::new("s3cret".into()))).ok();
            }
            _ => panic!("unexpected event"),
        }
        let resp = client.await.unwrap().unwrap();
        assert!(resp.ok && resp.output.as_deref() == Some("s3cret"));

        // A dropped reply (app closed the dialog) means deny.
        let sock = srv.sock_path.clone();
        let req = Request::KnownHost {
            token: token.clone(),
            invocation: "HOSTNAME".into(),
            host: "h".into(),
            key_type: "ssh-ed25519".into(),
            key_b64: "AAAAC3NzaC1lZDI1NTE5AAAAIK4SRKnlQCejQkj52bLe3gZ6LBxCBX2JdOaWKhc2o0mF".into(),
        };
        let client = tokio::spawn(async move { send(&sock, &req).await });
        drop(rx.recv().await.unwrap());
        assert!(!client.await.unwrap().unwrap().ok);

        // After the session is forgotten, its token stops working.
        srv.forget_session("session-1");
        let req = Request::Askpass { token, prompt: "p".into(), prompt_kind: PromptKind::Secret };
        assert!(send(&srv.sock_path, &req).await.is_none());
    }
}
