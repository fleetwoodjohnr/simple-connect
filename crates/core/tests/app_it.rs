//! The application core end to end, the way the UI drives it.
//! Run with: `cargo test -p simple-connect-core --test app_it -- --ignored`
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::ExposeSecret;
use simple_connect_core::app::transfers::{ConflictChoice, JobState};
use simple_connect_core::app::tunnels::{TunnelKind, TunnelSpec};
use simple_connect_core::app::{ConnectRequest, Manager, SecretPromptKind, Status, Ui, UiEvent, sysinfo};
use simple_connect_core::paths::AppPaths;
use simple_connect_core::profiles::{self, AuthMethod, ProfileDraft};
use simple_connect_core::security::{CredentialStore, MemoryStore};
use simple_connect_core::settings::Settings;
use simple_connect_core::ssh::engine::Engine;
use simple_connect_core::ssh::mux::Destination;
use simple_connect_core::validate::{Host, User};
use support::Sshd;
use tokio::sync::mpsc;

struct TestUi(mpsc::UnboundedSender<UiEvent>);
impl Ui for TestUi {
    fn emit(&self, e: UiEvent) {
        let _ = self.0.send(e);
    }
}

#[derive(Default)]
struct Log {
    statuses: Vec<String>,
    password_prompts: usize,
    /// Latest sudo-prompt offer: (terminal, visible).
    sudo_offer: Option<(String, bool)>,
    jobs: Vec<(String, JobState, Option<bool>, u64)>,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn banner(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok_and(|mut s| {
        s.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).is_ok() && &b == b"SSH-"
    })
}

async fn wait_for(log: &Arc<Mutex<Log>>, what: &str, f: impl Fn(&Log) -> bool) {
    for _ in 0..300 {
        if f(&log.lock().unwrap()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}; statuses: {:?}", log.lock().unwrap().statuses);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn full_session_lifecycle() {
    let sshd = Sshd::start("");
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(dir.path());
    paths.ensure().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let (engine, helper_events) =
        Engine::start_with_home(paths, PathBuf::from(env!("CARGO_BIN_EXE_sc-test-helper")), Some(home)).await.unwrap();

    let mut conn = simple_connect_core::storage::open_in_memory().unwrap();
    let draft = ProfileDraft {
        name: "Test box".into(),
        host: "127.0.0.1".into(),
        port: Some(u32::from(sshd.port)),
        username: Some("pw".into()),
        auth: AuthMethod::Password,
        ..Default::default()
    };
    let profile = profiles::create(&mut conn, &draft).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let settings = Settings { include_user_ssh_config: false, ..Settings::default() };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let m = Manager::new(Arc::new(engine), Arc::new(TestUi(tx)), db.clone(), settings, helper_events);
    let store = Arc::new(MemoryStore::default());
    m.set_store(Some(store.clone()));

    // The "user": trusts the new host and types the password, asking to save it.
    let log: Arc<Mutex<Log>> = Arc::default();
    {
        let (m, log) = (m.clone(), log.clone());
        tokio::spawn(async move {
            while let Some(e) = rx.recv().await {
                match e {
                    UiEvent::Session { status, .. } => log.lock().unwrap().statuses.push(format!("{status:?}")),
                    UiEvent::HostKeyPrompt { id, changed, .. } => {
                        assert!(!changed);
                        m.answer_host_key(id, true, None).await.unwrap();
                    }
                    UiEvent::SecretPrompt { id, kind, .. } => {
                        assert_eq!(kind, SecretPromptKind::Password);
                        log.lock().unwrap().password_prompts += 1;
                        m.answer_secret(id, Some("correct horse".into()), true).unwrap();
                    }
                    UiEvent::PasswordPrompt { terminal, visible, .. } => log.lock().unwrap().sudo_offer = Some((terminal, visible)),
                    UiEvent::Transfers { jobs } => {
                        log.lock().unwrap().jobs = jobs.into_iter().map(|j| (j.name, j.state, j.verified, j.id)).collect();
                    }
                    _ => {}
                }
            }
        });
    }

    let req = ConnectRequest {
        dest: Destination {
            host: Host::parse("127.0.0.1").unwrap(),
            user: Some(User::parse("pw").unwrap()),
            port: Some(sshd.port),
            jump: Vec::new(),
            identity_file: None,
            auth: AuthMethod::Password,
        },
        label: "Test box".into(),
        profile_id: Some(profile.id.clone()),
        legacy_crypto: false,
        keepalive_secs: Some(2),
        start_dir: Some("/tmp".into()),
        reuse_password: None,
    };
    let sid = m.connect(req);
    wait_for(&log, "connected", |l| l.statuses.last().is_some_and(|s| s == "Connected")).await;

    // The password was saved only after sign-in succeeded.
    let secret_ref = profiles::secret_ref(&db.lock().unwrap(), &profile.id).unwrap().unwrap();
    assert_eq!(store.get(&secret_ref).unwrap().unwrap().expose_secret(), "correct horse");

    // Terminal, starting in the profile's folder.
    let out: Arc<Mutex<Vec<u8>>> = Arc::default();
    let sink = out.clone();
    let term = m.open_terminal(&sid, 100, 30, None, move |b| sink.lock().unwrap().extend(b)).unwrap();
    m.terminal(&sid, &term).unwrap().write(b"echo cwd=$(pwd)\n").unwrap();
    for _ in 0..50 {
        if String::from_utf8_lossy(&out.lock().unwrap()).contains("cwd=/tmp") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(String::from_utf8_lossy(&out.lock().unwrap()).contains("cwd=/tmp"));

    // sudo asks for the password: the login password is offered, and sent only on request.
    let shown = |term: String| move |l: &Log| l.sudo_offer == Some((term.clone(), true));
    m.terminal_write(&sid, &term, b"sudo -k; sudo id -u\n").unwrap();
    wait_for(&log, "sudo prompt offer", shown(term.clone())).await;
    m.terminal_send_password(&sid, &term).unwrap();
    let mut root = false;
    for _ in 0..50 {
        root = String::from_utf8_lossy(&out.lock().unwrap()).contains("\r\n0\r\n");
        if root {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(root, "sudo accepted the reused password");
    assert!(m.terminal_send_password(&sid, &term).is_err(), "no prompt waiting any more");

    // Typing at the prompt withdraws the offer; the backend refuses to send.
    m.terminal_write(&sid, &term, b"sudo -k; sudo true\n").unwrap();
    wait_for(&log, "second offer", shown(term.clone())).await;
    m.terminal_write(&sid, &term, b"x").unwrap();
    assert!(m.terminal_send_password(&sid, &term).is_err(), "typing first means answering by hand");
    m.terminal_write(&sid, &term, b"\x03").unwrap();

    // With reuse turned off, nothing is offered or sent.
    m.set_settings(Settings { include_user_ssh_config: false, reuse_ssh_password: false, ..Settings::default() });
    log.lock().unwrap().sudo_offer = None;
    m.terminal_write(&sid, &term, b"sudo -k; sudo true\n").unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    // A delayed withdrawal event from the preceding Ctrl+C is harmless.
    assert!(!matches!(log.lock().unwrap().sudo_offer, Some((_, true))), "no visible offer when disabled");
    assert!(m.terminal_send_password(&sid, &term).is_err());
    m.terminal_write(&sid, &term, b"\x03").unwrap();
    m.set_settings(Settings { include_user_ssh_config: false, ..Settings::default() });
    assert!(!String::from_utf8_lossy(&out.lock().unwrap()).contains("correct horse"), "the password never reaches the screen");

    // Local and dynamic (SOCKS) tunnels reach the server's own sshd.
    let lport = free_port();
    let spec = |kind, port, host: Option<&str>| TunnelSpec {
        kind,
        bind_address: "127.0.0.1".into(),
        bind_port: port,
        target_host: host.map(Into::into),
        target_port: host.map(|_| 22),
        allow_external: false,
    };
    m.tunnels.add(&m, &sid, spec(TunnelKind::Local, lport, Some("127.0.0.1"))).await.unwrap();
    assert!(banner(lport));
    let dport = free_port();
    m.tunnels.add(&m, &sid, spec(TunnelKind::Dynamic, dport, None)).await.unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", dport)).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).unwrap();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 22]).unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).unwrap();
    assert_eq!(r[1], 0, "SOCKS connect succeeded");
    let mut b = [0u8; 4];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"SSH-");

    // System info without privileges.
    let info = sysinfo::gather(&m, &sid).await.unwrap();
    assert!(info.hostname.is_some() && info.kernel.is_some(), "{info:?}");

    // Folder upload, verified by checksum.
    let local = tempfile::tempdir().unwrap();
    let folder = local.path().join("site");
    std::fs::create_dir_all(folder.join("css")).unwrap();
    std::fs::write(folder.join("index.html"), "<h1>hi</h1>").unwrap();
    std::fs::write(folder.join("css/app.css"), "body{}").unwrap();
    m.transfers.enqueue_upload(&m, &sid, vec![folder.clone()], "/home/pw".into()).await.unwrap();
    wait_for(&log, "upload done", |l| l.jobs.len() == 2 && l.jobs.iter().all(|j| j.1 == JobState::Done)).await;
    assert!(log.lock().unwrap().jobs.iter().all(|j| j.2 == Some(true)), "verified by sha256");

    // Uploading again: both conflict; "keep both" for all.
    m.transfers.clear_finished(&m);
    m.transfers.enqueue_upload(&m, &sid, vec![folder], "/home/pw".into()).await.unwrap();
    wait_for(&log, "conflicts", |l| l.jobs.len() == 2 && l.jobs.iter().all(|j| j.1 == JobState::Conflict)).await;
    let first = log.lock().unwrap().jobs[0].3;
    m.transfers.resolve(&m, first, ConflictChoice::KeepBoth, true);
    wait_for(&log, "kept both", |l| l.jobs.iter().all(|j| j.1 == JobState::Done)).await;
    let mut names: Vec<String> = log.lock().unwrap().jobs.iter().map(|j| j.0.clone()).collect();
    names.sort();
    assert_eq!(names, ["app (1).css", "index (1).html"]);

    // The server restarts: the session reconnects on its own and the saved
    // password is used without asking again; tunnels come back.
    sshd.restart();
    wait_for(&log, "reconnecting", |l| l.statuses.iter().any(|s| s.starts_with("Reconnecting"))).await;
    wait_for(&log, "reconnected", |l| l.statuses.last().is_some_and(|s| s == "Connected")).await;
    assert_eq!(log.lock().unwrap().password_prompts, 1, "saved password reused");
    for _ in 0..30 {
        if banner(lport) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(banner(lport), "tunnel restored after reconnect");
    assert!(m.tunnels.list(&sid).iter().all(|t| t.active));

    // Locking hides saved secrets from the connection flow.
    m.set_locked(true);
    assert!(m.store().is_err());
    m.set_locked(false);

    // An independent command must be cancelled when its owning session closes.
    let command_manager = m.clone();
    let command_session = sid.clone();
    let command = tokio::spawn(async move {
        command_manager.remote_exec(&command_session, "touch /tmp/sc-command-started; sleep 30".into(), Duration::from_secs(60)).await
    });
    let mut started = false;
    for _ in 0..50 {
        started = m.remote_exec(&sid, "test -f /tmp/sc-command-started".into(), Duration::from_secs(2)).await.unwrap().status.success();
        if started {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(started, "remote command reached server before disconnect");
    m.disconnect(&sid).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), command).await.expect("remote command must stop with session").unwrap().is_err());
    assert!(!banner(lport), "tunnels close with the session");
    let _ = Status::Connected;
}
