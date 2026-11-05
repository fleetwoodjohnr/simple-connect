//! Runtime proof for the Windows SSH process model, using real OpenSSH on Unix.
//! cargo test -p simple-connect-core --features independent-ssh --test independent_it -- --ignored
#![cfg(all(unix, feature = "independent-ssh"))]
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use simple_connect_core::app::{ConnectRequest, Manager, Ui, UiEvent};
use simple_connect_core::profiles::AuthMethod;
use simple_connect_core::settings::Settings;
use simple_connect_core::sftp::{RemoteFs, transfer};
use simple_connect_core::ssh::config::Policy;
use simple_connect_core::ssh::errors::FailureKind;
use simple_connect_core::ssh::mux::Destination;
use simple_connect_core::ssh::terminal::Terminal;
use simple_connect_core::validate::{Host, User};
use support::{Script, Sshd, harness, harness_with_spaced_runtime, keypair};

struct SilentUi;
impl Ui for SilentUi {
    fn emit(&self, _: UiEvent) {}
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman and OpenSSH 9.4+ for tagged jump routing"]
async fn independent_connections_preserve_security_and_cancel_cleanly() {
    let keys = tempfile::tempdir().unwrap();
    let (key, public) = keypair(keys.path());
    let server = Sshd::start(&public);
    let destination = Destination {
        host: Host::parse("127.0.0.1").unwrap(),
        user: Some(User::parse("key").unwrap()),
        port: Some(server.port),
        jump: vec![],
        identity_file: Some(key.clone()),
        auth: AuthMethod::Key,
    };
    let policy = Policy { include_user_config: false, ..Policy::default() };
    let rejected = harness(Script::default()).await;
    let error = rejected.engine.connect("reject", &destination, &policy, |_, _| {}).await.err().unwrap();
    assert_eq!(error.kind, FailureKind::HostKeyRejected);
    rejected.engine.shutdown();

    let h = harness_with_spaced_runtime(Script { trust_unknown: true, ..Script::default() }).await;
    let master = h.engine.connect("independent", &destination, &policy, |_, _| {}).await.unwrap();
    assert!(!master.socket.exists(), "independent mode must not silently use multiplexing");
    assert_eq!(master.info.auth_method.as_deref(), Some("publickey"));

    // Terminal and SFTP authenticate independently, retaining helper host checks.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let mut args = master.client_args(&destination);
    args.extend(["-tt".into(), "--".into(), "127.0.0.1".into(), "stty size; echo independent-terminal".into()]);
    let term = Terminal::spawn(
        &h.engine.ossh.ssh,
        args,
        master.env.clone(),
        101,
        31,
        move |bytes| {
            let _ = tx.send(bytes);
        },
        move || {
            let _ = done_tx.send(());
        },
    )
    .unwrap();
    done_rx.recv_timeout(Duration::from_secs(15)).unwrap();
    let output: Vec<u8> = rx.try_iter().flatten().collect();
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("31 101") && output.contains("independent-terminal"), "{output}");
    drop(term);
    let fs = RemoteFs::open(&h.engine.ossh, &master, &destination).await.unwrap();
    let path = format!("{}/a b';$(id).txt", fs.home);
    let bytes = b"independent SFTP data\n";
    fs.write_atomic(&path, bytes).await.unwrap();
    assert_eq!(fs.read_limited(&path, 1024).await.unwrap(), bytes);
    let expected = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(transfer::remote_sha256(&h.engine.ossh, &master, &destination, &path).await.unwrap(), expected);
    fs.remove(&path).await.unwrap();
    drop(fs);

    // Forwarding must be usable before success is reported, and cancel closes it.
    let listen = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listen.local_addr().unwrap().port();
    drop(listen);
    let forward = format!("127.0.0.1:{port}:127.0.0.1:22");
    master.forward(&h.engine.ossh, &destination, "forward", "-L", &forward).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut banner = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read_exact(&mut stream, &mut banner)).await.unwrap().unwrap();
    assert_eq!(&banner, b"SSH-");
    drop(stream);
    master.forward(&h.engine.ossh, &destination, "cancel", "-L", &forward).await.unwrap();
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err());
    // Remote forwarding needs the server's confirmation, not merely the
    // earlier "Entering interactive session" debug line.
    let remote_forward = format!("127.0.0.1:45000:127.0.0.1:{}", server.port);
    master.forward(&h.engine.ossh, &destination, "forward", "-R", &remote_forward).await.unwrap();
    assert_eq!(server.exec("key", "timeout 3 nc 127.0.0.1 45000 | head -c 4"), "SSH-");
    master.forward(&h.engine.ossh, &destination, "cancel", "-R", &remote_forward).await.unwrap();
    let busy = format!("127.0.0.1:22:127.0.0.1:{}", server.port);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), master.forward(&h.engine.ossh, &destination, "forward", "-R", &busy))
            .await
            .unwrap()
            .is_err(),
        "the remote sshd already owns port 22; a denied forward must not report active"
    );
    master.close().await;

    // A real jump transport through the test server, with a spaced config
    // filename and original host aliases resolved from this harness's ssh_config.
    let home = h._dir.path().join("home/.ssh");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config"),
        format!(
            "Host jump-alias\n    HostName 127.0.0.1\n    IdentityFile {}\n",
            simple_connect_core::ssh::config::quote_path(&key).unwrap()
        ),
    )
    .unwrap();
    let mut jump = destination.clone();
    jump.port = Some(22);
    jump.jump = simple_connect_core::validate::jump_chain(&format!("key@jump-alias:{}", server.port)).unwrap();
    let jump_policy = Policy { include_user_config: true, ..policy.clone() };
    let routed = h.engine.connect("route-test", &jump, &jump_policy, |_, _| {}).await.unwrap();
    assert_eq!(routed.info.auth_method.as_deref(), Some("publickey"));
    routed.close().await;

    // Manager disconnect must cancel an already-running independent command.
    let (_unused_sender, events) = tokio::sync::mpsc::channel(1);
    let manager = Manager::new(
        h.engine.clone(),
        Arc::new(SilentUi),
        Arc::new(Mutex::new(simple_connect_core::storage::open_in_memory().unwrap())),
        Settings { include_user_ssh_config: false, auto_reconnect: false, ..Settings::default() },
        events,
    );
    let session = manager.connect(ConnectRequest {
        dest: destination,
        label: "Independent".into(),
        profile_id: None,
        legacy_crypto: false,
        keepalive_secs: None,
        start_dir: None,
        reuse_password: None,
    });
    tokio::time::timeout(Duration::from_secs(15), async {
        while manager.session(&session).unwrap().master().is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let marker = format!("/tmp/sc-independent-{}", uuid::Uuid::new_v4());
    let (m, sid, command) = (manager.clone(), session.clone(), format!("echo started > {marker}; exec sleep 60"));
    let pending = tokio::spawn(async move { m.remote_exec(&sid, command, Duration::from_secs(120)).await });
    tokio::time::timeout(Duration::from_secs(10), async {
        while server.exec("key", &format!("if test -f {marker}; then echo ready; fi")).trim() != "ready" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    manager.disconnect(&session).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), pending).await.unwrap().unwrap().is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    support::assert_no_process_args_contain(&marker);
    manager.shutdown().await;
}
