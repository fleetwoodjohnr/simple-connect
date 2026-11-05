//! End-to-end tests against a real OpenSSH server in podman.
//! Run with: `cargo test -p simple-connect-core --test ssh_it -- --ignored --test-threads=2`

#![allow(clippy::unwrap_used)]

mod support;

use std::time::Duration;

use simple_connect_core::profiles::AuthMethod;
use simple_connect_core::ssh::config::Policy;
use simple_connect_core::ssh::errors::FailureKind;
use simple_connect_core::ssh::mux::Destination;
use simple_connect_core::ssh::terminal::Terminal;
use simple_connect_core::validate::{Host, User};
use support::{Script, Seen, Sshd, harness, keypair};

fn dest(port: u16, user: &str, auth: AuthMethod) -> Destination {
    Destination {
        host: Host::parse("127.0.0.1").unwrap(),
        user: Some(User::parse(user).unwrap()),
        port: Some(port),
        jump: Vec::new(),
        identity_file: None,
        auth,
    }
}

fn policy() -> Policy {
    // Tests must not depend on the developer's ~/.ssh/config.
    Policy { include_user_config: false, ..Policy::default() }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn unknown_host_is_refused_unless_trusted() {
    let sshd = Sshd::start("");
    let h = harness(Script { trust_unknown: false, ..Script::default() }).await;
    let err = h.engine.connect("s1", &dest(sshd.port, "pw", AuthMethod::Password), &policy(), |_, _| {}).await.err().unwrap();
    assert_eq!(err.kind, FailureKind::HostKeyRejected, "{}", err.details);
    assert_eq!(h.seen.lock().unwrap().as_slice(), [Seen::HostKey("unknown".into())]);
    assert!(simple_connect_core::ssh::known_hosts::list(&h.engine.app_known_hosts()).is_empty(), "nothing was trusted");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn password_login_terminal_and_security_info() {
    let sshd = Sshd::start("");
    let h = harness(Script { trust_unknown: true, passwords: vec!["correct horse".into()], ..Script::default() }).await;
    let d = dest(sshd.port, "pw", AuthMethod::Password);
    let master = h.engine.connect("s2", &d, &policy(), |_, _| {}).await.unwrap();

    let info = &master.info;
    assert_eq!(info.auth_method.as_deref(), Some("password"));
    assert!(info.kex.is_some() && info.cipher.is_some() && info.host_key_fingerprint.is_some(), "{info:?}");
    let trusted = simple_connect_core::ssh::known_hosts::list(&h.engine.app_known_hosts());
    assert_eq!(trusted[0].fingerprint, info.host_key_fingerprint.clone().unwrap(), "trusted key is the negotiated one");

    // The password reached ssh only through askpass, never argv.
    let seen = h.seen.lock().unwrap().clone();
    assert!(seen.contains(&Seen::Prompt("pw@127.0.0.1's password: ".into())), "{seen:?}");

    // A terminal through the same master does not re-authenticate.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let mut args = master.client_args(&d);
    args.extend(["-tt".into(), "--".into(), "127.0.0.1".into(), "stty size; echo hello-from-$(whoami)".into()]);
    let _term = Terminal::spawn(
        &h.engine.ossh.ssh,
        args,
        master.env.clone(),
        120,
        40,
        move |b| drop(tx.send(b)),
        move || {
            let _ = done_tx.send(());
        },
    )
    .unwrap();
    done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let out = String::from_utf8_lossy(&rx.try_iter().flatten().collect::<Vec<_>>()).into_owned();
    assert!(out.contains("hello-from-pw"), "{out:?}");
    assert!(out.contains("40 120"), "remote pty got our size: {out:?}");
    assert_eq!(h.seen.lock().unwrap().len(), seen.len(), "no new prompts for the multiplexed session");

    master.close().await;
    assert!(!master.socket.exists() && !master.config.exists());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn key_login_without_prompts() {
    let dir = tempfile::tempdir().unwrap();
    let (key, public) = keypair(dir.path());
    let sshd = Sshd::start(&public);
    let h = harness(Script { trust_unknown: true, ..Script::default() }).await;
    let mut d = dest(sshd.port, "key", AuthMethod::Key);
    d.identity_file = Some(key);
    let master = h.engine.connect("s3", &d, &policy(), |_, _| {}).await.unwrap();
    assert_eq!(master.info.auth_method.as_deref(), Some("publickey"));
    assert!(h.seen.lock().unwrap().iter().all(|s| matches!(s, Seen::HostKey(_))));
    master.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn wrong_password_fails_cleanly() {
    let sshd = Sshd::start("");
    let h = harness(Script { trust_unknown: true, passwords: vec!["nope".into(); 3], ..Script::default() }).await;
    let err = h.engine.connect("s4", &dest(sshd.port, "pw", AuthMethod::Password), &policy(), |_, _| {}).await.err().unwrap();
    assert_eq!(err.kind, FailureKind::AuthFailed, "{}", err.details);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn cancelled_password_prompt_fails_cleanly() {
    let sshd = Sshd::start("");
    let h = harness(Script { trust_unknown: true, passwords: vec![], ..Script::default() }).await;
    let err = tokio::time::timeout(
        Duration::from_secs(20),
        h.engine.connect("s5", &dest(sshd.port, "pw", AuthMethod::Password), &policy(), |_, _| {}),
    )
    .await
    .expect("cancel must not hang")
    .err()
    .unwrap();
    assert_eq!(err.kind, FailureKind::AuthFailed, "{}", err.details);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn changed_host_key_is_blocked_until_accepted() {
    let sshd = Sshd::start("");
    let d = dest(sshd.port, "pw", AuthMethod::Password);
    let h = harness(Script { trust_unknown: true, passwords: vec!["correct horse".into()], ..Script::default() }).await;
    h.engine.connect("s6", &d, &policy(), |_, _| {}).await.unwrap().close().await;

    sshd.replace_host_keys();

    // Same app data, user rejects the changed key.
    let reject = support::harness_with(&h, Script { trust_unknown: false, accept_changed: false, ..Script::default() }).await;
    let err = reject.engine.connect("s7", &d, &policy(), |_, _| {}).await.err().unwrap();
    assert_eq!(err.kind, FailureKind::HostKeyRejected, "{}", err.details);
    assert!(reject.seen.lock().unwrap().contains(&Seen::HostKey("changed".into())));

    // User explicitly accepts: the old entry is replaced.
    let accept =
        support::harness_with(&h, Script { accept_changed: true, passwords: vec!["correct horse".into()], ..Script::default() }).await;
    let master = accept.engine.connect("s8", &d, &policy(), |_, _| {}).await.unwrap();
    assert_eq!(simple_connect_core::ssh::known_hosts::list(&accept.engine.app_known_hosts()).len(), 1);
    master.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn unreachable_port_is_refused() {
    let h = harness(Script::default()).await;
    // Port 9 (discard) is closed on localhost.
    let err = h.engine.connect("s9", &dest(9, "pw", AuthMethod::Auto), &policy(), |_, _| {}).await.err().unwrap();
    assert_eq!(err.kind, FailureKind::Refused, "{}", err.details);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs OpenSSH"]
async fn key_manager_never_puts_passphrases_on_argv() {
    use secrecy::SecretString;
    use simple_connect_core::ssh::keys::{self, KeyKind};
    let h = harness(Script::default()).await;
    // The harness checks /proc/*/cmdline each time a passphrase is handed over.
    let key = h.engine.generate_key(KeyKind::Ed25519, "id_test", "it@test", SecretString::from("kg pass 1234")).await.unwrap();
    assert_eq!((key.key_type.as_str(), key.encrypted), ("ssh-ed25519", Some(true)));
    assert!(h.engine.generate_key(KeyKind::Ed25519, "id_test", "", SecretString::from("")).await.is_err(), "no overwrite");

    let wrong = h.engine.change_passphrase(&key.path, SecretString::from("wrong passphrase"), SecretString::from("new passphrase")).await;
    assert!(wrong.is_err());
    h.engine.change_passphrase(&key.path, SecretString::from("kg pass 1234"), SecretString::from("")).await.unwrap();
    assert_eq!(keys::read(&key.path).unwrap().encrypted, Some(false));

    let imported = h.engine.import_key(&key.path, "id_copy", SecretString::from("")).await.unwrap();
    assert_eq!(imported.fingerprint, key.fingerprint);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&imported.path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn scanner_probe_identifies_ssh_without_logging_in() {
    use simple_connect_core::discovery::{SshStatus, probe};
    let sshd = Sshd::start("");
    let local = std::net::Ipv4Addr::LOCALHOST;
    match probe(local, sshd.port).await {
        Some(SshStatus::Open { software, .. }) => assert!(software.unwrap().starts_with("OpenSSH"), "banner parsed"),
        other => panic!("expected an SSH server, got {other:?}"),
    }
    assert_eq!(probe(local, 9).await, Some(SshStatus::Closed), "refused = online without SSH");
    let logs = std::process::Command::new("podman").args(["logs", &sshd.name]).output().unwrap();
    let logs = String::from_utf8_lossy(&logs.stderr).to_string() + &String::from_utf8_lossy(&logs.stdout);
    assert!(!logs.contains("Failed password") && !logs.contains("Invalid user"), "no authentication was attempted: {logs}");
}
