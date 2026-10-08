//! SFTP against a real server, over the session's ControlMaster.
//! Run with: `cargo test -p simple-connect-core --test sftp_it -- --ignored`

#![allow(clippy::unwrap_used)]

mod support;

use std::path::Path;

use simple_connect_core::profiles::AuthMethod;
use simple_connect_core::sftp::transfer::{self, Control};
use simple_connect_core::sftp::{EntryKind, RemoteFs, SftpError, remote_join};
use simple_connect_core::ssh::config::Policy;
use simple_connect_core::ssh::mux::{Destination, Master};
use simple_connect_core::validate::{Host, User};
use support::{Harness, Script, Sshd, harness};

async fn connect() -> (Sshd, Harness, Destination, Master) {
    let sshd = Sshd::start("");
    let h = harness(Script { trust_unknown: true, passwords: vec!["correct horse".into()], ..Script::default() }).await;
    let dest = Destination {
        host: Host::parse("127.0.0.1").unwrap(),
        user: Some(User::parse("pw").unwrap()),
        port: Some(sshd.port),
        jump: Vec::new(),
        identity_file: None,
        auth: AuthMethod::Password,
    };
    let policy = Policy { include_user_config: false, ..Policy::default() };
    let master = h.engine.connect("sftp", &dest, &policy, |_, _| {}).await.unwrap();
    (sshd, h, dest, master)
}

fn sha256_file(p: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    std::io::copy(&mut std::fs::File::open(p).unwrap(), &mut h).unwrap();
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn hostile_names_round_trip_and_cannot_escape() {
    let (_sshd, h, dest, master) = connect().await;
    let fs = RemoteFs::open(&h.engine.ossh, &master, &dest).await.unwrap();
    assert_eq!(fs.home, "/home/pw");
    let dir = remote_join(&fs.home, "names");
    fs.mkdir(&dir).await.unwrap();
    let names = ["a b", "it's", "$(id)", "`id`", "new\nline", "ünï 🚀.txt", "-rf", ";rm -rf ~", "\u{202e}gpj.exe"];
    for n in names {
        fs.sftp.fs().write(remote_join(&dir, n), n.as_bytes()).await.unwrap();
    }
    let mut listed: Vec<String> = fs.list(&dir).await.unwrap().into_iter().map(|e| e.name).collect();
    listed.sort();
    let mut want: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(listed, want);

    // Download them all: every name lands inside the target directory.
    let local = tempfile::tempdir().unwrap();
    for n in names {
        let dest_path = transfer::local_under(local.path(), &[n.to_owned()]).unwrap();
        transfer::download(&fs, &remote_join(&dir, n), &dest_path, &Control::default(), |_, _| {}).await.unwrap();
        assert_eq!(std::fs::read(&dest_path).unwrap(), n.as_bytes());
    }
    assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), names.len());
    assert!(transfer::local_under(local.path(), &["..".into()]).is_err());

    // The remote checksum command quotes hostile names safely.
    let remote = remote_join(&dir, "$(id)");
    let digest = transfer::remote_sha256(&h.engine.ossh, &master, &dest, &remote).await.unwrap();
    assert_eq!(digest, sha256_file(&local.path().join("$(id)")));

    fs.remove(&dir).await.unwrap();
    assert!(!fs.exists(&dir).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn large_upload_download_with_interruption_and_resume() {
    let (_sshd, h, dest, master) = connect().await;
    let fs = RemoteFs::open(&h.engine.ossh, &master, &dest).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("big.bin");
    {
        // 96 MiB of non-repeating data.
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(&src).unwrap());
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..(96 * 1024 * 1024 / 8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            f.write_all(&x.to_le_bytes()).unwrap();
        }
    }
    let want = sha256_file(&src);
    let remote = remote_join(&fs.home, "big.bin");

    // Upload, interrupted after ~20 MiB, then resumed.
    let control = Control::default();
    let err = transfer::upload(&fs, &src, &remote, false, &control, |done, _| {
        if done > 20 * 1024 * 1024 {
            control.stop();
        }
    })
    .await
    .unwrap_err();
    assert!(matches!(err, SftpError::Cancelled));
    let partial = fs.stat(&format!("{remote}.sc-part")).await.unwrap().size;
    assert!(partial > 0 && partial < 96 * 1024 * 1024, "partial upload kept: {partial}");
    let up = transfer::upload(&fs, &src, &remote, false, &Control::default(), |_, _| {}).await.unwrap();
    assert_eq!(up.sha256, want);
    assert_eq!(transfer::remote_sha256(&h.engine.ossh, &master, &dest, &remote).await.unwrap(), want);
    assert!(!fs.exists(&format!("{remote}.sc-part")).await);

    // Refuses to replace an existing file unless asked.
    assert!(transfer::upload(&fs, &src, &remote, false, &Control::default(), |_, _| {}).await.is_err());

    // Download, interrupted and resumed.
    let out = dir.path().join("down.bin");
    let control = Control::default();
    let err = transfer::download(&fs, &remote, &out, &control, |done, _| {
        if done > 30 * 1024 * 1024 {
            control.stop();
        }
    })
    .await
    .unwrap_err();
    assert!(matches!(err, SftpError::Cancelled));
    assert!(!out.exists() && dir.path().join("down.bin.sc-part").exists());
    let mut last = (0, 0);
    let got = transfer::download(&fs, &remote, &out, &Control::default(), |d, t| last = (d, t)).await.unwrap();
    assert_eq!(got.sha256, want);
    assert_eq!(sha256_file(&out), want);
    assert_eq!(last, (96 * 1024 * 1024, 96 * 1024 * 1024));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs podman"]
async fn editor_save_is_atomic_and_size_limited() {
    let (_sshd, h, dest, master) = connect().await;
    let fs = RemoteFs::open(&h.engine.ossh, &master, &dest).await.unwrap();
    let path = remote_join(&fs.home, "app.toml");
    fs.sftp.fs().write(&path, b"a = 1\n").await.unwrap();
    fs.chmod(&path, 0o640).await.unwrap();
    fs.write_atomic(&path, b"a = 2\n").await.unwrap();
    assert_eq!(fs.read_limited(&path, 1024).await.unwrap(), b"a = 2\n");
    assert_eq!(fs.stat(&path).await.unwrap().mode, Some(0o640), "mode preserved");
    assert!(matches!(fs.read_limited(&path, 3).await, Err(SftpError::TooLarge(_))));
    let names: Vec<_> = fs.list(&fs.home).await.unwrap().into_iter().filter(|e| e.kind == EntryKind::File).map(|e| e.name).collect();
    assert!(names.iter().all(|n| !n.contains("sc-save")), "no temp files left: {names:?}");
}
