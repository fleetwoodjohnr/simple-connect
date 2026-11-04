//! Disposable OpenSSH servers in podman for integration tests.
#![allow(dead_code, clippy::unwrap_used)]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use simple_connect_core::paths::AppPaths;
use simple_connect_core::ssh::engine::Engine;
use simple_connect_core::ssh::helper::HelperEvent;
use simple_connect_core::ssh::known_hosts::HostKeyStatus;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

const IMAGE: &str = "simple-connect-sshd";
/// sshd plus desktops for remote desktop tests (tests/desktop).
pub const DESKTOP_IMAGE: &str = "simple-connect-desktop";

fn podman(args: &[&str]) -> String {
    let out = Command::new("podman").args(args).output().expect("podman is required for integration tests");
    assert!(out.status.success(), "podman {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

pub struct Sshd {
    pub name: String,
    pub port: u16,
    authorized_key: String,
    image: &'static str,
}

impl Sshd {
    pub fn start(authorized_key: &str) -> Sshd {
        static BUILD: Once = Once::new();
        BUILD.call_once(|| {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/sshd");
            podman(&["build", "-q", "-t", IMAGE, dir.to_str().unwrap()]);
        });
        Self::run_image(IMAGE, authorized_key)
    }

    pub fn start_desktop() -> Sshd {
        static BUILD: Once = Once::new();
        BUILD.call_once(|| {
            let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests");
            podman(&["build", "-q", "-t", DESKTOP_IMAGE, "-f", "desktop/Containerfile", tests.to_str().unwrap()]);
        });
        Self::run_image(DESKTOP_IMAGE, "")
    }

    fn run_image(image: &'static str, authorized_key: &str) -> Sshd {
        let name = format!("sc-it-{}", &simple_connect_core::ssh::helper::random_token()[..12]);
        let mut s = Sshd { name, port: 0, authorized_key: authorized_key.to_owned(), image };
        s.run("127.0.0.1::22");
        let mapped = podman(&["port", &s.name, "22"]);
        s.port = mapped.rsplit(':').next().unwrap().parse().unwrap();
        s.wait_ready();
        s
    }

    fn run(&self, publish: &str) {
        podman(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &self.name,
            "-p",
            publish,
            "-e",
            &format!("AUTHORIZED_KEY={}", self.authorized_key),
            self.image,
        ]);
    }

    /// Ends every SSH connection but keeps the server and its other programs running.
    pub fn drop_connections(&self) {
        podman(&["exec", &self.name, "pkill", "sshd-session"]);
    }

    /// Runs a command in the container as `user` and returns its stdout.
    pub fn exec(&self, user: &str, cmd: &str) -> String {
        podman(&["exec", "-u", user, &self.name, "sh", "-c", cmd])
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.port)) {
                use std::io::Read;
                let mut buf = [0u8; 4];
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                if s.read_exact(&mut buf).is_ok() && &buf == b"SSH-" {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("sshd container did not become ready");
    }

    /// Restarts sshd in place (same host keys): drops every connection.
    pub fn restart(&self) {
        podman(&["restart", "-t", "0", &self.name]);
        self.wait_ready();
    }

    /// Same address, freshly generated host keys: what a rebuilt server — or a
    /// man-in-the-middle — looks like.
    pub fn replace_host_keys(&self) {
        podman(&["rm", "-f", &self.name]);
        self.run(&format!("127.0.0.1:{}:22", self.port));
        self.wait_ready();
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = Command::new("podman").args(["rm", "-f", &self.name]).output();
    }
}

pub fn keypair(dir: &Path) -> (PathBuf, String) {
    let key = dir.join("id_ed25519");
    let st = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "it"]).arg("-f").arg(&key).status().unwrap();
    assert!(st.success());
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    (key, public.trim().to_owned())
}

/// While a secret is in flight, no process on the machine may have it in argv
/// (`/proc/*/cmdline` is world-readable).
pub fn assert_no_process_args_contain(secret: &str) {
    if secret.len() < 6 {
        return; // too short to search for without false positives
    }
    #[cfg(target_os = "linux")]
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        if let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) {
            let found = cmdline.windows(secret.len()).any(|w| w == secret.as_bytes());
            assert!(!found, "secret visible in /proc/{}/cmdline", entry.file_name().to_string_lossy());
        }
    }
}

/// Scripted answers to the prompts a user would see.
#[derive(Clone, Default)]
pub struct Script {
    pub trust_unknown: bool,
    pub accept_changed: bool,
    pub passwords: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Seen {
    HostKey(String),
    Prompt(String),
}

pub struct Harness {
    pub engine: Arc<Engine>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub _dir: tempfile::TempDir,
}

pub async fn harness(script: Script) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(dir.path());
    start(paths, dir, script).await
}

/// A second app instance sharing `prev`'s data (trusted keys) with new answers.
pub async fn harness_with(prev: &Harness, script: Script) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths { data: prev.engine.paths.data.clone(), ..AppPaths::under(dir.path()) };
    start(paths, dir, script).await
}

async fn start(paths: AppPaths, dir: tempfile::TempDir, script: Script) -> Harness {
    paths.ensure().unwrap();
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_sc-test-helper"));
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let (engine, events) = Engine::start_with_home(paths, exe, Some(home)).await.unwrap();
    let engine = Arc::new(engine);
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    tokio::spawn(drive(engine.clone(), events, script, seen.clone()));
    Harness { engine, seen, _dir: dir }
}

async fn drive(engine: Arc<Engine>, mut events: mpsc::Receiver<HelperEvent>, script: Script, seen: Arc<Mutex<Vec<Seen>>>) {
    let mut passwords = script.passwords.into_iter();
    while let Some(ev) = events.recv().await {
        match ev {
            HelperEvent::KnownHost { key, reply, .. } => {
                let status = engine.check_host_key(&key);
                let label = match &status {
                    HostKeyStatus::Known => "known",
                    HostKeyStatus::Unknown => "unknown",
                    HostKeyStatus::Changed { .. } => "changed",
                    HostKeyStatus::Revoked => "revoked",
                };
                seen.lock().unwrap().push(Seen::HostKey(label.into()));
                let answer = match status {
                    HostKeyStatus::Known => Ok(None),
                    HostKeyStatus::Unknown if script.trust_unknown => engine.trust_host_key(&key, false, false).map(Some).map_err(drop),
                    HostKeyStatus::Changed { .. } if script.accept_changed => {
                        engine.trust_host_key(&key, true, false).map(Some).map_err(drop)
                    }
                    _ => Err(()),
                };
                let _ = reply.send(answer);
            }
            HelperEvent::Askpass { session, prompt, reply, .. } => {
                if let Some(answer) = engine.scripted_answer(&session, &prompt) {
                    assert_no_process_args_contain(&answer);
                    let _ = reply.send(Some(answer));
                    continue;
                }
                seen.lock().unwrap().push(Seen::Prompt(prompt));
                let answer = passwords.next().map(Zeroizing::new);
                if let Some(a) = &answer {
                    assert_no_process_args_contain(a);
                }
                let _ = reply.send(answer);
            }
            HelperEvent::Notify { .. } | HelperEvent::NotifyDone { .. } => {}
        }
    }
}
