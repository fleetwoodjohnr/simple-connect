//! The OpenSSH ControlMaster for one connection. It authenticates once; the
//! terminal, SFTP and tunnels then run as multiplexed `ssh -S <socket>` clients.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;

use super::errors::{ConnectFailure, FailureKind, classify};
use super::openssh::OpenSsh;
use crate::profiles::AuthMethod;
use crate::validate::{Host, JumpHop, User};

/// Everything needed to reach a server. All fields are validated types.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Destination {
    pub host: Host,
    pub user: Option<User>,
    pub port: Option<u16>,
    pub jump: Vec<JumpHop>,
    pub identity_file: Option<PathBuf>,
    pub auth: AuthMethod,
}

impl Destination {
    /// Options shared by the master and multiplexed clients, ending with `-- host`.
    fn target_args(&self, out: &mut Vec<OsString>) {
        if let Some(p) = self.port {
            out.extend(["-p".into(), p.to_string().into()]);
        }
        if let Some(u) = &self.user {
            out.extend(["-l".into(), u.as_str().into()]);
        }
    }

    fn auth_args(&self, out: &mut Vec<OsString>) {
        if !self.jump.is_empty() {
            let spec = self.jump.iter().map(JumpHop::to_spec).collect::<Vec<_>>().join(",");
            out.extend(["-J".into(), spec.into()]);
        }
        if let Some(key) = &self.identity_file {
            out.extend(["-i".into(), key.into()]);
        }
        let fixed: &[&str] = match self.auth {
            AuthMethod::Auto => &[],
            AuthMethod::Key => &["-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey"],
            AuthMethod::Agent => &["-o", "PreferredAuthentications=publickey"],
            AuthMethod::Password => &["-o", "PreferredAuthentications=keyboard-interactive,password", "-o", "PubkeyAuthentication=no"],
        };
        out.extend(fixed.iter().map(OsString::from));
    }

    /// `user@host:port` for display.
    pub fn label(&self) -> String {
        let user = self.user.as_ref().map(|u| format!("{}@", u.as_str())).unwrap_or_default();
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        format!("{user}{}{port}", self.host.for_destination())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Connecting,
    Authenticating,
    Connected,
}

/// Negotiated session parameters, parsed from `ssh -v`. Informational only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityInfo {
    pub remote_address: Option<String>,
    pub server_software: Option<String>,
    pub kex: Option<String>,
    pub host_key_algorithm: Option<String>,
    pub host_key_fingerprint: Option<String>,
    pub cipher: Option<String>,
    pub mac: Option<String>,
    pub auth_method: Option<String>,
}

impl SecurityInfo {
    /// Returns the connection phase this line indicates, if any.
    pub fn parse_line(&mut self, line: &str) -> Option<Phase> {
        let after = |prefix: &str| line.strip_prefix(prefix).map(str::trim);
        if let Some(rest) = after("debug1: Connecting to ") {
            // "host [1.2.3.4] port 22."
            self.remote_address = rest.split_once('[').and_then(|(_, r)| r.split_once(']')).map(|(ip, _)| ip.to_owned());
        } else if let Some(rest) = line.split_once("remote software version ").map(|(_, r)| r.trim()) {
            self.server_software = Some(rest.to_owned());
        } else if line.starts_with("debug1: Authenticating to ") {
            return Some(Phase::Authenticating);
        } else if let Some(rest) = after("debug1: kex: algorithm:") {
            self.kex = Some(rest.to_owned());
        } else if let Some(rest) = after("debug1: kex: host key algorithm:") {
            self.host_key_algorithm = Some(rest.to_owned());
        } else if let Some(rest) = after("debug1: kex: server->client cipher:") {
            // "chacha20-poly1305@openssh.com MAC: <implicit> compression: none"
            let mut it = rest.split_whitespace();
            self.cipher = it.next().map(str::to_owned);
            self.mac = it.nth(1).filter(|m| *m != "<implicit>").map(str::to_owned);
        } else if let Some(rest) = after("debug1: Server host key:") {
            self.host_key_fingerprint = rest.split_whitespace().nth(1).map(str::to_owned);
        } else if line.starts_with("Authenticated to ") {
            // Authenticated to h ([1.2.3.4]:22) using "publickey".
            self.auth_method = line.split('"').nth(1).map(str::to_owned);
        }
        None
    }
}

/// Paths and helper environment for one master process.
pub struct MasterSpec<'a> {
    pub ossh: &'a OpenSsh,
    pub dest: &'a Destination,
    pub config: &'a Path,
    pub socket: &'a Path,
    pub env: Vec<(String, String)>,
}

/// A running, authenticated master.
pub struct Master {
    pub socket: PathBuf,
    pub config: PathBuf,
    pub info: SecurityInfo,
    child: Arc<tokio::sync::Mutex<Child>>,
    /// Recent stderr (debug lines included), for diagnosing a later disconnect.
    log: Arc<Mutex<Vec<String>>>,
    exited: watch::Receiver<bool>,
}

const LOG_LINES: usize = 200;

fn push_log(log: &Mutex<Vec<String>>, line: String) {
    if let Ok(mut l) = log.lock() {
        if l.len() >= LOG_LINES {
            l.remove(0);
        }
        l.push(line);
    }
}

/// Starts the master and waits until it is authenticated (its control socket
/// appears) or has failed. `on_phase` reports progress with what is known so far.
pub async fn start(
    spec: MasterSpec<'_>,
    on_phase: impl Fn(Phase, &SecurityInfo) + Send + Sync + 'static,
) -> Result<Master, ConnectFailure> {
    let mut args: Vec<OsString> =
        vec!["-F".into(), spec.config.into(), "-M".into(), "-S".into(), spec.socket.into(), "-N".into(), "-v".into()];
    spec.dest.target_args(&mut args);
    spec.dest.auth_args(&mut args);
    args.extend(["--".into(), spec.dest.host.as_str().into()]);

    let _ = std::fs::remove_file(spec.socket);
    let mut child = Command::new(&spec.ossh.ssh)
        .args(&args)
        .envs(spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| ConnectFailure {
            kind: FailureKind::Unknown,
            message: "OpenSSH could not be started.".into(),
            details: e.to_string(),
        })?;
    on_phase(Phase::Connecting, &SecurityInfo::default());

    let stderr = child.stderr.take().expect("stderr is piped");
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let info: Arc<Mutex<SecurityInfo>> = Arc::default();
    let (exit_tx, exited) = watch::channel(false);
    let child = Arc::new(tokio::sync::Mutex::new(child));

    // Stderr reader: feeds the log and security info for the master's lifetime.
    let on_phase = Arc::new(on_phase);
    {
        let (log, info, on_phase) = (log.clone(), info.clone(), on_phase.clone());
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let update = info.lock().ok().and_then(|mut i| i.parse_line(&line).map(|p| (p, i.clone())));
                if let Some((phase, snapshot)) = update {
                    on_phase(phase, &snapshot);
                }
                push_log(&log, line);
            }
        });
    }
    // Exit watcher.
    {
        let child = child.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(Some(_)) = child.lock().await.try_wait() {
                    let _ = exit_tx.send(true);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }

    let mut exit_rx = exited.clone();
    loop {
        if spec.socket.exists() {
            let info = info.lock().map(|i| i.clone()).unwrap_or_default();
            on_phase(Phase::Connected, &info);
            return Ok(Master { socket: spec.socket.into(), config: spec.config.into(), info, child, log, exited });
        }
        tokio::select! {
            _ = exit_rx.changed() => {
                // Let the stderr reader drain the final lines.
                tokio::time::sleep(Duration::from_millis(50)).await;
                let lines = log.lock().map(|l| l.clone()).unwrap_or_default();
                return Err(classify(&lines));
            }
            _ = tokio::time::sleep(Duration::from_millis(40)) => {}
        }
    }
}

impl Master {
    /// Resolves when the connection ends.
    pub async fn closed(&self) {
        let mut rx = self.exited.clone();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn is_alive(&self) -> bool {
        !*self.exited.borrow()
    }

    /// Why the connection ended, from the master's stderr.
    pub fn failure(&self) -> ConnectFailure {
        classify(&self.log.lock().map(|l| l.clone()).unwrap_or_default())
    }

    /// Arguments for a multiplexed client through this master (no re-authentication).
    pub fn client_args(&self, dest: &Destination) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["-F".into(), self.config.clone().into(), "-S".into(), self.socket.clone().into()];
        dest.target_args(&mut args);
        args
    }

    /// Ends the connection and removes the socket and generated config.
    pub async fn close(&self) {
        let mut child = self.child.lock().await;
        let _ = child.start_kill();
        let _ = child.wait().await;
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(&self.config);
    }
}

/// Removes control sockets and configs left behind by a crashed instance.
/// Any orphaned master is asked to exit first.
pub fn cleanup_stale(ossh: &OpenSsh, runtime_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(runtime_dir) else { return };
    for e in entries.flatten() {
        let path = e.path();
        match path.extension().and_then(|x| x.to_str()) {
            Some("sock") if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with("cm-")) => {
                let _ = std::process::Command::new(&ossh.ssh)
                    .arg("-S")
                    .arg(&path)
                    .args(["-O", "exit", "stale"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = std::fs::remove_file(&path);
            }
            Some("conf") => {
                let _ = std::fs::remove_file(&path);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_debug_output() {
        let lines = [
            "debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2222.",
            "debug1: Remote protocol version 2.0, remote software version OpenSSH_10.0",
            "debug1: Authenticating to 127.0.0.1:2222 as 'pw'",
            "debug1: kex: algorithm: mlkem768x25519-sha256",
            "debug1: kex: host key algorithm: ssh-ed25519",
            "debug1: kex: server->client cipher: aes256-ctr MAC: hmac-sha2-256-etm@openssh.com compression: none",
            "debug1: Server host key: ssh-ed25519 SHA256:RaNAkPS+Ojr7MtUl1EZCX+pKlFEA5XXGGfb+93d2LOo",
            "Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using \"password\".",
        ];
        let mut info = SecurityInfo::default();
        let phases: Vec<_> = lines.iter().filter_map(|l| info.parse_line(l)).collect();
        assert_eq!(phases, [Phase::Authenticating]);
        assert_eq!(info.remote_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(info.server_software.as_deref(), Some("OpenSSH_10.0"));
        assert_eq!(info.kex.as_deref(), Some("mlkem768x25519-sha256"));
        assert_eq!(info.cipher.as_deref(), Some("aes256-ctr"));
        assert_eq!(info.mac.as_deref(), Some("hmac-sha2-256-etm@openssh.com"));
        assert_eq!(info.host_key_fingerprint.as_deref(), Some("SHA256:RaNAkPS+Ojr7MtUl1EZCX+pKlFEA5XXGGfb+93d2LOo"));
        assert_eq!(info.auth_method.as_deref(), Some("password"));

        let mut aead = SecurityInfo::default();
        aead.parse_line("debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none");
        assert_eq!((aead.cipher.as_deref(), aead.mac), (Some("chacha20-poly1305@openssh.com"), None));
    }

    #[test]
    fn builds_safe_arguments() {
        let dest = Destination {
            host: Host::parse("example.com").unwrap(),
            user: Some(User::parse("deploy").unwrap()),
            port: Some(2222),
            jump: crate::validate::jump_chain("ops@bastion:22").unwrap(),
            identity_file: Some("/home/u/.ssh/id_ed25519".into()),
            auth: AuthMethod::Key,
        };
        let mut args = Vec::new();
        dest.target_args(&mut args);
        dest.auth_args(&mut args);
        let args: Vec<String> = args.into_iter().map(|a| a.into_string().unwrap()).collect();
        assert_eq!(
            args,
            [
                "-p",
                "2222",
                "-l",
                "deploy",
                "-J",
                "ops@bastion:22",
                "-i",
                "/home/u/.ssh/id_ed25519",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey"
            ]
        );
        assert_eq!(dest.label(), "deploy@example.com:2222");
    }
}
