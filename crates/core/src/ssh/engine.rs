//! Ties OpenSSH discovery, the generated config, the helper bridge and the
//! master together. UI decisions arrive as [`HelperEvent`]s that the caller
//! answers; host-key bookkeeping lives here so every caller applies the same rules.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::SshError;
use super::config::{self, ConfigPaths, Policy};
use super::errors::{ConnectFailure, FailureKind};
use super::helper::{self, HelperEvent, HelperServer};
use super::known_hosts::{self, HostKeyStatus, OfferedKey};
use super::mux::{self, Destination, Master, MasterSpec, Phase};
use super::openssh::OpenSsh;
use crate::paths::AppPaths;

pub struct Engine {
    pub ossh: OpenSsh,
    pub paths: AppPaths,
    pub helper: HelperServer,
    exe: PathBuf,
    home: Option<PathBuf>,
    /// Passphrases the user already typed into a dialog, for `ssh-keygen` runs.
    scripted: Mutex<HashMap<String, VecDeque<SecretString>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Ssh(#[from] SshError),
    #[error("The SSH helper could not be started: {0}")]
    Io(#[from] std::io::Error),
}

impl Engine {
    /// `exe` is the binary `ssh` re-executes as askpass / KnownHostsCommand.
    pub async fn start(paths: AppPaths, exe: PathBuf) -> Result<(Engine, mpsc::Receiver<HelperEvent>), EngineError> {
        Self::start_with_home(paths, exe, dirs::home_dir()).await
    }

    /// As [`Engine::start`] with an explicit home directory (tests).
    pub async fn start_with_home(
        paths: AppPaths,
        exe: PathBuf,
        home: Option<PathBuf>,
    ) -> Result<(Engine, mpsc::Receiver<HelperEvent>), EngineError> {
        let ossh = OpenSsh::discover()?;
        mux::cleanup_stale(&ossh, &paths.runtime);
        let (helper, events) = helper::start(&paths.runtime).await?;
        Ok((Engine { ossh, paths, helper, exe, home, scripted: Mutex::default() }, events))
    }

    pub fn app_known_hosts(&self) -> PathBuf {
        self.paths.data.join("known_hosts")
    }

    pub fn user_known_hosts(&self) -> Option<PathBuf> {
        self.home.as_ref().map(|h| h.join(".ssh/known_hosts"))
    }

    /// Opens an authenticated master for `session`.
    pub async fn connect(
        &self,
        session: &str,
        dest: &Destination,
        policy: &Policy,
        on_phase: impl Fn(Phase, &mux::SecurityInfo) + Send + Sync + 'static,
    ) -> Result<Master, ConnectFailure> {
        let fail = |details: String| ConnectFailure {
            kind: FailureKind::ConfigProblem,
            message: FailureKind::ConfigProblem.message().into(),
            details,
        };
        let kh = self.app_known_hosts();
        let cfg_text =
            config::render(&self.ossh, &ConfigPaths { helper_exe: &self.exe, app_known_hosts: &kh, home: self.home.as_deref() }, policy)
                .map_err(|e| fail(e.to_string()))?;

        // The config path is inserted unquoted into the shell ProxyCommand that
        // OpenSSH builds for ProxyJump, so it must be free of shell metacharacters.
        let id: String = session.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(40).collect();
        let cfg_path = self.paths.runtime.join(format!("{id}.conf"));
        let sock = self.paths.runtime.join(format!("cm-{id}.sock"));
        let safe = |p: &Path| p.to_str().is_some_and(|s| s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)));
        if !safe(&cfg_path) {
            return Err(fail(format!("The runtime directory path {} must not contain spaces or special characters.", cfg_path.display())));
        }
        crate::paths::write_private(&cfg_path, cfg_text.as_bytes()).map_err(|e| fail(e.to_string()))?;

        let env = self.helper.env_for(session, &self.exe);
        let result = mux::start(MasterSpec { ossh: &self.ossh, dest, config: &cfg_path, socket: &sock, env }, on_phase).await;
        if result.is_err() {
            let _ = std::fs::remove_file(&cfg_path);
        }
        result
    }

    pub fn check_host_key(&self, key: &OfferedKey) -> HostKeyStatus {
        let files = known_hosts::sources(&self.app_known_hosts(), self.home.as_deref());
        known_hosts::check(&self.ossh.keygen, &files, key)
    }

    /// Records a trusted key and returns the line for the helper to print.
    /// `replace` first removes earlier keys for the host. The user's
    /// ~/.ssh/known_hosts is only touched when `also_user_file` is set.
    pub fn trust_host_key(&self, key: &OfferedKey, replace: bool, also_user_file: bool) -> std::io::Result<String> {
        let mut files = vec![self.app_known_hosts()];
        if also_user_file && let Some(user) = self.user_known_hosts() {
            files.push(user);
        }
        for file in &files {
            if replace {
                known_hosts::forget(&self.ossh.keygen, file, &key.host)?;
            }
            known_hosts::trust(file, key)?;
        }
        Ok(key.line())
    }

    /// For an askpass event: the queued answer if this session is a scripted
    /// `ssh-keygen` run and the prompt asks for a passphrase. Other prompts (a
    /// security-key PIN, say) still go to the user.
    pub fn scripted_answer(&self, session: &str, prompt: &str) -> Option<Zeroizing<String>> {
        if !prompt.to_ascii_lowercase().contains("passphrase") {
            return None;
        }
        let mut map = self.scripted.lock().ok()?;
        map.get_mut(session)?.pop_front().map(|s| Zeroizing::new(s.expose_secret().to_owned()))
    }

    /// Runs `ssh-keygen` with passphrases supplied through askpass, never argv.
    pub async fn run_keygen(&self, args: &[std::ffi::OsString], answers: Vec<SecretString>) -> std::io::Result<std::process::Output> {
        let session = format!("keygen-{}", uuid::Uuid::new_v4());
        if let Ok(mut m) = self.scripted.lock() {
            m.insert(session.clone(), answers.into());
        }
        let out = tokio::process::Command::new(&self.ossh.keygen)
            .args(args)
            .envs(self.helper.env_for(&session, &self.exe))
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output()
            .await;
        if let Ok(mut m) = self.scripted.lock() {
            m.remove(&session);
        }
        self.helper.forget_session(&session);
        out
    }

    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    pub fn shutdown(&self) {
        let _ = std::fs::remove_file(&self.helper.sock_path);
    }
}
