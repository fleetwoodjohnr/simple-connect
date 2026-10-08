//! Application core: sessions, prompts, terminals, transfers and tunnels.
//!
//! The Tauri layer is a thin adapter: it forwards commands here and delivers
//! [`UiEvent`]s to the webview. Keeping this logic here means it is exercised by
//! the integration tests without a GUI.

pub mod sysinfo;
pub mod transfers;
pub mod tunnels;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use tokio::sync::{Notify, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::profiles;
use crate::security::{CredentialStore, SecretError, new_password_ref, passphrase_ref};
use crate::settings::Settings;
use crate::sftp::{RemoteFs, SftpError};
use crate::ssh::config::Policy;
use crate::ssh::engine::Engine;
use crate::ssh::errors::{ConnectFailure, FailureKind};
use crate::ssh::helper::{HelperEvent, PromptKind};
use crate::ssh::known_hosts::{HostKeyStatus, KnownKey, OfferedKey};
use crate::ssh::mux::{Destination, Master, Phase, SecurityInfo};
use crate::ssh::prompt::{PromptDetector, is_login_prompt};
use crate::ssh::terminal::Terminal;

pub type Db = Arc<Mutex<rusqlite::Connection>>;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Status {
    Connecting,
    Authenticating,
    Connected,
    Reconnecting { attempt: u32, delay_secs: u64 },
    Disconnected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SecretPromptKind {
    /// OpenSSH's own `user@host's password:` prompt.
    Password,
    /// Private key passphrase.
    Passphrase,
    /// Security key PIN.
    Pin,
    /// Keyboard-interactive: the text comes from the server and is untrusted.
    Server,
    /// Yes/no confirmation.
    Confirm,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum UiEvent {
    Session {
        session: String,
        label: String,
        status: Status,
        info: Option<SecurityInfo>,
        failure: Option<ConnectFailure>,
    },
    HostKeyPrompt {
        id: u64,
        session: String,
        host: String,
        address: Option<String>,
        key_type: String,
        fingerprint: String,
        changed: bool,
        previous: Vec<KnownKey>,
    },
    SecretPrompt {
        id: u64,
        session: String,
        kind: SecretPromptKind,
        prompt: String,
        can_save: bool,
    },
    PromptClosed {
        id: u64,
    },
    Notice {
        id: u64,
        session: String,
        text: String,
    },
    NoticeDone {
        id: u64,
    },
    TerminalExit {
        session: String,
        terminal: String,
    },
    Transfers {
        jobs: Vec<transfers::JobView>,
    },
    Tunnels {
        session: String,
        tunnels: Vec<tunnels::Tunnel>,
    },
    /// A sudo/su password prompt is waiting in a terminal and the login password
    /// can be offered (`visible`), or the prompt went away.
    PasswordPrompt {
        session: String,
        terminal: String,
        visible: bool,
    },
}

pub trait Ui: Send + Sync + 'static {
    fn emit(&self, event: UiEvent);
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("That session no longer exists.")]
    NoSession,
    #[error("Not connected. Reconnect and try again.")]
    NotConnected,
    #[error("This prompt has expired.")]
    PromptExpired,
    #[error("Type the host name exactly as shown to confirm.")]
    ConfirmationMismatch,
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error(transparent)]
    Sftp(#[from] SftpError),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub dest: Destination,
    pub label: String,
    pub profile_id: Option<String>,
    pub legacy_crypto: bool,
    pub keepalive_secs: Option<u16>,
    pub start_dir: Option<String>,
    /// Per-connection override of `Settings::reuse_ssh_password`.
    pub reuse_password: Option<bool>,
}

enum SaveTarget {
    ProfilePassword(String),
    KeyPassphrase(PathBuf),
}

enum Pending {
    HostKey {
        key: OfferedKey,
        changed: bool,
        reply: oneshot::Sender<Result<Option<String>, ()>>,
    },
    /// `login`: the prompt asks for the target's login password (candidate for reuse).
    Secret {
        session: String,
        save: Option<SaveTarget>,
        login: bool,
        reply: oneshot::Sender<Option<Zeroizing<String>>>,
    },
}

struct TermEntry {
    term: Arc<Terminal>,
    prompt: Arc<Mutex<PromptDetector>>,
}

pub struct Session {
    pub id: String,
    pub req: ConnectRequest,
    master: RwLock<Option<Arc<Master>>>,
    sftp: tokio::sync::Mutex<Option<Arc<RemoteFs>>>,
    terminals: Mutex<HashMap<String, TermEntry>>,
    info: Mutex<SecurityInfo>,
    closing: AtomicBool,
    running: AtomicBool,
    wake: Notify,
    password_autofills: AtomicU32,
    passphrase_autofills: AtomicU32,
    /// The current attempt met a changed host key (explains a later rejection).
    host_key_changed: AtomicBool,
    /// The password typed (or filled in) for the target during this attempt.
    login_candidate: Mutex<Option<SecretString>>,
    /// The password that signed in, kept for sudo prompts when reuse is enabled.
    /// Zeroized when the session ends. Never logged or sent to the webview.
    login_password: Mutex<Option<SecretString>>,
    /// A secret the user asked to save; stored only once sign-in succeeds.
    save_on_success: Mutex<Vec<(SaveTarget, SecretString)>>,
}

impl Session {
    pub fn master(&self) -> Option<Arc<Master>> {
        self.master.read().ok()?.clone().filter(|m| m.is_alive())
    }
}

pub struct Manager {
    pub engine: Arc<Engine>,
    ui: Arc<dyn Ui>,
    pub db: Db,
    settings: RwLock<Settings>,
    store: RwLock<Option<Arc<dyn CredentialStore>>>,
    locked: AtomicBool,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    prompts: Mutex<HashMap<u64, Pending>>,
    next_id: AtomicU64,
    pub transfers: transfers::Queue,
    pub tunnels: tunnels::Registry,
}

const MAX_RECONNECT_ATTEMPTS: u32 = 8;

impl Manager {
    pub fn new(engine: Arc<Engine>, ui: Arc<dyn Ui>, db: Db, settings: Settings, events: mpsc::Receiver<HelperEvent>) -> Arc<Manager> {
        let m = Arc::new(Manager {
            engine,
            ui,
            db,
            settings: RwLock::new(settings),
            store: RwLock::new(None),
            locked: AtomicBool::new(false),
            sessions: Mutex::default(),
            prompts: Mutex::default(),
            next_id: AtomicU64::new(1),
            transfers: transfers::Queue::default(),
            tunnels: tunnels::Registry::default(),
        });
        tokio::spawn(m.clone().helper_loop(events));
        m
    }

    pub fn emit(&self, e: UiEvent) {
        self.ui.emit(e);
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn set_settings(&self, s: Settings) {
        if let Ok(mut cur) = self.settings.write() {
            *cur = s.sanitized();
        }
    }

    // ---- secrets & lock -------------------------------------------------------

    pub fn set_store(&self, store: Option<Arc<dyn CredentialStore>>) {
        if let Ok(mut s) = self.store.write() {
            *s = store;
        }
    }

    pub fn set_locked(&self, locked: bool) {
        self.locked.store(locked, Ordering::SeqCst);
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    /// The credential store, unless the app is locked or none is available.
    pub fn store(&self) -> Result<Arc<dyn CredentialStore>, SecretError> {
        if self.is_locked() {
            return Err(SecretError::Locked);
        }
        self.store.read().ok().and_then(|s| s.clone()).ok_or_else(|| SecretError::Keyring("no credential store is configured".into()))
    }

    async fn get_secret(&self, id: String) -> Option<SecretString> {
        let store = self.store().ok()?;
        tokio::task::spawn_blocking(move || store.get(&id)).await.ok()?.ok()?
    }

    async fn save_secret(&self, target: SaveTarget, secret: SecretString) -> Result<(), AppError> {
        let store = self.store()?;
        let id = match &target {
            SaveTarget::KeyPassphrase(path) => passphrase_ref(path),
            SaveTarget::ProfilePassword(pid) => {
                let conn = self.db.lock().map_err(|_| AppError::Invalid("database unavailable".into()))?;
                match profiles::secret_ref(&conn, pid).map_err(|e| AppError::Invalid(e.to_string()))? {
                    Some(r) => r,
                    None => {
                        let r = new_password_ref();
                        profiles::set_secret_ref(&conn, pid, Some(&r)).map_err(|e| AppError::Invalid(e.to_string()))?;
                        r
                    }
                }
            }
        };
        tokio::task::spawn_blocking(move || store.set(&id, &secret)).await.map_err(|e| AppError::Invalid(e.to_string()))??;
        Ok(())
    }

    /// Removes a profile's saved password (on profile deletion or user request).
    pub async fn forget_secret(&self, secret_ref: String) -> Result<(), AppError> {
        let store = self.store()?;
        tokio::task::spawn_blocking(move || store.delete(&secret_ref)).await.map_err(|e| AppError::Invalid(e.to_string()))??;
        Ok(())
    }

    // ---- sessions -----------------------------------------------------------

    pub fn session(&self, id: &str) -> Result<Arc<Session>, AppError> {
        self.sessions.lock().ok().and_then(|s| s.get(id).cloned()).ok_or(AppError::NoSession)
    }

    pub fn connect(self: &Arc<Self>, req: ConnectRequest) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let s = Arc::new(Session {
            id: id.clone(),
            req,
            master: RwLock::new(None),
            sftp: tokio::sync::Mutex::new(None),
            terminals: Mutex::default(),
            info: Mutex::default(),
            closing: AtomicBool::new(false),
            running: AtomicBool::new(false),
            wake: Notify::new(),
            password_autofills: AtomicU32::new(0),
            passphrase_autofills: AtomicU32::new(0),
            host_key_changed: AtomicBool::new(false),
            login_candidate: Mutex::default(),
            login_password: Mutex::default(),
            save_on_success: Mutex::default(),
        });
        if let Ok(mut map) = self.sessions.lock() {
            map.insert(id.clone(), s.clone());
        }
        self.start_loop(s);
        id
    }

    fn start_loop(self: &Arc<Self>, s: Arc<Session>) {
        if !s.running.swap(true, Ordering::SeqCst) {
            tokio::spawn(self.clone().run_session(s));
        }
    }

    fn status(&self, s: &Session, status: Status, failure: Option<ConnectFailure>) {
        let info = s.info.lock().ok().map(|i| i.clone());
        self.emit(UiEvent::Session { session: s.id.clone(), label: s.req.label.clone(), status, info, failure });
    }

    fn policy(&self, s: &Session) -> Policy {
        let st = self.settings();
        Policy {
            include_user_config: st.include_user_ssh_config,
            legacy_crypto: s.req.legacy_crypto,
            keepalive_secs: s.req.keepalive_secs.unwrap_or(st.keepalive_secs),
            connect_timeout_secs: st.connect_timeout_secs,
        }
    }

    async fn run_session(self: Arc<Self>, s: Arc<Session>) {
        let mut attempt = 0u32;
        loop {
            if s.closing.load(Ordering::SeqCst) {
                break;
            }
            s.password_autofills.store(0, Ordering::SeqCst);
            s.passphrase_autofills.store(0, Ordering::SeqCst);
            s.host_key_changed.store(false, Ordering::SeqCst);
            if let Ok(mut c) = s.login_candidate.lock() {
                *c = None;
            }
            self.status(&s, Status::Connecting, None);
            let (me, sess) = (self.clone(), s.clone());
            let on_phase = move |phase: Phase, info: &SecurityInfo| {
                if let Ok(mut i) = sess.info.lock() {
                    *i = info.clone();
                }
                match phase {
                    Phase::Authenticating => me.status(&sess, Status::Authenticating, None),
                    Phase::Connecting | Phase::Connected => {}
                }
            };
            let result = self.engine.connect(&s.id, &s.req.dest, &self.policy(&s), on_phase).await;
            match result {
                Ok(master) => {
                    attempt = 0;
                    if let Ok(mut i) = s.info.lock() {
                        *i = master.info.clone();
                    }
                    let master = Arc::new(master);
                    if let Ok(mut m) = s.master.write() {
                        *m = Some(master.clone());
                    }
                    self.commit_saved_secrets(&s).await;
                    let candidate = s.login_candidate.lock().ok().and_then(|mut c| c.take());
                    if candidate.is_some()
                        && self.reuse_enabled(&s)
                        && let Ok(mut lp) = s.login_password.lock()
                    {
                        *lp = candidate;
                    }
                    if let Some(pid) = &s.req.profile_id
                        && let Ok(conn) = self.db.lock()
                    {
                        let _ = profiles::touch(&conn, pid);
                    }
                    self.status(&s, Status::Connected, None);
                    self.tunnels.restore(&self, &s).await;
                    self.transfers.resume_interrupted(&self, &s.id);

                    master.closed().await;
                    if let Ok(mut m) = s.master.write() {
                        *m = None;
                    }
                    *s.sftp.lock().await = None;
                    self.tunnels.mark_inactive(&self, &s.id);
                    if s.closing.load(Ordering::SeqCst) {
                        break;
                    }
                    if !self.settings().auto_reconnect {
                        self.status(&s, Status::Disconnected, Some(master.failure()));
                        s.running.store(false, Ordering::SeqCst);
                        return;
                    }
                }
                Err(mut failure) => {
                    if failure.kind == FailureKind::HostKeyRejected && s.host_key_changed.load(Ordering::SeqCst) {
                        failure.kind = FailureKind::HostKeyChanged;
                        failure.message = FailureKind::HostKeyChanged.message().into();
                    }
                    let permanent = matches!(
                        failure.kind,
                        FailureKind::AuthFailed
                            | FailureKind::TooManyAuthFailures
                            | FailureKind::HostKeyRejected
                            | FailureKind::HostKeyChanged
                            | FailureKind::NoCommonAlgorithms
                            | FailureKind::ConfigProblem
                            | FailureKind::DnsFailed
                    );
                    // A first attempt that fails is reported, not retried: the user
                    // decides. Only an established connection that drops is retried.
                    if attempt == 0 || permanent || s.closing.load(Ordering::SeqCst) {
                        self.status(&s, Status::Failed, Some(failure));
                        s.running.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            }
            attempt += 1;
            if attempt > MAX_RECONNECT_ATTEMPTS {
                self.status(&s, Status::Failed, None);
                s.running.store(false, Ordering::SeqCst);
                return;
            }
            let delay = (1u64 << (attempt - 1).min(5)).min(30);
            self.status(&s, Status::Reconnecting { attempt, delay_secs: delay }, None);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
                _ = s.wake.notified() => {}
            }
        }
        self.status(&s, Status::Disconnected, None);
        s.running.store(false, Ordering::SeqCst);
    }

    async fn commit_saved_secrets(&self, s: &Session) {
        let pending: Vec<_> = s.save_on_success.lock().map(|mut v| std::mem::take(&mut *v)).unwrap_or_default();
        for (target, secret) in pending {
            if let Err(e) = self.save_secret(target, secret).await {
                tracing::warn!(session = %s.id, "could not save secret: {e}");
            }
        }
    }

    /// Reconnects now: restarts a failed session, or skips the backoff wait.
    pub async fn reconnect(self: &Arc<Self>, id: &str) -> Result<(), AppError> {
        let s = self.session(id)?;
        s.closing.store(false, Ordering::SeqCst);
        if let Some(m) = s.master() {
            m.close().await; // the loop notices and reconnects
        }
        s.wake.notify_one();
        self.start_loop(s);
        Ok(())
    }

    /// Closes the connection and forgets the session.
    pub async fn disconnect(&self, id: &str) -> Result<(), AppError> {
        let s = self.session(id)?;
        s.closing.store(true, Ordering::SeqCst);
        s.wake.notify_one();
        self.cancel_prompts(id);
        self.transfers.cancel_session(id);
        if let Ok(mut t) = s.terminals.lock() {
            t.drain().for_each(|(_, entry)| entry.term.kill());
        }
        if let Some(m) = s.master() {
            m.close().await;
        }
        self.engine.helper.forget_session(id);
        self.tunnels.forget_session(id);
        if let Ok(mut map) = self.sessions.lock() {
            map.remove(id);
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        let ids: Vec<String> = self.sessions.lock().map(|m| m.keys().cloned().collect()).unwrap_or_default();
        for id in ids {
            let _ = self.disconnect(&id).await;
        }
        self.engine.shutdown();
    }

    // ---- prompts --------------------------------------------------------------

    async fn helper_loop(self: Arc<Self>, mut events: mpsc::Receiver<HelperEvent>) {
        while let Some(ev) = events.recv().await {
            let me = self.clone();
            tokio::spawn(async move { me.on_helper(ev).await });
        }
    }

    async fn on_helper(&self, ev: HelperEvent) {
        match ev {
            HelperEvent::KnownHost { session, key, reply, .. } => self.on_host_key(session, key, reply).await,
            HelperEvent::Askpass { session, prompt, kind, reply } => self.on_askpass(session, prompt, kind, reply).await,
            HelperEvent::Notify { session, id, prompt } => self.emit(UiEvent::Notice { id, session, text: prompt }),
            HelperEvent::NotifyDone { id, .. } => self.emit(UiEvent::NoticeDone { id }),
        }
    }

    async fn on_host_key(&self, session: String, key: OfferedKey, reply: oneshot::Sender<Result<Option<String>, ()>>) {
        let engine = self.engine.clone();
        let k = key.clone();
        let status = tokio::task::spawn_blocking(move || engine.check_host_key(&k)).await.unwrap_or(HostKeyStatus::Revoked);
        let (changed, previous) = match status {
            HostKeyStatus::Known => return drop(reply.send(Ok(None))),
            HostKeyStatus::Revoked => return drop(reply.send(Err(()))),
            // Certificates are validated by ssh against @cert-authority lines.
            _ if key.is_certificate() => return drop(reply.send(Ok(None))),
            HostKeyStatus::Unknown => (false, Vec::new()),
            HostKeyStatus::Changed { previous } => (true, previous),
        };
        if changed && let Ok(s) = self.session(&session) {
            s.host_key_changed.store(true, Ordering::SeqCst);
        }
        let host = display_host(&key.host).to_owned();
        // The address from `ssh -v` belongs to the first hop, so only show it for
        // direct connections to this host.
        let address = self.session(&session).ok().and_then(|s| {
            let direct = s.req.dest.jump.is_empty() && s.req.dest.host.as_str() == host;
            direct.then(|| s.info.lock().ok()?.remote_address.clone()).flatten()
        });
        let id = self.next_id();
        let event = UiEvent::HostKeyPrompt {
            id,
            session,
            host,
            address,
            key_type: key.key_type.clone(),
            fingerprint: key.fingerprint(),
            changed,
            previous,
        };
        if let Ok(mut p) = self.prompts.lock() {
            p.insert(id, Pending::HostKey { key, changed, reply });
        }
        self.emit(event);
    }

    /// The user's host-key decision. A changed key additionally requires the
    /// host name to be typed (`typed_host`).
    pub async fn answer_host_key(&self, id: u64, trust: bool, typed_host: Option<String>) -> Result<(), AppError> {
        let pending = self.prompts.lock().ok().and_then(|mut p| p.remove(&id)).ok_or(AppError::PromptExpired)?;
        let Pending::HostKey { key, changed, reply } = pending else { return Err(AppError::PromptExpired) };
        if !trust {
            let _ = reply.send(Err(()));
            self.emit(UiEvent::PromptClosed { id });
            return Ok(());
        }
        if changed && typed_host.as_deref().map(str::trim) != Some(display_host(&key.host)) {
            if let Ok(mut p) = self.prompts.lock() {
                p.insert(id, Pending::HostKey { key, changed, reply });
            }
            return Err(AppError::ConfirmationMismatch);
        }
        let also_user = self.settings().write_user_known_hosts;
        let engine = self.engine.clone();
        let line = tokio::task::spawn_blocking(move || engine.trust_host_key(&key, changed, also_user))
            .await
            .map_err(|e| AppError::Invalid(e.to_string()))?;
        let _ = reply.send(line.map(Some).map_err(|e| tracing::error!("could not record host key: {e}")));
        self.emit(UiEvent::PromptClosed { id });
        Ok(())
    }

    async fn on_askpass(&self, session: String, prompt: String, kind: PromptKind, reply: oneshot::Sender<Option<Zeroizing<String>>>) {
        if let Some(answer) = self.engine.scripted_answer(&session, &prompt) {
            let _ = reply.send(Some(answer));
            return;
        }
        let s = self.session(&session).ok();
        let (kind, save) = classify_prompt(&prompt, kind, s.as_deref());
        let login = s.as_ref().is_some_and(|s| {
            let d = &s.req.dest;
            let password_prompt = kind == SecretPromptKind::Password;
            (password_prompt || kind == SecretPromptKind::Server)
                && is_login_prompt(&prompt, password_prompt, d.user.as_ref().map(|u| u.as_str()), d.host.as_str(), d.jump.is_empty())
        });

        // Saved secrets are filled in once per connection attempt, and only for
        // prompts that OpenSSH itself generates for the expected target.
        if let Some(s) = &s {
            let saved_id = match &save {
                Some(SaveTarget::ProfilePassword(_)) if s.password_autofills.fetch_add(1, Ordering::SeqCst) == 0 => {
                    s.req.profile_id.as_ref().and_then(|pid| self.db.lock().ok().and_then(|c| profiles::secret_ref(&c, pid).ok().flatten()))
                }
                Some(SaveTarget::KeyPassphrase(path)) if s.passphrase_autofills.fetch_add(1, Ordering::SeqCst) == 0 => {
                    Some(passphrase_ref(path))
                }
                _ => None,
            };
            if let Some(id) = saved_id
                && let Some(secret) = self.get_secret(id).await
            {
                let _ = reply.send(Some(Zeroizing::new(secret.expose_secret().to_owned())));
                if login && let Ok(mut c) = s.login_candidate.lock() {
                    *c = Some(secret);
                }
                return;
            }
        }

        let id = self.next_id();
        let can_save = save.is_some();
        self.emit(UiEvent::SecretPrompt { id, session: session.clone(), kind, prompt, can_save });
        if let Ok(mut p) = self.prompts.lock() {
            p.insert(id, Pending::Secret { session, save, login, reply });
        }
    }

    /// The user's answer to a secret prompt (`None` = cancelled). With `save`,
    /// the secret is stored once sign-in succeeds.
    pub fn answer_secret(&self, id: u64, value: Option<String>, save: bool) -> Result<(), AppError> {
        let pending = self.prompts.lock().ok().and_then(|mut p| p.remove(&id)).ok_or(AppError::PromptExpired)?;
        let Pending::Secret { session, save: target, login, reply } = pending else { return Err(AppError::PromptExpired) };
        let value = value.map(Zeroizing::new);
        if let (Some(v), true) = (&value, login)
            && let Ok(s) = self.session(&session)
            && let Ok(mut c) = s.login_candidate.lock()
        {
            *c = Some(SecretString::from(v.as_str().to_owned()));
        }
        if let (Some(v), Some(target), true) = (&value, target, save)
            && let Ok(s) = self.session(&session)
            && let Ok(mut list) = s.save_on_success.lock()
        {
            list.push((target, SecretString::from(v.as_str().to_owned())));
        }
        let _ = reply.send(value);
        self.emit(UiEvent::PromptClosed { id });
        Ok(())
    }

    fn cancel_prompts(&self, session: &str) {
        let ids: Vec<u64> = self
            .prompts
            .lock()
            .map(|mut p| {
                let ids: Vec<u64> =
                    p.iter().filter(|(_, v)| matches!(v, Pending::Secret { session: s, .. } if s == session)).map(|(k, _)| *k).collect();
                ids.iter().for_each(|k| drop(p.remove(k)));
                ids
            })
            .unwrap_or_default();
        ids.into_iter().for_each(|id| self.emit(UiEvent::PromptClosed { id }));
    }

    // ---- terminals ------------------------------------------------------------

    pub fn open_terminal(
        self: &Arc<Self>,
        session: &str,
        cols: u16,
        rows: u16,
        sink: impl FnMut(Vec<u8>) + Send + 'static,
    ) -> Result<String, AppError> {
        let s = self.session(session)?;
        let master = s.master().ok_or(AppError::NotConnected)?;
        let mut args = master.client_args(&s.req.dest);
        args.extend(["-tt".into(), "--".into(), s.req.dest.host.as_str().into()]);
        if let Some(dir) = &s.req.start_dir {
            args.push(format!("cd -- {} 2>/dev/null; exec \"$SHELL\" -l", crate::ssh::shell::quote(dir)).into());
        }
        let term_id = uuid::Uuid::new_v4().to_string();
        let prompt = Arc::new(Mutex::new(PromptDetector::new(s.req.dest.user.as_ref().map(|u| u.as_str()), s.req.dest.host.as_str())));
        let mut sink = sink;
        let (me, sid, tid, detector) = (Arc::downgrade(self), s.id.clone(), term_id.clone(), prompt.clone());
        let watched = move |bytes: Vec<u8>| {
            let change = detector.lock().ok().and_then(|mut d| d.feed(&bytes));
            if let (Some(visible), Some(me)) = (change, me.upgrade())
                && (!visible || me.can_offer_password(&sid))
            {
                me.emit(UiEvent::PasswordPrompt { session: sid.clone(), terminal: tid.clone(), visible });
            }
            sink(bytes);
        };
        let (me, sid, tid) = (Arc::downgrade(self), s.id.clone(), term_id.clone());
        let term = Terminal::spawn(&self.engine.ossh.ssh, args, cols, rows, watched, move || {
            if let Some(me) = me.upgrade() {
                if let Ok(s) = me.session(&sid)
                    && let Ok(mut t) = s.terminals.lock()
                {
                    t.remove(&tid);
                }
                me.emit(UiEvent::TerminalExit { session: sid, terminal: tid });
            }
        })?;
        if let Ok(mut t) = s.terminals.lock() {
            t.insert(term_id.clone(), TermEntry { term: Arc::new(term), prompt });
        }
        Ok(term_id)
    }

    fn entry(&self, session: &str, terminal: &str) -> Result<(Arc<Terminal>, Arc<Mutex<PromptDetector>>), AppError> {
        let s = self.session(session)?;
        let t = s.terminals.lock().ok().and_then(|t| t.get(terminal).map(|e| (e.term.clone(), e.prompt.clone())));
        t.ok_or(AppError::NotConnected)
    }

    pub fn terminal(&self, session: &str, terminal: &str) -> Result<Arc<Terminal>, AppError> {
        Ok(self.entry(session, terminal)?.0)
    }

    /// Keyboard input. Typing answers any waiting prompt by hand, so the offer is withdrawn.
    pub fn terminal_write(&self, session: &str, terminal: &str, data: &[u8]) -> Result<(), AppError> {
        let (term, prompt) = self.entry(session, terminal)?;
        if prompt.lock().is_ok_and(|mut p| p.reset()) {
            self.emit(UiEvent::PasswordPrompt { session: session.into(), terminal: terminal.into(), visible: false });
        }
        Ok(term.write(data)?)
    }

    fn reuse_enabled(&self, s: &Session) -> bool {
        s.req.reuse_password.unwrap_or_else(|| self.settings().reuse_ssh_password)
    }

    fn can_offer_password(&self, session: &str) -> bool {
        !self.is_locked()
            && self.session(session).is_ok_and(|s| self.reuse_enabled(&s) && s.login_password.lock().is_ok_and(|p| p.is_some()))
    }

    /// Answers the waiting sudo/su prompt with the session's login password, at
    /// the user's request. The password goes straight into the terminal: it never
    /// crosses IPC, and is refused unless the backend itself sees a prompt waiting.
    pub fn terminal_send_password(&self, session: &str, terminal: &str) -> Result<(), AppError> {
        if !self.can_offer_password(session) {
            return Err(AppError::Invalid("There's no saved sign-in password to use here.".into()));
        }
        let (term, prompt) = self.entry(session, terminal)?;
        let mut detector = prompt.lock().map_err(|_| AppError::Invalid("terminal state unavailable".into()))?;
        if !detector.showing {
            return Err(AppError::Invalid("No password prompt is waiting.".into()));
        }
        let password = self.session(session)?.login_password.lock().ok().and_then(|p| p.clone());
        let password = password.ok_or_else(|| AppError::Invalid("There's no saved sign-in password to use here.".into()))?;
        let mut line = Zeroizing::new(Vec::with_capacity(password.expose_secret().len() + 1));
        line.extend_from_slice(password.expose_secret().as_bytes());
        line.push(b'\r');
        term.write(&line)?;
        detector.reset();
        drop(detector);
        self.emit(UiEvent::PasswordPrompt { session: session.into(), terminal: terminal.into(), visible: false });
        Ok(())
    }

    pub fn close_terminal(&self, session: &str, terminal: &str) {
        if let Ok(s) = self.session(session)
            && let Ok(mut t) = s.terminals.lock()
            && let Some(entry) = t.remove(terminal)
        {
            entry.term.kill();
        }
    }

    // ---- SFTP ---------------------------------------------------------------

    /// The session's SFTP channel, opened on first use over the existing master.
    pub async fn sftp(&self, session: &str) -> Result<Arc<RemoteFs>, AppError> {
        let s = self.session(session)?;
        let mut slot = s.sftp.lock().await;
        if let Some(fs) = slot.as_ref() {
            return Ok(fs.clone());
        }
        let master = s.master().ok_or(AppError::NotConnected)?;
        let fs = Arc::new(RemoteFs::open(&self.engine.ossh, &master, &s.req.dest).await?);
        *slot = Some(fs.clone());
        Ok(fs)
    }

    /// Runs a command on the server through the master (no TTY, stdin closed).
    /// Callers build `command` from fixed text plus [`crate::ssh::shell::quote`]d values.
    pub async fn remote_exec(&self, session: &str, command: String, timeout: Duration) -> Result<std::process::Output, AppError> {
        let s = self.session(session)?;
        let master = s.master().ok_or(AppError::NotConnected)?;
        let mut args = master.client_args(&s.req.dest);
        args.extend(["-T".into(), "--".into(), s.req.dest.host.as_str().into(), command.into()]);
        let run =
            tokio::process::Command::new(&self.engine.ossh.ssh).args(args).stdin(std::process::Stdio::null()).kill_on_drop(true).output();
        Ok(tokio::time::timeout(timeout, run).await.map_err(|_| AppError::Invalid("The server took too long to respond.".into()))??)
    }

    /// Server-side copy (`cp -R -p`); needs a POSIX server.
    pub async fn remote_copy(&self, session: &str, from: &str, to: &str) -> Result<(), AppError> {
        use crate::ssh::shell::quote;
        let out = self.remote_exec(session, format!("cp -R -p -- {} {}", quote(from), quote(to)), Duration::from_secs(600)).await?;
        if out.status.success() {
            return Ok(());
        }
        let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        Err(AppError::Invalid(if err.is_empty() { "Copying isn't supported on this server.".into() } else { err }))
    }

    /// Drops a broken SFTP channel so the next call reopens it.
    pub async fn reset_sftp(&self, session: &str) {
        if let Ok(s) = self.session(session) {
            *s.sftp.lock().await = None;
        }
    }
}

/// `[host]:port` → `host`.
pub fn display_host(known_hosts_name: &str) -> &str {
    known_hosts_name.strip_prefix('[').and_then(|r| r.split_once("]:")).map_or(known_hosts_name, |(h, _)| h)
}

fn classify_prompt(prompt: &str, kind: PromptKind, s: Option<&Session>) -> (SecretPromptKind, Option<SaveTarget>) {
    if kind == PromptKind::Confirm {
        return (SecretPromptKind::Confirm, None);
    }
    // OpenSSH: "%.30s@%.128s's password: "
    if let Some(who) = prompt.strip_suffix("'s password: ").filter(|w| !w.contains('\n')) {
        let save = s.and_then(|s| {
            let d = &s.req.dest;
            let expected_user = d.user.as_ref().map(|u| u.as_str());
            let (user, host) = who.rsplit_once('@')?;
            let matches = host == d.host.as_str() && expected_user.is_none_or(|u| u == user);
            matches.then(|| s.req.profile_id.clone().map(SaveTarget::ProfilePassword)).flatten()
        });
        return (SecretPromptKind::Password, save);
    }
    // "Enter passphrase for key '/path': " (ssh) / `Enter passphrase for "/path"` (newer)
    if let Some(rest) = prompt.strip_prefix("Enter passphrase for key ").or_else(|| prompt.strip_prefix("Enter passphrase for ")) {
        let path = rest.trim().trim_end_matches(':').trim_matches(|c| c == '\'' || c == '"');
        let save = (s.is_some() && path.starts_with('/')).then(|| SaveTarget::KeyPassphrase(PathBuf::from(path)));
        return (SecretPromptKind::Passphrase, save);
    }
    if prompt.contains("PIN") {
        return (SecretPromptKind::Pin, None);
    }
    (SecretPromptKind::Server, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_display() {
        assert_eq!(display_host("[127.0.0.1]:2222"), "127.0.0.1");
        assert_eq!(display_host("[fd00::1]:22"), "fd00::1");
        assert_eq!(display_host("example.com"), "example.com");
    }

    #[test]
    fn prompt_classification() {
        let (k, _) = classify_prompt("pw@127.0.0.1's password: ", PromptKind::Secret, None);
        assert_eq!(k, SecretPromptKind::Password);
        let (k, _) = classify_prompt("Enter passphrase for key '/home/u/.ssh/id': ", PromptKind::Secret, None);
        assert_eq!(k, SecretPromptKind::Passphrase);
        let (k, _) = classify_prompt("Enter PIN for ED25519-SK key /k: ", PromptKind::Secret, None);
        assert_eq!(k, SecretPromptKind::Pin);
        // A server imitating OpenSSH across lines is treated as server text.
        let (k, _) = classify_prompt("(pw@h) Password: ", PromptKind::Secret, None);
        assert_eq!(k, SecretPromptKind::Server);
        let (k, _) = classify_prompt("Are you sure?", PromptKind::Confirm, None);
        assert_eq!(k, SecretPromptKind::Confirm);
    }
}
