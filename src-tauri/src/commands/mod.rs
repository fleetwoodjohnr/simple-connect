//! IPC adapters. The webview is untrusted: every argument is validated (by the
//! core types or here) before use, and errors cross the boundary as
//! `{ code, message, details, fields }` with a user-friendly `message`.

pub mod backup;
pub mod desktop;
pub mod discovery;
pub mod files;
pub mod keys;
pub mod profiles;
pub mod security;
pub mod sessions;
pub mod terminal;
pub mod tunnels;

use std::sync::Arc;

use serde::Serialize;
use simple_connect_core::app::{AppError, Manager};
use simple_connect_core::profiles::{FieldError, ProfileError};
use simple_connect_core::quick_connect::{self, QuickConnect, QuickConnectError};
use simple_connect_core::settings::Settings;
use tauri::State;

use crate::state::{AppState, db_lock};

#[derive(Debug, Serialize)]
pub struct CmdError {
    code: &'static str,
    message: String,
    details: Option<String>,
    fields: Option<Vec<FieldError>>,
}

impl CmdError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        CmdError { code, message: message.into(), details: None, fields: None }
    }
    pub fn internal(details: impl Into<String>) -> Self {
        CmdError { details: Some(details.into()), ..Self::new("internal", "Something went wrong.") }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_input", message)
    }
}

macro_rules! user_error {
    ($($t:ty => $code:literal),* $(,)?) => {$(
        impl From<$t> for CmdError {
            fn from(e: $t) -> Self {
                CmdError::new($code, e.to_string())
            }
        }
    )*};
}

user_error! {
    QuickConnectError => "invalid_input",
    simple_connect_core::validate::ValidationError => "invalid_input",
    simple_connect_core::sftp::SftpError => "files",
    simple_connect_core::ssh::keys::KeyError => "keys",
    simple_connect_core::security::SecretError => "secrets",
    simple_connect_core::profiles::export::TransferError => "import",
    std::io::Error => "io",
}

impl From<AppError> for CmdError {
    fn from(e: AppError) -> Self {
        let code = match e {
            AppError::NoSession => "no_session",
            AppError::NotConnected => "not_connected",
            AppError::PromptExpired => "prompt_expired",
            AppError::ConfirmationMismatch => "confirmation_mismatch",
            AppError::Secret(_) => "secrets",
            AppError::Sftp(_) => "files",
            AppError::Invalid(_) => "invalid_input",
            AppError::Io(_) => "io",
        };
        CmdError::new(code, e.to_string())
    }
}

impl From<ProfileError> for CmdError {
    fn from(e: ProfileError) -> Self {
        let message = e.to_string();
        match e {
            ProfileError::Invalid(fields) => CmdError { fields: Some(fields), ..CmdError::invalid(message) },
            ProfileError::NotFound => CmdError::new("not_found", message),
            ProfileError::Db(db) => {
                tracing::error!("database error: {db}");
                CmdError { details: Some(db.to_string()), ..CmdError::new("storage", message) }
            }
        }
    }
}

impl From<simple_connect_core::storage::rusqlite::Error> for CmdError {
    fn from(e: simple_connect_core::storage::rusqlite::Error) -> Self {
        tracing::error!("database error: {e}");
        CmdError { details: Some(e.to_string()), ..CmdError::new("storage", "Your settings couldn't be saved.") }
    }
}

pub type CmdResult<T> = Result<T, CmdError>;

/// Opaque ids are only used as map keys or bound SQL parameters; this bounds them.
pub fn check_id(id: &str) -> CmdResult<&str> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(CmdError::invalid("Invalid identifier."));
    }
    Ok(id)
}

pub fn manager(state: &AppState) -> CmdResult<Arc<Manager>> {
    state.manager.clone().ok_or_else(|| {
        CmdError::new("ssh_unavailable", state.startup_error.clone().unwrap_or_else(|| "The SSH engine isn't available.".into()))
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: &'static str,
    openssh: Option<String>,
    startup_error: Option<String>,
    keyring_available: bool,
    locked: bool,
    vault_exists: bool,
    lock_configured: bool,
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    let lock_configured = state.vault.exists() || db_lock(&state.db).is_ok_and(|c| security::lock_verifier(&c).is_some());
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        openssh: state.manager.as_ref().map(|m| m.engine.ossh.version_string.clone()),
        startup_error: state.startup_error.clone(),
        keyring_available: state.keyring_available,
        locked: state.manager.as_ref().is_some_and(|m| m.is_locked()),
        vault_exists: state.vault.exists(),
        lock_configured,
    }
}

#[tauri::command]
pub fn parse_quick_connect(input: String) -> CmdResult<QuickConnect> {
    if input.len() > 1024 {
        return Err(CmdError::invalid("Input is too long."));
    }
    Ok(quick_connect::parse(&input)?)
}

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> CmdResult<Settings> {
    Ok(Settings::load(&*db_lock(&state.db)?))
}

/// Saves settings. Storage mode changes go through `set_credential_storage`.
#[tauri::command]
pub fn save_settings(state: State<'_, AppState>, settings: Settings) -> CmdResult<Settings> {
    let conn = db_lock(&state.db)?;
    let current = Settings::load(&conn);
    let next = Settings { credential_storage: current.credential_storage, ..settings }.sanitized();
    next.save(&conn)?;
    if let Some(m) = &state.manager {
        m.set_settings(next.clone());
    }
    Ok(next)
}
