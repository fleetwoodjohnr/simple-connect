//! App lock, credential storage, known hosts, clipboard and logs.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use secrecy::SecretString;
use simple_connect_core::security::{CredentialStore, KeyringStore, lock, passphrase_ref};
use simple_connect_core::settings::{CredentialStorage, Settings};
use simple_connect_core::ssh::known_hosts::{self, TrustedHost};
use simple_connect_core::storage::rusqlite::Connection;
use simple_connect_core::storage::settings as kv;
use tauri::{AppHandle, Emitter, Manager as _, State};
use tauri_plugin_clipboard_manager::ClipboardExt;

use super::{CmdError, CmdResult, manager};
use crate::state::{AppState, apply_storage, db_lock};

const VERIFIER_KEY: &str = "lock.verifier";

pub fn lock_verifier(conn: &Connection) -> Option<String> {
    kv::get::<String>(conn, VERIFIER_KEY).ok().flatten()
}

fn lock_configured(state: &AppState) -> bool {
    state.vault.exists() || db_lock(&state.db).is_ok_and(|c| lock_verifier(&c).is_some())
}

/// Locks immediately: saved secrets become unreachable, the vault key is
/// dropped, and the UI covers its content. No-op if no lock password is set.
pub fn lock_now(app: &AppHandle) {
    let state = app.state::<AppState>();
    if !lock_configured(&state) {
        return;
    }
    if let Some(m) = &state.manager {
        m.set_locked(true);
    }
    state.vault.lock();
    let _ = app.emit("app-locked", ());
}

#[tauri::command]
pub fn lock_app(app: AppHandle) {
    lock_now(&app);
}

#[tauri::command]
pub async fn unlock_app(app: AppHandle, state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let pw = SecretString::from(password);
    let storage = Settings::load(&*db_lock(&state.db)?).credential_storage;
    let ok = if storage == CredentialStorage::Vault {
        let vault = state.vault.clone();
        let pw = pw.clone();
        tauri::async_runtime::spawn_blocking(move || vault.unlock(&pw)).await.map_err(|e| CmdError::internal(e.to_string()))?.is_ok()
    } else {
        let verifier = lock_verifier(&*db_lock(&state.db)?);
        match verifier {
            Some(v) => tauri::async_runtime::spawn_blocking(move || lock::verify_password(&pw, &v)).await.unwrap_or(false),
            None => true,
        }
    };
    if !ok {
        // Slows down guessing through the UI.
        tokio::time::sleep(Duration::from_millis(800)).await;
        return Err(CmdError::new("wrong_password", "That password is incorrect."));
    }
    if let Some(m) = &state.manager {
        m.set_locked(false);
    }
    let _ = app.emit("app-unlocked", ());
    Ok(())
}

/// Sets, changes or removes the app-lock password used with the system keyring.
#[tauri::command]
pub async fn set_lock_password(state: State<'_, AppState>, current: Option<String>, new: Option<String>) -> CmdResult<()> {
    let existing = lock_verifier(&*db_lock(&state.db)?);
    if let Some(v) = existing {
        let cur = SecretString::from(current.unwrap_or_default());
        if !tauri::async_runtime::spawn_blocking(move || lock::verify_password(&cur, &v)).await.unwrap_or(false) {
            return Err(CmdError::new("wrong_password", "The current password is incorrect."));
        }
    }
    match new.filter(|n| !n.is_empty()) {
        Some(n) => {
            if n.chars().count() < 8 {
                return Err(CmdError::invalid("Use at least 8 characters."));
            }
            let phc = tauri::async_runtime::spawn_blocking(move || lock::hash_password(&SecretString::from(n)))
                .await
                .map_err(|e| CmdError::internal(e.to_string()))?
                .map_err(|e| CmdError::internal(e.to_string()))?;
            kv::set(&*db_lock(&state.db)?, VERIFIER_KEY, &phc)?;
        }
        None => {
            db_lock(&state.db)?.execute("DELETE FROM settings WHERE key = ?1", [VERIFIER_KEY])?;
        }
    }
    Ok(())
}

/// Ids of every secret the app may hold: profile passwords and key passphrases.
fn secret_ids(state: &AppState) -> CmdResult<Vec<String>> {
    let conn = db_lock(&state.db)?;
    let mut ids: Vec<String> = conn
        .prepare("SELECT secret_ref FROM profiles WHERE secret_ref IS NOT NULL")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if let Some(home) = std::env::var_os("HOME") {
        let dir = std::path::Path::new(&home).join(".ssh");
        ids.extend(simple_connect_core::ssh::keys::list(&dir).iter().map(|k| passphrase_ref(&k.path)));
    }
    Ok(ids)
}

fn migrate(ids: &[String], from: &dyn CredentialStore, to: &dyn CredentialStore) -> CmdResult<()> {
    for id in ids {
        if let Some(secret) = from.get(id)? {
            to.set(id, &secret)?;
            from.delete(id)?;
        }
    }
    Ok(())
}

/// Switches to the encrypted vault, moving saved secrets out of the keyring.
#[tauri::command]
pub async fn enable_vault(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    if password.chars().count() < 8 {
        return Err(CmdError::invalid("Use at least 8 characters."));
    }
    let m = manager(&state)?;
    let ids = secret_ids(&state)?;
    let vault = state.vault.clone();
    let keyring_ok = state.keyring_available;
    tauri::async_runtime::spawn_blocking(move || -> CmdResult<()> {
        vault.create(&SecretString::from(password))?;
        if keyring_ok {
            migrate(&ids, &KeyringStore, vault.as_ref())?;
        }
        Ok(())
    })
    .await
    .map_err(|e| CmdError::internal(e.to_string()))??;
    let conn = db_lock(&state.db)?;
    let s = Settings { credential_storage: CredentialStorage::Vault, ..Settings::load(&conn) };
    s.save(&conn)?;
    m.set_settings(s);
    apply_storage(&m, &state.vault, CredentialStorage::Vault, None);
    Ok(())
}

/// Returns to the system keyring: secrets move back and the vault file is deleted.
#[tauri::command]
pub async fn disable_vault(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    if !state.keyring_available {
        return Err(CmdError::invalid("The system keyring isn't available, so the vault can't be turned off."));
    }
    let m = manager(&state)?;
    let ids = secret_ids(&state)?;
    let vault = state.vault.clone();
    let path = state.paths.data.join("vault.bin");
    tauri::async_runtime::spawn_blocking(move || -> CmdResult<()> {
        vault.unlock(&SecretString::from(password))?;
        migrate(&ids, vault.as_ref(), &KeyringStore)?;
        vault.lock();
        std::fs::remove_file(path)?;
        Ok(())
    })
    .await
    .map_err(|e| CmdError::internal(e.to_string()))??;
    let conn = db_lock(&state.db)?;
    let s = Settings { credential_storage: CredentialStorage::Keyring, ..Settings::load(&conn) };
    s.save(&conn)?;
    m.set_settings(s);
    apply_storage(&m, &state.vault, CredentialStorage::Keyring, Some(Arc::new(KeyringStore)));
    m.set_locked(false);
    Ok(())
}

#[tauri::command]
pub async fn change_vault_password(state: State<'_, AppState>, current: String, new: String) -> CmdResult<()> {
    if new.chars().count() < 8 {
        return Err(CmdError::invalid("Use at least 8 characters."));
    }
    let vault = state.vault.clone();
    tauri::async_runtime::spawn_blocking(move || vault.change_password(&SecretString::from(current), &SecretString::from(new)))
        .await
        .map_err(|e| CmdError::internal(e.to_string()))??;
    Ok(())
}

#[tauri::command]
pub fn list_known_hosts(state: State<'_, AppState>) -> Vec<TrustedHost> {
    known_hosts::list(&state.paths.data.join("known_hosts"))
}

#[tauri::command]
pub fn forget_known_host(state: State<'_, AppState>, host: String) -> CmdResult<()> {
    if host.is_empty() || host.len() > 300 || host.chars().any(|c| c.is_whitespace() || c.is_control()) || host.starts_with('-') {
        return Err(CmdError::invalid("Invalid host."));
    }
    let m = manager(&state)?;
    known_hosts::forget(&m.engine.ossh.keygen, &state.paths.data.join("known_hosts"), &host)?;
    Ok(())
}

/// Copies text the user asked to copy. If enabled, the clipboard is cleared
/// after the configured delay, but only if it still holds this text.
#[tauri::command]
pub fn copy_text(app: AppHandle, state: State<'_, AppState>, text: String) -> CmdResult<()> {
    if text.len() > 8 * 1024 * 1024 {
        return Err(CmdError::invalid("That's too much text to copy."));
    }
    app.clipboard().write_text(text.clone()).map_err(|e| CmdError::internal(e.to_string()))?;
    let generation = state.clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;
    let secs = Settings::load(&*db_lock(&state.db)?).clipboard_clear_secs;
    if secs > 0 {
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(u64::from(secs))).await;
            let state = app.state::<AppState>();
            let unchanged = state.clipboard_generation.load(Ordering::SeqCst) == generation;
            if unchanged && app.clipboard().read_text().is_ok_and(|t| t == text) {
                let _ = app.clipboard().write_text(String::new());
            }
        });
    }
    Ok(())
}

#[tauri::command]
pub fn paste_text(app: AppHandle) -> CmdResult<String> {
    app.clipboard().read_text().map_err(|_| CmdError::new("clipboard", "The clipboard doesn't contain text."))
}

#[tauri::command]
pub fn log_folder(state: State<'_, AppState>) -> String {
    state.paths.logs().to_string_lossy().into_owned()
}

#[tauri::command]
pub fn clear_logs(state: State<'_, AppState>) -> CmdResult<()> {
    for entry in std::fs::read_dir(state.paths.logs())?.flatten() {
        if entry.path().extension().is_some_and(|e| e == "log") || entry.file_name().to_string_lossy().starts_with("simple-connect") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}
