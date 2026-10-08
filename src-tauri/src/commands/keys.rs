//! SSH key manager. Passphrases arrive from the user's dialog and go to
//! `ssh-keygen` through askpass; private key material is never returned.

use secrecy::SecretString;
use simple_connect_core::ssh::keys::{self, KeyInfo, KeyKind};
use simple_connect_core::validate;
use tauri::State;

use super::{CmdError, CmdResult, manager};
use crate::state::AppState;

fn ssh_dir() -> CmdResult<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".ssh")).ok_or_else(|| CmdError::internal("no home directory"))
}

#[tauri::command]
pub async fn list_keys() -> CmdResult<Vec<KeyInfo>> {
    let dir = ssh_dir()?;
    tauri::async_runtime::spawn_blocking(move || keys::list(&dir)).await.map_err(|e| CmdError::internal(e.to_string()))
}

#[tauri::command]
pub async fn generate_key(
    state: State<'_, AppState>,
    kind: KeyKind,
    name: String,
    comment: String,
    passphrase: String,
) -> CmdResult<KeyInfo> {
    Ok(manager(&state)?.engine.generate_key(kind, &name, &comment, SecretString::from(passphrase)).await?)
}

#[tauri::command]
pub async fn change_key_passphrase(state: State<'_, AppState>, path: String, old: String, new: String) -> CmdResult<()> {
    let path = validate::local_path(&path)?;
    Ok(manager(&state)?.engine.change_passphrase(&path, SecretString::from(old), SecretString::from(new)).await?)
}

#[tauri::command]
pub async fn import_key(state: State<'_, AppState>, source: String, name: String, passphrase: String) -> CmdResult<KeyInfo> {
    let source = validate::local_path(&source)?;
    Ok(manager(&state)?.engine.import_key(&source, &name, SecretString::from(passphrase)).await?)
}

/// Writes a key's public half to a file the user chose.
#[tauri::command]
pub async fn export_public_key(state: State<'_, AppState>, path: String, destination: String) -> CmdResult<()> {
    let key = keys::read(&validate::local_path(&path)?).ok_or_else(|| CmdError::invalid("That key couldn't be read."))?;
    std::fs::write(super::files::local_path(&state, &destination)?, format!("{}\n", key.public_key))?;
    Ok(())
}
