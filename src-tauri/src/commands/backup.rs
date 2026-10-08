use secrecy::SecretString;
use simple_connect_core::profiles::export::{self, ImportReport, MAX_IMPORT_BYTES};
use simple_connect_core::validate;
use tauri::State;

use super::{CmdError, CmdResult};
use crate::state::{AppState, db_lock};

/// Exports profiles. Passwords are included only with a backup password, and
/// then the whole file is encrypted.
#[tauri::command]
pub async fn export_profiles(state: State<'_, AppState>, destination: String, backup_password: Option<String>) -> CmdResult<()> {
    let dest = super::files::local_path(&state, &destination)?;
    let pw = backup_password.filter(|p| !p.is_empty()).map(SecretString::from);
    if pw.as_ref().is_some_and(|p| secrecy::ExposeSecret::expose_secret(p).chars().count() < 8) {
        return Err(CmdError::invalid("Use a backup password of at least 8 characters."));
    }
    let store = state.manager.as_ref().and_then(|m| m.store().ok());
    let data = export::export(&*db_lock(&state.db)?, pw.as_ref(), store.as_deref())?;
    simple_connect_core::paths::write_private(&dest, &data)?;
    Ok(())
}

#[tauri::command]
pub async fn import_profiles(state: State<'_, AppState>, source: String, password: Option<String>) -> CmdResult<ImportReport> {
    let src = validate::local_path(&source)?;
    if std::fs::metadata(&src)?.len() as usize > MAX_IMPORT_BYTES {
        return Err(CmdError::invalid("The file is too large to import."));
    }
    let data = std::fs::read(&src)?;
    let pw = password.filter(|p| !p.is_empty()).map(SecretString::from);
    let store = state.manager.as_ref().and_then(|m| m.store().ok());
    Ok(export::import(&mut *db_lock(&state.db)?, &data, pw.as_ref(), store.as_deref())?)
}
