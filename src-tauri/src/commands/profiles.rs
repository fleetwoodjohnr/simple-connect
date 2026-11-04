use simple_connect_core::profiles::{self, Group, Profile, ProfileDraft, ssh_config};
use tauri::State;

use super::{CmdResult, check_id};
use crate::state::{AppState, db_lock};

#[tauri::command]
pub async fn list_profiles(state: State<'_, AppState>) -> CmdResult<Vec<Profile>> {
    Ok(profiles::list(&*db_lock(&state.db)?)?)
}

#[tauri::command]
pub async fn create_profile(state: State<'_, AppState>, draft: ProfileDraft) -> CmdResult<Profile> {
    Ok(profiles::create(&mut *db_lock(&state.db)?, &draft)?)
}

#[tauri::command]
pub async fn update_profile(state: State<'_, AppState>, id: String, draft: ProfileDraft) -> CmdResult<Profile> {
    Ok(profiles::update(&mut *db_lock(&state.db)?, check_id(&id)?, &draft)?)
}

/// Deletes the profile and its saved passwords.
#[tauri::command]
pub async fn delete_profile(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let refs = profiles::delete(&*db_lock(&state.db)?, check_id(&id)?)?;
    for r in refs {
        if let Some(m) = &state.manager
            && let Err(e) = m.forget_secret(r).await
        {
            tracing::warn!("saved password not removed: {e}");
        }
    }
    Ok(())
}

/// Forgets the saved SSH password, or the remote desktop password with `desktop`.
#[tauri::command]
pub async fn forget_saved_password(state: State<'_, AppState>, id: String, desktop: Option<bool>) -> CmdResult<()> {
    let id = check_id(&id)?;
    let desktop = desktop.unwrap_or(false);
    let secret_ref =
        if desktop { profiles::desktop_secret_ref(&*db_lock(&state.db)?, id)? } else { profiles::secret_ref(&*db_lock(&state.db)?, id)? };
    if let Some(r) = secret_ref {
        let m = super::manager(&state)?;
        if desktop {
            for id in profiles::desktop_secret_ids(&r) {
                m.forget_secret(id).await?;
            }
        } else {
            m.forget_secret(r).await?;
        }
        let conn = db_lock(&state.db)?;
        if desktop { profiles::set_desktop_secret_ref(&conn, id, None)? } else { profiles::set_secret_ref(&conn, id, None)? }
    }
    Ok(())
}

#[tauri::command]
pub async fn set_favorite(state: State<'_, AppState>, id: String, favorite: bool) -> CmdResult<()> {
    Ok(profiles::set_favorite(&*db_lock(&state.db)?, check_id(&id)?, favorite)?)
}

#[tauri::command]
pub async fn set_legacy_crypto(state: State<'_, AppState>, id: String, allow: bool) -> CmdResult<()> {
    let id = check_id(&id)?;
    tracing::warn!(profile = %id, allow, "legacy cryptography setting changed");
    Ok(profiles::set_legacy_crypto(&*db_lock(&state.db)?, id, allow)?)
}

#[tauri::command]
pub async fn move_profile(state: State<'_, AppState>, id: String, group_id: Option<String>) -> CmdResult<()> {
    let group_id = group_id.as_deref().map(check_id).transpose()?;
    Ok(profiles::set_group(&*db_lock(&state.db)?, check_id(&id)?, group_id)?)
}

#[tauri::command]
pub async fn list_groups(state: State<'_, AppState>) -> CmdResult<Vec<Group>> {
    Ok(profiles::list_groups(&*db_lock(&state.db)?)?)
}

#[tauri::command]
pub async fn create_group(state: State<'_, AppState>, name: String) -> CmdResult<Group> {
    Ok(profiles::create_group(&*db_lock(&state.db)?, &name)?)
}

#[tauri::command]
pub async fn rename_group(state: State<'_, AppState>, id: String, name: String) -> CmdResult<()> {
    Ok(profiles::rename_group(&*db_lock(&state.db)?, check_id(&id)?, &name)?)
}

#[tauri::command]
pub async fn delete_group(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    Ok(profiles::delete_group(&*db_lock(&state.db)?, check_id(&id)?)?)
}

/// Aliases from ~/.ssh/config (read-only; empty when the user turned it off).
#[tauri::command]
pub async fn list_ssh_config_hosts(state: State<'_, AppState>) -> CmdResult<Vec<ssh_config::SshConfigHost>> {
    let enabled = simple_connect_core::settings::Settings::load(&*db_lock(&state.db)?).include_user_ssh_config;
    Ok(if enabled { ssh_config::read_user_config() } else { Vec::new() })
}
