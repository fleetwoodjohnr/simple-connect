use simple_connect_core::app::{ConnectRequest, sysinfo};
use simple_connect_core::profiles::{self, AuthMethod};
use simple_connect_core::quick_connect;
use simple_connect_core::settings::Settings;
use simple_connect_core::ssh::mux::Destination;
use simple_connect_core::validate::Host;
use tauri::State;

use super::{CmdError, CmdResult, check_id, manager};
use crate::state::{AppState, db_lock};

#[tauri::command]
pub async fn connect_profile(state: State<'_, AppState>, id: String) -> CmdResult<String> {
    let p = profiles::get(&*db_lock(&state.db)?, check_id(&id)?)?;
    let f = p.fields;
    let req = ConnectRequest {
        dest: Destination { host: f.host, user: f.username, port: f.port, jump: f.jump, identity_file: f.identity_file, auth: f.auth },
        label: f.name,
        profile_id: Some(p.id),
        legacy_crypto: p.legacy_crypto,
        keepalive_secs: f.keepalive_secs,
        start_dir: f.start_dir,
        reuse_password: f.reuse_password,
    };
    Ok(manager(&state)?.connect(req))
}

#[tauri::command]
pub async fn connect_quick(state: State<'_, AppState>, input: String) -> CmdResult<String> {
    if input.len() > 1024 {
        return Err(CmdError::invalid("Input is too long."));
    }
    let q = quick_connect::parse(&input)?;
    let dest = Destination {
        auth: if q.identity_file.is_some() { AuthMethod::Key } else { AuthMethod::Auto },
        host: q.host,
        user: q.user,
        port: q.port,
        jump: q.jump,
        identity_file: q.identity_file,
    };
    let req = ConnectRequest {
        label: dest.label(),
        dest,
        profile_id: None,
        legacy_crypto: false,
        keepalive_secs: None,
        start_dir: None,
        reuse_password: None,
    };
    Ok(manager(&state)?.connect(req))
}

/// Connects to a ~/.ssh/config alias; OpenSSH resolves its settings.
#[tauri::command]
pub async fn connect_alias(state: State<'_, AppState>, alias: String) -> CmdResult<String> {
    if !Settings::load(&*db_lock(&state.db)?).include_user_ssh_config {
        return Err(CmdError::invalid("Reading ~/.ssh/config is turned off in Settings."));
    }
    let host = Host::parse(&alias)?;
    let dest = Destination { host, user: None, port: None, jump: Vec::new(), identity_file: None, auth: AuthMethod::Auto };
    let req = ConnectRequest {
        label: alias,
        dest,
        profile_id: None,
        legacy_crypto: false,
        keepalive_secs: None,
        start_dir: None,
        reuse_password: None,
    };
    Ok(manager(&state)?.connect(req))
}

#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>, session: String) -> CmdResult<()> {
    Ok(manager(&state)?.disconnect(check_id(&session)?).await?)
}

#[tauri::command]
pub async fn reconnect(state: State<'_, AppState>, session: String) -> CmdResult<()> {
    Ok(manager(&state)?.reconnect(check_id(&session)?).await?)
}

#[tauri::command]
pub async fn answer_host_key(state: State<'_, AppState>, id: u64, trust: bool, typed_host: Option<String>) -> CmdResult<()> {
    Ok(manager(&state)?.answer_host_key(id, trust, typed_host).await?)
}

#[tauri::command]
pub fn answer_secret(state: State<'_, AppState>, id: u64, value: Option<String>, save: bool) -> CmdResult<()> {
    if value.as_ref().is_some_and(|v| v.len() > 4096) {
        return Err(CmdError::invalid("That answer is too long."));
    }
    Ok(manager(&state)?.answer_secret(id, value, save)?)
}

#[tauri::command]
pub async fn system_info(state: State<'_, AppState>, session: String) -> CmdResult<sysinfo::SysInfo> {
    let m = manager(&state)?;
    Ok(sysinfo::gather(&m, check_id(&session)?).await?)
}
