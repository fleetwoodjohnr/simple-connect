use simple_connect_core::app::tunnels::{Tunnel, TunnelSpec};
use tauri::State;

use super::{CmdResult, check_id, manager};
use crate::state::AppState;

#[tauri::command]
pub async fn add_tunnel(state: State<'_, AppState>, session: String, spec: TunnelSpec) -> CmdResult<Tunnel> {
    let m = manager(&state)?;
    Ok(m.tunnels.add(&m, check_id(&session)?, spec).await?)
}

#[tauri::command]
pub async fn remove_tunnel(state: State<'_, AppState>, session: String, id: String) -> CmdResult<()> {
    let m = manager(&state)?;
    Ok(m.tunnels.remove(&m, check_id(&session)?, check_id(&id)?).await?)
}

#[tauri::command]
pub fn list_tunnels(state: State<'_, AppState>, session: String) -> CmdResult<Vec<Tunnel>> {
    Ok(manager(&state)?.tunnels.list(check_id(&session)?))
}
