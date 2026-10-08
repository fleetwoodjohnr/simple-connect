//! Local network scanner. Runs only on the user's request, on a network chosen
//! from `list_networks` (the backend re-checks that it is a local one).

use std::sync::atomic::Ordering;

use simple_connect_core::discovery::{self, LocalNetwork, ScanEvent};
use tauri::State;
use tauri::ipc::Channel;

use super::{CmdError, CmdResult};
use crate::state::AppState;

#[tauri::command]
pub fn list_networks() -> Vec<LocalNetwork> {
    discovery::local_networks()
}

#[tauri::command]
pub async fn scan_network(state: State<'_, AppState>, network_id: String, port: u16, on_event: Channel<ScanEvent>) -> CmdResult<u32> {
    if port == 0 || network_id.len() > 128 {
        return Err(CmdError::invalid("Choose a network and a port from 1 to 65535."));
    }
    if state.scanning.swap(true, Ordering::SeqCst) {
        return Err(CmdError::invalid("A scan is already running."));
    }
    state.scan_cancel.store(false, Ordering::SeqCst);
    let result = discovery::scan(&network_id, port, &state.scan_cancel, |e| drop(on_event.send(e))).await;
    state.scanning.store(false, Ordering::SeqCst);
    result.map_err(|e| CmdError::invalid(e.to_string()))
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) {
    state.scan_cancel.store(true, Ordering::SeqCst);
}
