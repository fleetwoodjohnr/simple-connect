//! Remote desktop. The stream reaches the webview over a `Channel`; sign-in
//! happens in the backend, so no password crosses IPC.

use simple_connect_core::desktop::OpenRequest;
use simple_connect_core::desktop::probe::Probe;
use simple_connect_core::desktop::rdp::Input;
use tauri::State;
use tauri::ipc::{Channel, Response};

use super::{CmdError, CmdResult, check_id, manager};
use crate::state::AppState;

/// Finds out how the session's computer can show its desktop.
#[tauri::command]
pub async fn desktop_probe(state: State<'_, AppState>, session: String) -> CmdResult<Probe> {
    Ok(manager(&state)?.desktop_probe(check_id(&session)?).await?)
}

/// Opens a remote desktop. Progress arrives as `desktop` UI events.
#[tauri::command]
pub async fn desktop_open(
    state: State<'_, AppState>,
    session: String,
    request: OpenRequest,
    on_data: Channel<Response>,
) -> CmdResult<String> {
    let sink = move |bytes: Vec<u8>| {
        let _ = on_data.send(Response::new(bytes));
    };
    Ok(manager(&state)?.desktop_open(check_id(&session)?, request, sink)?)
}

/// Bytes from the VNC viewer (input events, update requests).
#[tauri::command]
pub fn desktop_write(state: State<'_, AppState>, session: String, desktop: String, data: Vec<u8>) -> CmdResult<()> {
    if data.len() > 1024 * 1024 {
        return Err(CmdError::invalid("That's too much data at once."));
    }
    Ok(manager(&state)?.desktop_write(check_id(&session)?, check_id(&desktop)?, data)?)
}

/// RDP input events (keys as scan codes, positions in remote pixels).
#[tauri::command]
pub fn desktop_input(state: State<'_, AppState>, session: String, desktop: String, events: Vec<Input>) -> CmdResult<()> {
    if events.len() > 256 {
        return Err(CmdError::invalid("Too many input events at once."));
    }
    Ok(manager(&state)?.desktop_input(check_id(&session)?, check_id(&desktop)?, events)?)
}

/// Asks an RDP server to match the view's size.
#[tauri::command]
pub fn desktop_resize(state: State<'_, AppState>, session: String, desktop: String, width: u32, height: u32) -> CmdResult<()> {
    Ok(manager(&state)?.desktop_resize(check_id(&session)?, check_id(&desktop)?, width, height)?)
}

/// Offers text as the RDP server's clipboard (only on the user's request).
#[tauri::command]
pub fn desktop_clipboard(state: State<'_, AppState>, session: String, desktop: String, text: String) -> CmdResult<()> {
    if text.len() > 1024 * 1024 {
        return Err(CmdError::invalid("That's too much text for the clipboard."));
    }
    Ok(manager(&state)?.desktop_clipboard(check_id(&session)?, check_id(&desktop)?, text)?)
}

/// The webview handled `bytes` of output (flow control).
#[tauri::command]
pub fn desktop_ack(state: State<'_, AppState>, session: String, desktop: String, bytes: usize) -> CmdResult<()> {
    manager(&state)?.desktop_ack(check_id(&session)?, check_id(&desktop)?, bytes);
    Ok(())
}

#[tauri::command]
pub fn desktop_close(state: State<'_, AppState>, session: String, desktop: String) -> CmdResult<()> {
    manager(&state)?.desktop_close(check_id(&session)?, check_id(&desktop)?);
    Ok(())
}

/// Signs out of the session's virtual desktop.
#[tauri::command]
pub async fn desktop_end_virtual(state: State<'_, AppState>, session: String) -> CmdResult<()> {
    Ok(manager(&state)?.desktop_end_virtual(check_id(&session)?).await?)
}
