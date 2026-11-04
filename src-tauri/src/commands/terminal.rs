use tauri::State;
use tauri::ipc::{Channel, Response};

use super::{CmdError, CmdResult, check_id, manager};
use crate::state::AppState;

/// Opens a shell, or runs a remote desktop setup recipe (by id from the fixed
/// list, never command text). Output is streamed as raw bytes over `on_output`.
#[tauri::command]
pub fn open_terminal(
    state: State<'_, AppState>,
    session: String,
    cols: u16,
    rows: u16,
    recipe: Option<String>,
    on_output: Channel<Response>,
) -> CmdResult<String> {
    let sink = move |bytes: Vec<u8>| {
        let _ = on_output.send(Response::new(bytes));
    };
    let recipe = recipe.as_deref().map(check_id).transpose()?;
    Ok(manager(&state)?.open_terminal(check_id(&session)?, cols, rows, recipe, sink)?)
}

#[tauri::command]
pub fn terminal_write(state: State<'_, AppState>, session: String, terminal: String, data: Vec<u8>) -> CmdResult<()> {
    if data.len() > 4 * 1024 * 1024 {
        return Err(CmdError::invalid("That paste is too large."));
    }
    Ok(manager(&state)?.terminal_write(check_id(&session)?, check_id(&terminal)?, &data)?)
}

/// Answers a waiting sudo/su prompt with the login password. The password stays
/// in the backend; this only works while the backend itself sees the prompt.
#[tauri::command]
pub fn terminal_send_password(state: State<'_, AppState>, session: String, terminal: String) -> CmdResult<()> {
    Ok(manager(&state)?.terminal_send_password(check_id(&session)?, check_id(&terminal)?)?)
}

#[tauri::command]
pub fn terminal_resize(state: State<'_, AppState>, session: String, terminal: String, cols: u16, rows: u16) -> CmdResult<()> {
    manager(&state)?.terminal(check_id(&session)?, check_id(&terminal)?)?.resize(cols, rows)?;
    Ok(())
}

/// The webview rendered `bytes` of output (flow control).
#[tauri::command]
pub fn terminal_ack(state: State<'_, AppState>, session: String, terminal: String, bytes: usize) -> CmdResult<()> {
    if let Ok(t) = manager(&state)?.terminal(check_id(&session)?, check_id(&terminal)?) {
        t.ack(bytes);
    }
    Ok(())
}

#[tauri::command]
pub fn close_terminal(state: State<'_, AppState>, session: String, terminal: String) -> CmdResult<()> {
    manager(&state)?.close_terminal(check_id(&session)?, check_id(&terminal)?);
    Ok(())
}
