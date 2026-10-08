//! Local and remote file operations, the editor, and the transfer queue.

use std::path::PathBuf;
use std::sync::Arc;

use simple_connect_core::app::Manager;
use simple_connect_core::app::transfers::{ConflictChoice, JobView};
use simple_connect_core::sftp::{Entry, RemoteFs, local};
use simple_connect_core::validate;
use tauri::State;

use super::{CmdError, CmdResult, check_id, manager};
use crate::state::AppState;

/// A frontend-supplied local path: absolute, normalised, never inside the
/// application's private data (database, vault, logs, sockets).
pub fn local_path(state: &AppState, p: &str) -> CmdResult<PathBuf> {
    let path = validate::local_path(p)?;
    if simple_connect_core::sftp::is_app_private(&path, &state.paths) {
        return Err(CmdError::invalid("That folder holds Simple Connect's private data and can't be used here."));
    }
    Ok(path)
}

fn remote(p: &str) -> CmdResult<&str> {
    Ok(validate::remote_path(p)?)
}

async fn fs(m: &Arc<Manager>, session: &str) -> CmdResult<Arc<RemoteFs>> {
    Ok(m.sftp(check_id(session)?).await?)
}

/// A failed SFTP call on a dead connection drops the channel so it is reopened later.
async fn after_error(m: &Arc<Manager>, session: &str) {
    if m.session(session).ok().and_then(|s| s.master()).is_none() {
        m.reset_sftp(session).await;
    }
}

macro_rules! remote_op {
    ($m:expr, $session:expr, $op:expr) => {{
        let r = $op.await;
        if r.is_err() {
            after_error(&$m, &$session).await;
        }
        r.map_err(CmdError::from)
    }};
}

#[tauri::command]
pub async fn remote_home(state: State<'_, AppState>, session: String) -> CmdResult<String> {
    let m = manager(&state)?;
    Ok(fs(&m, &session).await?.home.clone())
}

#[tauri::command]
pub async fn list_remote(state: State<'_, AppState>, session: String, path: String) -> CmdResult<Vec<Entry>> {
    let m = manager(&state)?;
    let f = fs(&m, &session).await?;
    remote_op!(m, session, f.list(remote(&path)?))
}

#[tauri::command]
pub async fn remote_mkdir(state: State<'_, AppState>, session: String, path: String) -> CmdResult<()> {
    let m = manager(&state)?;
    let f = fs(&m, &session).await?;
    remote_op!(m, session, f.mkdir(remote(&path)?))
}

#[tauri::command]
pub async fn remote_rename(state: State<'_, AppState>, session: String, from: String, to: String) -> CmdResult<()> {
    let m = manager(&state)?;
    let f = fs(&m, &session).await?;
    if f.exists(remote(&to)?).await {
        return Err(CmdError::invalid("A file with that name already exists."));
    }
    remote_op!(m, session, f.rename(remote(&from)?, &to))
}

#[tauri::command]
pub async fn remote_delete(state: State<'_, AppState>, session: String, path: String) -> CmdResult<()> {
    let m = manager(&state)?;
    let f = fs(&m, &session).await?;
    let p = remote(&path)?;
    if p == "/" || p == f.home {
        return Err(CmdError::invalid("Refusing to delete the root or home folder."));
    }
    remote_op!(m, session, f.remove(p))
}

#[tauri::command]
pub async fn remote_copy(state: State<'_, AppState>, session: String, from: String, to: String) -> CmdResult<()> {
    let m = manager(&state)?;
    let f = fs(&m, &session).await?;
    if f.exists(remote(&to)?).await {
        return Err(CmdError::invalid("A file with that name already exists."));
    }
    Ok(m.remote_copy(check_id(&session)?, remote(&from)?, &to).await?)
}

#[tauri::command]
pub async fn remote_chmod(state: State<'_, AppState>, session: String, path: String, mode: u32) -> CmdResult<()> {
    if mode > 0o7777 {
        return Err(CmdError::invalid("Invalid permissions."));
    }
    let m = manager(&state)?;
    let f = fs(&m, &session).await?;
    remote_op!(m, session, f.chmod(remote(&path)?, mode))
}

/// Opens a remote text file in the editor. The contents stay in memory: no
/// local temporary copy is written.
#[tauri::command]
pub async fn read_remote_text(state: State<'_, AppState>, session: String, path: String) -> CmdResult<String> {
    let m = manager(&state)?;
    let f = fs(&m, &session).await?;
    let limit = u64::from(m.settings().editor_max_mb) * 1_000_000;
    let bytes = remote_op!(m, session, f.read_limited(remote(&path)?, limit))?;
    String::from_utf8(bytes).map_err(|_| CmdError::invalid("This file isn't text (or isn't UTF-8), so it can't be edited here."))
}

#[tauri::command]
pub async fn write_remote_text(state: State<'_, AppState>, session: String, path: String, content: String) -> CmdResult<()> {
    let m = manager(&state)?;
    if content.len() as u64 > u64::from(m.settings().editor_max_mb) * 1_000_000 {
        return Err(CmdError::invalid("The file is larger than the editor limit."));
    }
    let f = fs(&m, &session).await?;
    remote_op!(m, session, f.write_atomic(remote(&path)?, content.as_bytes()))
}

#[tauri::command]
pub fn local_home() -> CmdResult<String> {
    dirs_home().ok_or_else(|| CmdError::internal("no home directory"))
}

fn dirs_home() -> Option<String> {
    std::env::var_os("HOME").map(|h| h.to_string_lossy().into_owned())
}

#[tauri::command]
pub async fn list_local(state: State<'_, AppState>, path: String) -> CmdResult<Vec<Entry>> {
    let p = local_path(&state, &path)?;
    Ok(tokio_blocking(move || local::list(&p)).await?)
}

#[tauri::command]
pub async fn local_mkdir(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let p = local_path(&state, &path)?;
    Ok(tokio_blocking(move || local::mkdir(&p)).await?)
}

#[tauri::command]
pub async fn local_rename(state: State<'_, AppState>, from: String, to: String) -> CmdResult<()> {
    let (a, b) = (local_path(&state, &from)?, local_path(&state, &to)?);
    Ok(tokio_blocking(move || local::rename(&a, &b)).await?)
}

#[tauri::command]
pub async fn local_trash(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let p = local_path(&state, &path)?;
    Ok(tokio_blocking(move || local::trash(&p)).await?)
}

async fn tokio_blocking<T: Send + 'static>(f: impl FnOnce() -> std::io::Result<T> + Send + 'static) -> std::io::Result<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(std::io::Error::other)?
}

#[tauri::command]
pub async fn enqueue_upload(state: State<'_, AppState>, session: String, local_paths: Vec<String>, remote_dir: String) -> CmdResult<()> {
    let paths = local_paths.iter().map(|p| local_path(&state, p)).collect::<CmdResult<Vec<_>>>()?;
    let m = manager(&state)?;
    Ok(m.transfers.enqueue_upload(&m, check_id(&session)?, paths, remote(&remote_dir)?.to_owned()).await?)
}

#[tauri::command]
pub async fn enqueue_download(state: State<'_, AppState>, session: String, remote_paths: Vec<String>, local_dir: String) -> CmdResult<()> {
    let dir = local_path(&state, &local_dir)?;
    let paths = remote_paths.iter().map(|p| remote(p).map(str::to_owned)).collect::<CmdResult<Vec<_>>>()?;
    let m = manager(&state)?;
    Ok(m.transfers.enqueue_download(&m, check_id(&session)?, paths, dir).await?)
}

#[tauri::command]
pub fn list_transfers(state: State<'_, AppState>) -> CmdResult<Vec<JobView>> {
    Ok(manager(&state)?.transfers.snapshot())
}

#[tauri::command]
pub fn transfer_action(state: State<'_, AppState>, id: u64, action: String) -> CmdResult<()> {
    let m = manager(&state)?;
    match action.as_str() {
        "pause" => m.transfers.pause(&m, id),
        "resume" | "retry" => m.transfers.resume(&m, id),
        "cancel" => m.transfers.cancel(&m, id),
        _ => return Err(CmdError::invalid("Unknown action.")),
    }
    Ok(())
}

#[tauri::command]
pub fn resolve_conflict(state: State<'_, AppState>, id: u64, choice: ConflictChoice, apply_to_all: bool) -> CmdResult<()> {
    let m = manager(&state)?;
    m.transfers.resolve(&m, id, choice, apply_to_all);
    Ok(())
}

#[tauri::command]
pub fn clear_transfers(state: State<'_, AppState>) -> CmdResult<()> {
    let m = manager(&state)?;
    m.transfers.clear_finished(&m);
    Ok(())
}
