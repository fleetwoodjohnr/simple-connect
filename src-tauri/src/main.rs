// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use std::sync::{Arc, Mutex};

use simple_connect_core::settings::Settings;
use simple_connect_core::{logging, paths::AppPaths, ssh::helper, storage};
use tauri::Manager as _;

fn fatal(what: &str, e: impl std::fmt::Display) -> ! {
    eprintln!("simple-connect: {what}: {e}");
    tracing::error!("{what}: {e}");
    std::process::exit(1);
}

fn main() {
    // When ssh runs us as SSH_ASKPASS or KnownHostsCommand, answer and exit
    // before anything else starts.
    if let Some(code) = helper::run_if_helper() {
        std::process::exit(code);
    }

    let paths =
        AppPaths::from_env().and_then(|p| p.ensure().map(|()| p)).unwrap_or_else(|e| fatal("cannot prepare application directories", e));
    let _log_guard = logging::init(&paths.logs()).inspect_err(|e| eprintln!("simple-connect: logging disabled: {e}"));
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "starting");

    let conn = storage::open(&paths.data.join("app.db")).unwrap_or_else(|e| fatal("cannot open database", e));
    let settings = Settings::load(&conn);
    let db = Arc::new(Mutex::new(conn));

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            state::init(app, paths.clone(), db.clone(), settings.clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::prepare_update_install,
            commands::parse_quick_connect,
            commands::get_settings,
            commands::save_settings,
            commands::profiles::list_profiles,
            commands::profiles::create_profile,
            commands::profiles::update_profile,
            commands::profiles::delete_profile,
            commands::profiles::forget_saved_password,
            commands::profiles::set_favorite,
            commands::profiles::set_legacy_crypto,
            commands::profiles::move_profile,
            commands::profiles::list_groups,
            commands::profiles::create_group,
            commands::profiles::rename_group,
            commands::profiles::delete_group,
            commands::profiles::list_ssh_config_hosts,
            commands::sessions::connect_profile,
            commands::sessions::connect_quick,
            commands::sessions::connect_alias,
            commands::sessions::disconnect,
            commands::sessions::reconnect,
            commands::sessions::answer_host_key,
            commands::sessions::answer_secret,
            commands::sessions::system_info,
            commands::terminal::open_terminal,
            commands::terminal::terminal_write,
            commands::terminal::terminal_send_password,
            commands::terminal::terminal_resize,
            commands::terminal::terminal_ack,
            commands::terminal::close_terminal,
            commands::files::remote_home,
            commands::files::list_remote,
            commands::files::remote_mkdir,
            commands::files::remote_rename,
            commands::files::remote_delete,
            commands::files::remote_copy,
            commands::files::remote_chmod,
            commands::files::read_remote_text,
            commands::files::write_remote_text,
            commands::files::local_home,
            commands::files::list_local,
            commands::files::local_mkdir,
            commands::files::local_rename,
            commands::files::local_trash,
            commands::files::enqueue_upload,
            commands::files::enqueue_download,
            commands::files::list_transfers,
            commands::files::transfer_action,
            commands::files::resolve_conflict,
            commands::files::clear_transfers,
            commands::tunnels::add_tunnel,
            commands::tunnels::remove_tunnel,
            commands::tunnels::list_tunnels,
            commands::keys::list_keys,
            commands::keys::generate_key,
            commands::keys::change_key_passphrase,
            commands::keys::import_key,
            commands::keys::export_public_key,
            commands::security::lock_app,
            commands::security::unlock_app,
            commands::security::set_lock_password,
            commands::security::enable_vault,
            commands::security::disable_vault,
            commands::security::change_vault_password,
            commands::security::list_known_hosts,
            commands::security::forget_known_host,
            commands::security::copy_text,
            commands::security::paste_text,
            commands::security::log_folder,
            commands::security::clear_logs,
            commands::backup::export_profiles,
            commands::backup::import_profiles,
            commands::discovery::list_networks,
            commands::discovery::scan_network,
            commands::discovery::cancel_scan,
            commands::desktop::desktop_probe,
            commands::desktop::desktop_open,
            commands::desktop::desktop_write,
            commands::desktop::desktop_ack,
            commands::desktop::desktop_input,
            commands::desktop::desktop_resize,
            commands::desktop::desktop_clipboard,
            commands::desktop::desktop_close,
            commands::desktop::desktop_end_virtual,
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| fatal("cannot start the user interface", e));

    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event
            && let Some(m) = handle.state::<state::AppState>().manager.clone()
        {
            // Close masters cleanly so no orphaned ssh processes or sockets remain.
            tauri::async_runtime::block_on(m.shutdown());
        }
    });
}
