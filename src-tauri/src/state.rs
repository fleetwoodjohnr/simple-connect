//! Process-wide state and the bridge that delivers core events to the webview.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use simple_connect_core::app::{Db, Manager, Ui, UiEvent};
use simple_connect_core::paths::AppPaths;
use simple_connect_core::security::vault::VaultStore;
use simple_connect_core::security::{CredentialStore, KeyringStore};
use simple_connect_core::settings::{CredentialStorage, Settings};
use simple_connect_core::ssh::engine::Engine;
use tauri::{AppHandle, Emitter, Manager as _};

pub struct TauriUi(pub AppHandle);

impl Ui for TauriUi {
    fn emit(&self, event: UiEvent) {
        if let Err(e) = self.0.emit("ui-event", &event) {
            tracing::warn!("could not deliver UI event: {e}");
        }
    }
}

pub struct AppState {
    pub paths: AppPaths,
    pub db: Db,
    /// `None` when OpenSSH is missing or too old; `startup_error` says why.
    pub manager: Option<Arc<Manager>>,
    pub startup_error: Option<String>,
    pub vault: Arc<VaultStore>,
    /// Whether the system keyring answered at startup.
    pub keyring_available: bool,
    /// Bumped on every copy, so a delayed clear never wipes newer content.
    pub clipboard_generation: AtomicU64,
    pub scanning: AtomicBool,
    pub scan_cancel: AtomicBool,
}

/// Activates the configured credential store. With the vault, the app starts
/// locked until the master password is entered.
pub fn apply_storage(manager: &Manager, vault: &Arc<VaultStore>, storage: CredentialStorage, keyring: Option<Arc<KeyringStore>>) {
    match storage {
        CredentialStorage::Keyring => manager.set_store(keyring.map(|k| k as Arc<dyn CredentialStore>)),
        CredentialStorage::Vault => {
            manager.set_store(Some(vault.clone() as Arc<dyn CredentialStore>));
            if !vault.is_unlocked() {
                manager.set_locked(true);
            }
        }
    }
}

pub fn init(app: &mut tauri::App, paths: AppPaths, db: Db, settings: Settings) {
    let vault = Arc::new(VaultStore::new(&paths.data.join("vault.bin")));
    let keyring = KeyringStore::connect().inspect_err(|e| tracing::warn!("{e}")).ok().map(Arc::new);
    let keyring_available = keyring.is_some();
    let ui: Arc<dyn Ui> = Arc::new(TauriUi(app.handle().clone()));

    let started = std::env::current_exe().map_err(|e| e.to_string()).and_then(|exe| {
        tauri::async_runtime::block_on(async {
            let (engine, events) = Engine::start(paths.clone(), exe).await.map_err(|e| e.to_string())?;
            Ok::<_, String>(Manager::new(Arc::new(engine), ui, db.clone(), settings.clone(), events))
        })
    });
    let (manager, startup_error) = match started {
        Ok(m) => {
            apply_storage(&m, &vault, settings.credential_storage, keyring);
            (Some(m), None)
        }
        Err(e) => {
            tracing::error!("SSH engine unavailable: {e}");
            (None, Some(e))
        }
    };

    if let Some(m) = &manager {
        let (m, handle) = (m.clone(), app.handle().clone());
        tauri::async_runtime::spawn(async move {
            let lock = move |reason: &'static str| {
                let s = m.settings();
                let wanted = match reason {
                    "sleep" => s.lock_on_sleep,
                    _ => s.lock_on_session_lock,
                };
                if wanted {
                    crate::commands::security::lock_now(&handle);
                }
            };
            if let Err(e) = simple_connect_core::security::session_watch::watch(lock).await {
                tracing::info!("session lock notifications unavailable: {e}");
            }
        });
    }

    app.manage(AppState {
        paths,
        db,
        manager,
        startup_error,
        vault,
        keyring_available,
        clipboard_generation: AtomicU64::new(0),
        scanning: AtomicBool::new(false),
        scan_cancel: AtomicBool::new(false),
    });
}

pub fn db_lock(
    db: &Db,
) -> Result<std::sync::MutexGuard<'_, simple_connect_core::storage::rusqlite::Connection>, crate::commands::CmdError> {
    db.lock().map_err(|_| crate::commands::CmdError::internal("database lock poisoned"))
}
