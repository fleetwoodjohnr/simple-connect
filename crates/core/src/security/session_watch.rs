//! Locks the app when the computer sleeps or the desktop session locks
//! (systemd-logind over D-Bus; works on GNOME, KDE, Cinnamon, XFCE, Hyprland…).

use futures_util::StreamExt;

/// Runs until the bus connection ends. `on_lock(reason)` fires for each event.
#[cfg(target_os = "linux")]
pub async fn watch(on_lock: impl Fn(&'static str) + Send + Sync + 'static) -> zbus::Result<()> {
    const DEST: &str = "org.freedesktop.login1";
    let conn = zbus::Connection::system().await?;
    let manager = zbus::Proxy::new(&conn, DEST, "/org/freedesktop/login1", "org.freedesktop.login1.Manager").await?;
    // "auto" resolves to the session of the calling process.
    let session = zbus::Proxy::new(&conn, DEST, "/org/freedesktop/login1/session/auto", "org.freedesktop.login1.Session").await?;
    let mut sleep = manager.receive_signal("PrepareForSleep").await?;
    let mut lock = session.receive_signal("Lock").await?;
    let mut hint = session.receive_property_changed::<bool>("LockedHint").await;
    loop {
        tokio::select! {
            Some(msg) = sleep.next() => {
                if msg.body().deserialize::<bool>().unwrap_or(false) {
                    on_lock("sleep");
                }
            }
            Some(_) = lock.next() => on_lock("session"),
            Some(change) = hint.next() => {
                if change.get().await.unwrap_or(false) {
                    on_lock("session");
                }
            }
            else => return Ok(()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn watch(_on_lock: impl Fn(&'static str) + Send + Sync + 'static) -> std::io::Result<()> {
    // ponytail: macOS/Windows session notifications arrive with those ports.
    Ok(())
}
