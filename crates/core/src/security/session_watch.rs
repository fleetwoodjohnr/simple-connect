//! Locks the app on native sleep/session events: systemd-logind on Linux,
//! WTS and power broadcasts on Windows, and workspace notifications on macOS.

#[cfg(target_os = "linux")]
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

#[cfg(any(windows, target_os = "macos"))]
pub async fn watch(on_lock: impl Fn(&'static str) + Send + Sync + 'static) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || native::watch(std::sync::Arc::new(on_lock))).await.map_err(std::io::Error::other)?
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
pub async fn watch(_on_lock: impl Fn(&'static str) + Send + Sync + 'static) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)] // Native window callback boundary; all storage outlives its HWND.
mod native {
    use std::io;
    use std::ptr::{null, null_mut};
    use std::sync::Arc;
    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification},
        },
        UI::WindowsAndMessaging::*,
    };
    type Callback = Arc<dyn Fn(&'static str) + Send + Sync>;

    unsafe extern "system" fn window_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // SAFETY: watch sets this pointer before processing notifications and
        // clears it before freeing its Box or destroying the window.
        let callback = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const Callback;
        let reason = match (message, wparam) {
            (WM_WTSSESSION_CHANGE, n) if n == WTS_SESSION_LOCK as usize => Some("session"),
            (WM_POWERBROADCAST, n) if n == PBT_APMSUSPEND as usize => Some("sleep"),
            _ => None,
        };
        if let Some(reason) = reason {
            if !callback.is_null() {
                // Never unwind across the OS callback boundary.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe { (*callback)(reason) }));
            }
        }
        unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
    }

    pub fn watch(callback: Callback) -> io::Result<()> {
        let name: Vec<u16> = format!("SimpleConnectSessionWatch-{}", std::process::id()).encode_utf16().chain(Some(0)).collect();
        // SAFETY: the class name, callback Box, and module handle remain live
        // until notifications are unregistered and the HWND is destroyed.
        unsafe {
            let instance = GetModuleHandleW(null());
            if instance.is_null() {
                return Err(io::Error::last_os_error());
            }
            let class =
                WNDCLASSW { lpfnWndProc: Some(window_proc), hInstance: instance, lpszClassName: name.as_ptr(), ..Default::default() };
            if RegisterClassW(&class) == 0 {
                return Err(io::Error::last_os_error());
            }
            // This must be a hidden top-level window: HWND_MESSAGE windows do
            // not receive the system's power broadcasts.
            let hwnd = CreateWindowExW(0, name.as_ptr(), name.as_ptr(), WS_POPUP, 0, 0, 0, 0, null_mut(), null_mut(), instance, null());
            if hwnd.is_null() {
                let error = io::Error::last_os_error();
                UnregisterClassW(name.as_ptr(), instance);
                return Err(error);
            }
            let callback = Box::new(callback);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (&*callback as *const Callback) as isize);
            if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
                let error = io::Error::last_os_error();
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                DestroyWindow(hwnd);
                UnregisterClassW(name.as_ptr(), instance);
                return Err(error);
            }
            let mut message = MSG::default();
            let result = loop {
                let received = GetMessageW(&mut message, null_mut(), 0, 0);
                if received <= 0 {
                    break if received == 0 { Ok(()) } else { Err(io::Error::last_os_error()) };
                }
                TranslateMessage(&message);
                DispatchMessageW(&message);
            };
            WTSUnRegisterSessionNotification(hwnd);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DestroyWindow(hwnd);
            UnregisterClassW(name.as_ptr(), instance);
            drop(callback);
            result
        }
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)] // Typed Objective-C observer registration; captures are Send + Sync.
mod native {
    use block2::RcBlock;
    use objc2_app_kit::{NSWorkspace, NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification};
    use objc2_foundation::{NSDistributedNotificationCenter, NSNotification, NSOperationQueue, NSRunLoop, NSString};
    use std::io;
    use std::ptr::NonNull;
    use std::sync::Arc;

    pub fn watch(callback: Arc<dyn Fn(&'static str) + Send + Sync>) -> io::Result<()> {
        let center = NSWorkspace::sharedWorkspace().notificationCenter();
        let distributed = NSDistributedNotificationCenter::defaultCenter();
        let queue = NSOperationQueue::mainQueue();
        let sleep = callback.clone();
        let sleep_block = RcBlock::new(move |_: NonNull<NSNotification>| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sleep("sleep")));
        });
        let inactive = callback.clone();
        let inactive_block = RcBlock::new(move |_: NonNull<NSNotification>| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inactive("session")));
        });
        let lock_block = RcBlock::new(move |_: NonNull<NSNotification>| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback("session")));
        });
        let locked = NSString::from_str("com.apple.screenIsLocked");
        // SAFETY: obj=None accepts all senders; queue is the OS main queue;
        // blocks capture only Arc<dyn Fn + Send + Sync>. Retained observer tokens
        // and centers stay alive for the lifetime of this watcher thread.
        let _observers = unsafe {
            (
                center.addObserverForName_object_queue_usingBlock(Some(NSWorkspaceWillSleepNotification), None, None, &sleep_block),
                center.addObserverForName_object_queue_usingBlock(
                    Some(NSWorkspaceSessionDidResignActiveNotification),
                    None,
                    Some(&queue),
                    &inactive_block,
                ),
                distributed.addObserverForName_object_queue_usingBlock(Some(&locked), None, Some(&queue), &lock_block),
            )
        };
        // Distributed notifications need a serviced runloop on the registration
        // thread. This is a Foundation worker loop, independent of Tauri's UI
        // runloop; UI-queued callbacks are dispatched by the existing NSApp.
        NSRunLoop::currentRunLoop().run();
        Err(io::Error::other("the macOS session notification runloop stopped"))
    }
}
