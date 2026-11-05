//! CI-only installed updater rehearsal. This example is never bundled or shipped.
//! update_rehearsal <reject-tamper|install> <localhost-feed> <installed-path> <target>
//! Only this isolated example permits HTTP; production configuration stays HTTPS-only.

use std::path::PathBuf;
use std::time::Duration;

use tauri_plugin_updater::UpdaterExt;

type Failure = Box<dyn std::error::Error + Send + Sync>;

fn loopback(url: &tauri::Url) -> bool {
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none()
}

async fn rehearse(app: tauri::AppHandle, mode: String, feed: tauri::Url, installed: PathBuf, target: String) -> Result<(), Failure> {
    let update = app
        .updater_builder()
        .target(target)
        .endpoints(vec![feed.clone()])?
        .executable_path(installed)
        .no_proxy()
        .timeout(Duration::from_secs(120))
        .restart_after_install(false)
        .build()?
        .check()
        .await?
        .ok_or("candidate was not detected as an upgrade from 0.0.9")?;
    if update.current_version != "0.0.9" || update.version != env!("CARGO_PKG_VERSION") {
        return Err("rehearsal current/candidate version mismatch".into());
    }
    if !loopback(&update.download_url) || update.download_url.port() != feed.port() {
        return Err("rehearsal download must use the same local fixture server".into());
    }
    eprintln!("Updater detected {} -> {} for {}", update.current_version, update.version, update.target);
    let downloaded = update.download(|_, _| {}, || {}).await;
    if mode == "reject-tamper" {
        return match downloaded {
            Err(tauri_plugin_updater::Error::Minisign(_)) => {
                eprintln!("Tampered download rejected by native minisign verification");
                Ok(())
            }
            Err(error) => Err(format!("tamper check failed for an unrelated reason: {error}").into()),
            Ok(_) => Err("native updater accepted a tampered package".into()),
        };
    }
    let bytes = downloaded?;
    // Native NSIS installation exits this example on Windows; Python waits for
    // its installer and independently verifies the replacement executable hash.
    update.install(bytes)?;
    eprintln!("Native updater installation completed");
    Ok(())
}

fn main() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 || !matches!(args[1].as_str(), "reject-tamper" | "install") {
        return Err("expected mode, localhost feed URL, installed executable/AppImage path, target".into());
    }
    let feed: tauri::Url = args[2].parse()?;
    let installed = PathBuf::from(&args[3]);
    let os = if cfg!(target_os = "macos") { "darwin" } else { std::env::consts::OS };
    let bundle = if cfg!(windows) {
        "nsis"
    } else if cfg!(target_os = "macos") {
        "app"
    } else {
        "appimage"
    };
    let expected_target = format!("{os}-{}-{bundle}", std::env::consts::ARCH);
    if !loopback(&feed) || !installed.is_absolute() || !installed.is_file() || args[4] != expected_target {
        return Err("rehearsal requires an existing absolute install path, local fixture and native target".into());
    }
    if std::env::var_os("SIMPLE_CONNECT_HOME").is_none() {
        return Err("rehearsal requires an isolated SIMPLE_CONNECT_HOME".into());
    }
    let mut context = tauri::generate_context!();
    context.package_info_mut().version = "0.0.9".parse()?;
    context.config_mut().version = Some("0.0.9".into());
    context.config_mut().app.windows.clear();
    context.config_mut().plugins.0.get_mut("updater").ok_or("missing updater configuration")?["dangerousInsecureTransportProtocol"] =
        serde_json::Value::Bool(true);
    #[cfg(windows)]
    {
        context.config_mut().plugins.0.get_mut("updater").ok_or("missing updater configuration")?["windows"] =
            serde_json::json!({"installMode": "quiet"});
    }
    let mode = args[1].clone();
    let target = args[4].clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let result = rehearse(handle.clone(), mode, feed, installed, target).await;
                let code = match result {
                    Ok(()) => 0,
                    Err(error) => {
                        eprintln!("Updater rehearsal failed: {error}");
                        1
                    }
                };
                handle.exit(code);
            });
            Ok(())
        })
        .run(context)?;
    Ok(())
}
