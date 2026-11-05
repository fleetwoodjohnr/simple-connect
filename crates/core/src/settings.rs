//! Typed application settings, stored as one JSON document in the settings table.
//! Every field has a secure default, and values are clamped when loaded so a
//! hand-edited database can't produce an unsafe configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStorage {
    /// Secret Service / Keychain / Credential Manager.
    Keyring,
    /// Encrypted vault file unlocked with a master password.
    Vault,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct TerminalSettings {
    pub font_family: String,
    pub font_size: u16,
    pub line_height: f32,
    pub theme: String,
    pub scrollback: u32,
    pub cursor_blink: bool,
    pub copy_on_select: bool,
    pub confirm_multiline_paste: bool,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            font_family: "IBM Plex Mono".into(),
            font_size: 14,
            line_height: 1.2,
            theme: "auto".into(),
            scrollback: 10_000,
            cursor_blink: true,
            copy_on_select: false,
            confirm_multiline_paste: true,
        }
    }
}

/// How the remote screen fits the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DesktopScale {
    /// Scaled to fit the window.
    #[default]
    Fit,
    /// One remote pixel per screen pixel, scrolled.
    Actual,
    /// The remote desktop is resized to the window where the server allows it.
    Remote,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DesktopSettings {
    pub quality: crate::desktop::Quality,
    pub scale: DesktopScale,
    /// Copy the remote clipboard automatically and send the local one on focus.
    /// Off by default: clipboard contents move only when the user asks.
    pub clipboard_sync: bool,
    /// Where dropped files go, relative to the remote home folder.
    pub upload_dir: String,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self { quality: crate::desktop::Quality::Auto, scale: DesktopScale::Fit, clipboard_sync: false, upload_dir: "Desktop".into() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub auto_check_updates: bool,
    pub auto_reconnect: bool,
    pub include_user_ssh_config: bool,
    pub keepalive_secs: u16,
    pub connect_timeout_secs: u16,
    pub verify_checksums: bool,
    pub editor_max_mb: u32,
    /// 0 = never clear.
    pub clipboard_clear_secs: u32,
    /// 0 = never auto-lock.
    pub auto_lock_minutes: u32,
    pub lock_on_sleep: bool,
    pub lock_on_session_lock: bool,
    pub credential_storage: CredentialStorage,
    /// Write newly trusted host keys to ~/.ssh/known_hosts as well (off by default:
    /// the user's OpenSSH files are only changed with explicit permission).
    pub write_user_known_hosts: bool,
    pub show_hidden_files: bool,
    /// Offer the SSH login password at sudo/su prompts (sent only on Enter).
    pub reuse_ssh_password: bool,
    pub terminal: TerminalSettings,
    pub remote_desktop: DesktopSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_check_updates: true,
            auto_reconnect: true,
            include_user_ssh_config: true,
            keepalive_secs: 30,
            connect_timeout_secs: 15,
            verify_checksums: true,
            editor_max_mb: 5,
            clipboard_clear_secs: 30,
            auto_lock_minutes: 0,
            lock_on_sleep: true,
            lock_on_session_lock: true,
            credential_storage: CredentialStorage::Keyring,
            write_user_known_hosts: false,
            show_hidden_files: false,
            reuse_ssh_password: true,
            terminal: TerminalSettings::default(),
            remote_desktop: DesktopSettings::default(),
        }
    }
}

impl Settings {
    pub const KEY: &'static str = "app.settings";

    /// Clamps every numeric field into its supported range.
    pub fn sanitized(mut self) -> Self {
        self.keepalive_secs = self.keepalive_secs.min(3600);
        self.connect_timeout_secs = self.connect_timeout_secs.clamp(3, 120);
        self.editor_max_mb = self.editor_max_mb.clamp(1, 100);
        if ![0, 15, 30, 60].contains(&self.clipboard_clear_secs) {
            self.clipboard_clear_secs = 30;
        }
        self.auto_lock_minutes = self.auto_lock_minutes.min(24 * 60);
        let t = &mut self.terminal;
        t.font_size = t.font_size.clamp(8, 40);
        t.line_height = t.line_height.clamp(1.0, 2.0);
        t.scrollback = t.scrollback.clamp(500, 200_000);
        t.font_family = t.font_family.chars().filter(|c| c.is_alphanumeric() || " -_,'\"".contains(*c)).take(120).collect();
        t.theme = t.theme.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(32).collect();
        // A folder under the remote home: no absolute paths, no "..".
        let d = &mut self.remote_desktop;
        let dir: String = d.upload_dir.trim().trim_matches('/').chars().filter(|c| !c.is_control()).take(200).collect();
        d.upload_dir = if dir.split('/').any(|c| c == ".." || c == ".") { String::new() } else { dir };
        self
    }

    pub fn load(conn: &rusqlite::Connection) -> Settings {
        crate::storage::settings::get::<Settings>(conn, Self::KEY).ok().flatten().unwrap_or_default().sanitized()
    }

    pub fn save(&self, conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        crate::storage::settings::set(conn, Self::KEY, &self.clone().sanitized())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_settings_enable_update_checks_by_default() {
        let old: Settings = serde_json::from_str(r#"{"autoReconnect":false}"#).unwrap();
        assert!(old.auto_check_updates);
        assert!(!old.auto_reconnect);
        let opted_out: Settings = serde_json::from_str(r#"{"autoCheckUpdates":false}"#).unwrap();
        assert!(!opted_out.auto_check_updates);
    }

    #[test]
    fn defaults_are_secure_and_values_are_clamped() {
        let d = Settings::default();
        assert!(d.verify_checksums && !d.write_user_known_hosts && d.lock_on_sleep);
        assert!(!d.remote_desktop.clipboard_sync, "clipboards move only on request by default");
        let wild = Settings { connect_timeout_secs: 0, clipboard_clear_secs: 7, editor_max_mb: 10_000, ..Settings::default() }.sanitized();
        assert_eq!((wild.connect_timeout_secs, wild.clipboard_clear_secs, wild.editor_max_mb), (3, 30, 100));
        for (dir, want) in [("/Desktop/", "Desktop"), ("../../etc", ""), ("a/./b", ""), ("Uploads/in", "Uploads/in")] {
            let mut s = Settings::default();
            s.remote_desktop.upload_dir = dir.into();
            assert_eq!(s.sanitized().remote_desktop.upload_dir, want, "{dir}");
        }

        let conn = crate::storage::open_in_memory().unwrap();
        assert_eq!(Settings::load(&conn), d);
        let mut s = d.clone();
        s.auto_reconnect = false;
        s.save(&conn).unwrap();
        assert!(!Settings::load(&conn).auto_reconnect);
        // Unknown or partial JSON falls back field by field.
        crate::storage::settings::set(&conn, Settings::KEY, &serde_json::json!({"autoReconnect": false, "bogus": 1})).unwrap();
        let partial = Settings::load(&conn);
        assert!(!partial.auto_reconnect && partial.verify_checksums);
    }
}
