//! Export and import of connection profiles.
//!
//! A plain export is JSON without any secrets. Saved passwords are only included
//! in an encrypted backup (Argon2id + XChaCha20-Poly1305, see
//! [`crate::security::vault::seal`]) protected by a password the user chooses.
//!
//! Imports are untrusted: size-limited, parsed with unknown fields rejected,
//! and every profile goes through the same validation as manual input. Security
//! policy (legacy algorithms) is never imported.

use std::collections::HashMap;

use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{AuthMethod, Profile, ProfileDraft, create, create_group, list, list_groups, set_favorite};
use crate::security::{CredentialStore, new_password_ref, vault};
use crate::validate::JumpHop;

const FORMAT: &str = "simple-connect/profiles";
const BACKUP_MAGIC: &[u8; 8] = b"SCBACKUP";
pub const MAX_IMPORT_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportFile {
    format: String,
    version: u32,
    profiles: Vec<ExportProfile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportProfile {
    name: String,
    host: String,
    port: Option<u32>,
    username: Option<String>,
    folder: Option<String>,
    #[serde(default)]
    auth: AuthMethod,
    identity_file: Option<String>,
    jump: Option<String>,
    start_dir: Option<String>,
    keepalive_secs: Option<u32>,
    terminal_theme: Option<String>,
    color: Option<String>,
    icon: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reuse_password: Option<bool>,
    /// Present only inside encrypted backups.
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("The file is too large to import.")]
    TooLarge,
    #[error("This isn't a Simple Connect export, or it's damaged.")]
    BadFormat,
    #[error("This backup is encrypted. Enter its password.")]
    NeedsPassword,
    #[error("The backup password is incorrect.")]
    WrongPassword,
    #[error("Saved passwords can't be read: {0}")]
    Secrets(String),
    #[error("The connection list couldn't be read or written.")]
    Db(#[from] rusqlite::Error),
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub imported: usize,
    /// "name: reason" for profiles that failed validation.
    pub skipped: Vec<String>,
}

/// Serialises all profiles. With `backup_password`, saved passwords are
/// included and the whole file is encrypted; without it, no secret is written.
pub fn export(
    conn: &Connection,
    backup_password: Option<&SecretString>,
    store: Option<&dyn CredentialStore>,
) -> Result<Vec<u8>, TransferError> {
    let groups: HashMap<String, String> = list_groups(conn).map_err(db)?.into_iter().map(|g| (g.id, g.name)).collect();
    let profiles: Vec<Profile> = list(conn).map_err(db)?;
    let mut out = Vec::with_capacity(profiles.len());
    for p in profiles {
        let password = match (backup_password, store, p.has_saved_secret) {
            (Some(_), Some(store), true) => {
                let r = super::secret_ref(conn, &p.id).map_err(db)?;
                match r {
                    Some(r) => store.get(&r).map_err(|e| TransferError::Secrets(e.to_string()))?.map(|s| s.expose_secret().to_owned()),
                    None => None,
                }
            }
            _ => None,
        };
        let f = p.fields;
        out.push(ExportProfile {
            name: f.name,
            host: f.host.as_str().to_owned(),
            port: f.port.map(u32::from),
            username: f.username.map(|u| u.as_str().to_owned()),
            folder: f.group_id.and_then(|g| groups.get(&g).cloned()),
            auth: f.auth,
            identity_file: f.identity_file.map(|p| p.to_string_lossy().into_owned()),
            jump: (!f.jump.is_empty()).then(|| f.jump.iter().map(JumpHop::to_spec).collect::<Vec<_>>().join(",")),
            start_dir: f.start_dir,
            keepalive_secs: f.keepalive_secs.map(u32::from),
            terminal_theme: f.terminal_theme,
            color: f.color,
            icon: f.icon,
            tags: f.tags,
            favorite: p.favorite,
            mac: f.mac,
            reuse_password: f.reuse_password,
            password,
        });
    }
    let json = zeroize::Zeroizing::new(
        serde_json::to_vec_pretty(&ExportFile { format: FORMAT.into(), version: 1, profiles: out })
            .map_err(|_| TransferError::BadFormat)?,
    );
    match backup_password {
        Some(pw) => vault::seal(BACKUP_MAGIC, pw, &json).map_err(|e| TransferError::Secrets(e.to_string())),
        None => Ok(json.to_vec()),
    }
}

fn db(e: super::ProfileError) -> TransferError {
    match e {
        super::ProfileError::Db(e) => TransferError::Db(e),
        _ => TransferError::BadFormat,
    }
}

pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(BACKUP_MAGIC)
}

pub fn import(
    conn: &mut Connection,
    data: &[u8],
    password: Option<&SecretString>,
    store: Option<&dyn CredentialStore>,
) -> Result<ImportReport, TransferError> {
    if data.len() > MAX_IMPORT_BYTES {
        return Err(TransferError::TooLarge);
    }
    let plain = if is_encrypted(data) {
        let pw = password.ok_or(TransferError::NeedsPassword)?;
        vault::open(BACKUP_MAGIC, pw, data).map_err(|e| match e {
            crate::security::SecretError::WrongPassword => TransferError::WrongPassword,
            _ => TransferError::BadFormat,
        })?
    } else {
        zeroize::Zeroizing::new(data.to_vec())
    };
    let file: ExportFile = serde_json::from_slice(&plain).map_err(|_| TransferError::BadFormat)?;
    if file.format != FORMAT || file.version != 1 {
        return Err(TransferError::BadFormat);
    }

    let mut folders: HashMap<String, String> = list_groups(conn).map_err(db)?.into_iter().map(|g| (g.name, g.id)).collect();
    let mut report = ImportReport::default();
    for p in file.profiles {
        let group_id = match &p.folder {
            Some(name) => match folders.get(name) {
                Some(id) => Some(id.clone()),
                None => match create_group(conn, name) {
                    Ok(g) => {
                        folders.insert(g.name.clone(), g.id.clone());
                        Some(g.id)
                    }
                    Err(_) => None,
                },
            },
            None => None,
        };
        let draft = ProfileDraft {
            name: p.name.clone(),
            host: p.host,
            port: p.port,
            username: p.username,
            group_id,
            auth: p.auth,
            identity_file: p.identity_file,
            jump: p.jump,
            start_dir: p.start_dir,
            keepalive_secs: p.keepalive_secs,
            terminal_theme: p.terminal_theme,
            color: p.color,
            icon: p.icon,
            tags: p.tags,
            mac: p.mac,
            reuse_password: p.reuse_password,
        };
        match create(conn, &draft) {
            Ok(created) => {
                report.imported += 1;
                if p.favorite {
                    let _ = set_favorite(conn, &created.id, true);
                }
                if let (Some(pw), Some(store)) = (p.password, store) {
                    let r = new_password_ref();
                    if store.set(&r, &SecretString::from(pw)).is_ok() {
                        let _ = super::set_secret_ref(conn, &created.id, Some(&r));
                    }
                }
            }
            Err(super::ProfileError::Invalid(errs)) => {
                let why = errs.first().map(|e| e.message.clone()).unwrap_or_default();
                report.skipped.push(format!("{}: {why}", p.name.chars().take(60).collect::<String>()));
            }
            Err(e) => return Err(db(e)),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::MemoryStore;
    use crate::storage::open_in_memory;

    fn seed(conn: &mut Connection, store: &MemoryStore) {
        let g = create_group(conn, "Work").unwrap();
        let d = ProfileDraft {
            name: "Web".into(),
            host: "web.example.com".into(),
            username: Some("deploy".into()),
            group_id: Some(g.id),
            jump: Some("ops@bastion:22".into()),
            tags: vec!["prod".into()],
            mac: Some("dc:a6:32:00:00:01".into()),
            ..Default::default()
        };
        let p = create(conn, &d).unwrap();
        set_favorite(conn, &p.id, true).unwrap();
        store.set("password:x", &SecretString::from("hunter2")).unwrap();
        super::super::set_secret_ref(conn, &p.id, Some("password:x")).unwrap();
    }

    #[test]
    fn plain_export_has_no_secrets() {
        let (mut conn, store) = (open_in_memory().unwrap(), MemoryStore::default());
        seed(&mut conn, &store);
        let data = export(&conn, None, Some(&store)).unwrap();
        let text = String::from_utf8(data.clone()).unwrap();
        assert!(!text.contains("hunter2") && !text.contains("password"));

        let mut other = open_in_memory().unwrap();
        let report = import(&mut other, &data, None, None).unwrap();
        assert_eq!(report.imported, 1);
        let p = &list(&other).unwrap()[0];
        assert!(p.favorite && !p.has_saved_secret);
        assert_eq!(p.fields.jump[0].to_spec(), "ops@bastion:22");
        assert_eq!(list_groups(&other).unwrap()[0].name, "Work");
        assert_eq!(p.fields.mac.as_deref(), Some("dc:a6:32:00:00:01"));
    }

    #[test]
    fn encrypted_backup_carries_passwords() {
        let (mut conn, store) = (open_in_memory().unwrap(), MemoryStore::default());
        seed(&mut conn, &store);
        let pw = SecretString::from("backup pw");
        let data = export(&conn, Some(&pw), Some(&store)).unwrap();
        assert!(is_encrypted(&data) && !data.windows(7).any(|w| w == b"hunter2"));

        let (mut other, other_store) = (open_in_memory().unwrap(), MemoryStore::default());
        assert!(matches!(import(&mut other, &data, None, None), Err(TransferError::NeedsPassword)));
        assert!(matches!(import(&mut other, &data, Some(&SecretString::from("bad")), None), Err(TransferError::WrongPassword)));
        import(&mut other, &data, Some(&pw), Some(&other_store)).unwrap();
        let r = super::super::secret_ref(&other, &list(&other).unwrap()[0].id).unwrap().unwrap();
        assert_eq!(other_store.get(&r).unwrap().unwrap().expose_secret(), "hunter2");
    }

    #[test]
    fn hostile_imports_are_rejected_or_skipped() {
        let mut conn = open_in_memory().unwrap();
        assert!(matches!(import(&mut conn, b"not json", None, None), Err(TransferError::BadFormat)));
        let unknown = br#"{"format":"simple-connect/profiles","version":1,"profiles":[],"legacyCrypto":true}"#;
        assert!(matches!(import(&mut conn, unknown, None, None), Err(TransferError::BadFormat)), "unknown fields rejected");
        let policy = br#"{"format":"simple-connect/profiles","version":1,"profiles":[{"name":"x","host":"h","legacyCrypto":true}]}"#;
        assert!(matches!(import(&mut conn, policy, None, None), Err(TransferError::BadFormat)), "security policy can't be imported");
        let evil = br#"{"format":"simple-connect/profiles","version":1,"profiles":[
            {"name":"ok","host":"good.example"},
            {"name":"evil","host":"-oProxyCommand=sh"},
            {"name":"jump","host":"h","jump":"a;b"}]}"#;
        let r = import(&mut conn, evil, None, None).unwrap();
        assert_eq!((r.imported, r.skipped.len()), (1, 2));
        assert!(matches!(import(&mut conn, &vec![b' '; MAX_IMPORT_BYTES + 1], None, None), Err(TransferError::TooLarge)));
    }
}
