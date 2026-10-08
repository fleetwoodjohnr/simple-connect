//! Saved connection profiles and folders.
//!
//! Input arrives as an untrusted [`ProfileDraft`] (UI or import) and is validated
//! into [`ProfileFields`] with per-field, user-facing errors. Security policy
//! (`legacy_crypto`) and secret references are never part of a draft, so neither
//! the UI form nor an imported file can set them.

pub mod export;
pub mod ssh_config;

use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};

use crate::storage::now;
use crate::validate::{self, Host, JumpHop, User};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// Let OpenSSH try agent and keys, then password.
    #[default]
    Auto,
    Password,
    Key,
    Agent,
}

impl AuthMethod {
    fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Auto => "auto",
            AuthMethod::Password => "password",
            AuthMethod::Key => "key",
            AuthMethod::Agent => "agent",
        }
    }
    fn from_db(s: &str) -> Self {
        match s {
            "password" => AuthMethod::Password,
            "key" => AuthMethod::Key,
            "agent" => AuthMethod::Agent,
            _ => AuthMethod::Auto,
        }
    }
}

pub const COLORS: &[&str] = &["gray", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink"];
pub const ICONS: &[&str] = &["server", "nas", "pi", "router", "cloud", "database", "desktop", "container"];
const MAX_TAGS: usize = 16;

/// Untrusted profile input.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileDraft {
    pub name: String,
    pub host: String,
    pub port: Option<u32>,
    pub username: Option<String>,
    pub group_id: Option<String>,
    #[serde(default)]
    pub auth: AuthMethod,
    pub identity_file: Option<String>,
    pub jump: Option<String>,
    pub start_dir: Option<String>,
    pub keepalive_secs: Option<u32>,
    pub terminal_theme: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Hardware address, used to recognise the device when its IP changes.
    pub mac: Option<String>,
    /// Offer the login password at sudo/su prompts. `None` follows the app setting.
    pub reuse_password: Option<bool>,
}

/// Validated, user-editable profile fields.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileFields {
    pub name: String,
    pub host: Host,
    pub port: Option<u16>,
    pub username: Option<User>,
    pub group_id: Option<String>,
    pub auth: AuthMethod,
    pub identity_file: Option<PathBuf>,
    pub jump: Vec<JumpHop>,
    pub start_dir: Option<String>,
    pub keepalive_secs: Option<u16>,
    pub terminal_theme: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub tags: Vec<String>,
    pub mac: Option<String>,
    pub reuse_password: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    #[serde(flatten)]
    pub fields: ProfileFields,
    pub favorite: bool,
    pub legacy_crypto: bool,
    pub has_saved_secret: bool,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldError {
    pub field: &'static str,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("Some fields need attention.")]
    Invalid(Vec<FieldError>),
    #[error("That connection or folder no longer exists.")]
    NotFound,
    #[error("The connection list could not be saved.")]
    Db(#[from] rusqlite::Error),
}

type Result<T> = std::result::Result<T, ProfileError>;

/// Trimmed text with no control characters; empty → None.
fn text(value: Option<&str>, max: usize, field: &'static str, errs: &mut Vec<FieldError>) -> Option<String> {
    let v = value.map(str::trim).filter(|v| !v.is_empty())?;
    if v.chars().count() > max || v.chars().any(char::is_control) {
        errs.push(FieldError { field, message: format!("Use at most {max} characters, without line breaks.") });
        return None;
    }
    Some(v.to_owned())
}

fn one_of(value: Option<&str>, allowed: &[&str], field: &'static str, errs: &mut Vec<FieldError>) -> Option<String> {
    let v = value.filter(|v| !v.is_empty())?;
    if allowed.contains(&v) {
        Some(v.to_owned())
    } else {
        errs.push(FieldError { field, message: "Choose one of the listed options.".into() });
        None
    }
}

impl ProfileDraft {
    pub fn validate(&self) -> std::result::Result<ProfileFields, Vec<FieldError>> {
        let mut errs = Vec::new();
        let mut check = |field: &'static str, r: std::result::Result<(), validate::ValidationError>| {
            if let Err(e) = r {
                errs.push(FieldError { field, message: e.to_string() });
            }
        };

        let host = Host::parse(&self.host);
        check("host", host.as_ref().map(drop).map_err(Clone::clone));
        let username = self.username.as_deref().filter(|u| !u.trim().is_empty()).map(User::parse).transpose();
        check("username", username.as_ref().map(drop).map_err(Clone::clone));
        let port = self.port.map(|p| validate::port(&p.to_string())).transpose();
        check("port", port.as_ref().map(drop).map_err(Clone::clone));
        let identity_file =
            self.identity_file.as_deref().filter(|p| !p.trim().is_empty()).map(|p| validate::identity_file(p.trim())).transpose();
        check("identityFile", identity_file.as_ref().map(drop).map_err(Clone::clone));
        let jump = self.jump.as_deref().filter(|j| !j.trim().is_empty()).map(validate::jump_chain).transpose();
        check("jump", jump.as_ref().map(drop).map_err(Clone::clone));
        let remote_dir = self.start_dir.as_deref().filter(|d| !d.is_empty()).map(validate::remote_path).transpose();
        check("startDir", remote_dir.map(drop));
        let mac = self.mac.as_deref().filter(|m| !m.trim().is_empty()).map(validate::mac).transpose();
        check("mac", mac.as_ref().map(drop).map_err(Clone::clone));

        let name = text(Some(&self.name), 100, "name", &mut errs);
        if name.is_none() && !errs.iter().any(|e| e.field == "name") {
            errs.push(FieldError { field: "name", message: "Enter a name for this connection.".into() });
        }
        let start_dir = text(self.start_dir.as_deref(), 1024, "startDir", &mut errs);
        let keepalive_secs = match self.keepalive_secs {
            Some(s) if s > 3600 => {
                errs.push(FieldError { field: "keepaliveSecs", message: "Use 0 to 3600 seconds.".into() });
                None
            }
            s => s.map(|s| s as u16),
        };
        let terminal_theme = text(self.terminal_theme.as_deref(), 32, "terminalTheme", &mut errs);
        let color = one_of(self.color.as_deref(), COLORS, "color", &mut errs);
        let icon = one_of(self.icon.as_deref(), ICONS, "icon", &mut errs);
        let group_id = text(self.group_id.as_deref(), 64, "groupId", &mut errs);

        let mut tags: Vec<String> = Vec::new();
        for t in &self.tags {
            if let Some(t) = text(Some(t), 32, "tags", &mut errs)
                && !tags.contains(&t)
            {
                tags.push(t);
            }
        }
        if tags.len() > MAX_TAGS {
            errs.push(FieldError { field: "tags", message: format!("Use at most {MAX_TAGS} tags.") });
        }

        if !errs.is_empty() {
            return Err(errs);
        }
        Ok(ProfileFields {
            name: name.unwrap_or_default(),
            host: host.map_err(|_| Vec::new())?,
            port: port.ok().flatten(),
            username: username.ok().flatten(),
            group_id,
            auth: self.auth,
            identity_file: identity_file.ok().flatten(),
            jump: jump.ok().flatten().unwrap_or_default(),
            start_dir,
            keepalive_secs,
            terminal_theme,
            color,
            icon,
            tags,
            mac: mac.ok().flatten(),
            reuse_password: self.reuse_password,
        })
    }
}

fn jump_spec(jump: &[JumpHop]) -> Option<String> {
    (!jump.is_empty()).then(|| jump.iter().map(JumpHop::to_spec).collect::<Vec<_>>().join(","))
}

const COLUMNS: &str = "id, name, host, port, username, group_id, auth, identity_file, jump, start_dir, keepalive_secs,
     terminal_theme, color, icon, favorite, legacy_crypto, secret_ref, last_used_at, mac, reuse_password";

/// Rows were validated on write; re-validate on read so a tampered database
/// can't smuggle unvalidated hosts or users into `ssh` arguments.
fn from_row(r: &Row) -> rusqlite::Result<Option<Profile>> {
    let draft = ProfileDraft {
        name: r.get(1)?,
        host: r.get(2)?,
        port: r.get(3)?,
        username: r.get(4)?,
        group_id: r.get(5)?,
        auth: AuthMethod::from_db(&r.get::<_, String>(6)?),
        identity_file: r.get(7)?,
        jump: r.get(8)?,
        start_dir: r.get(9)?,
        keepalive_secs: r.get(10)?,
        terminal_theme: r.get(11)?,
        color: r.get(12)?,
        icon: r.get(13)?,
        tags: Vec::new(),
        mac: r.get(18)?,
        reuse_password: r.get(19)?,
    };
    let id: String = r.get(0)?;
    let Ok(fields) = draft.validate() else {
        tracing::warn!(profile = %id, "skipping stored profile that fails validation");
        return Ok(None);
    };
    Ok(Some(Profile {
        id,
        fields,
        favorite: r.get(14)?,
        legacy_crypto: r.get(15)?,
        has_saved_secret: r.get::<_, Option<String>>(16)?.is_some(),
        last_used_at: r.get(17)?,
    }))
}

pub fn list(conn: &Connection) -> Result<Vec<Profile>> {
    let mut stmt = conn.prepare(&format!("SELECT {COLUMNS} FROM profiles ORDER BY name COLLATE NOCASE"))?;
    let mut profiles: Vec<Profile> = stmt.query_map([], from_row)?.filter_map(|r| r.transpose()).collect::<rusqlite::Result<_>>()?;
    let mut tags = conn.prepare("SELECT profile_id, tag FROM profile_tags ORDER BY tag COLLATE NOCASE")?;
    let pairs = tags.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for pair in pairs {
        let (pid, tag) = pair?;
        if let Some(p) = profiles.iter_mut().find(|p| p.id == pid) {
            p.fields.tags.push(tag);
        }
    }
    Ok(profiles)
}

pub fn get(conn: &Connection, id: &str) -> Result<Profile> {
    let p = conn
        .query_row(&format!("SELECT {COLUMNS} FROM profiles WHERE id = ?1"), [id], from_row)
        .optional()?
        .flatten()
        .ok_or(ProfileError::NotFound)?;
    let tags = conn
        .prepare("SELECT tag FROM profile_tags WHERE profile_id = ?1 ORDER BY tag COLLATE NOCASE")?
        .query_map([id], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    Ok(Profile { fields: ProfileFields { tags, ..p.fields }, ..p })
}

fn check_group(conn: &Connection, group_id: Option<&str>) -> Result<()> {
    match group_id {
        Some(g) if !group_exists(conn, g)? => {
            Err(ProfileError::Invalid(vec![FieldError { field: "groupId", message: "That folder no longer exists.".into() }]))
        }
        _ => Ok(()),
    }
}

fn write_tags(conn: &Connection, id: &str, tags: &[String]) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM profile_tags WHERE profile_id = ?1", [id])?;
    let mut ins = conn.prepare("INSERT INTO profile_tags (profile_id, tag) VALUES (?1, ?2)")?;
    for t in tags {
        ins.execute(params![id, t])?;
    }
    Ok(())
}

pub fn create(conn: &mut Connection, draft: &ProfileDraft) -> Result<Profile> {
    let f = draft.validate().map_err(ProfileError::Invalid)?;
    check_group(conn, f.group_id.as_deref())?;
    let id = uuid::Uuid::new_v4().to_string();
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO profiles (id, name, host, port, username, group_id, auth, identity_file, jump, start_dir,
             keepalive_secs, terminal_theme, color, icon, mac, reuse_password, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?16, ?17, ?15, ?15)",
        params![
            id,
            f.name,
            f.host.as_str(),
            f.port,
            f.username.as_ref().map(User::as_str),
            f.group_id,
            f.auth.as_str(),
            f.identity_file.as_ref().map(|p| p.to_string_lossy()),
            jump_spec(&f.jump),
            f.start_dir,
            f.keepalive_secs,
            f.terminal_theme,
            f.color,
            f.icon,
            now(),
            f.mac,
            f.reuse_password
        ],
    )?;
    write_tags(&tx, &id, &f.tags)?;
    tx.commit()?;
    get(conn, &id)
}

pub fn update(conn: &mut Connection, id: &str, draft: &ProfileDraft) -> Result<Profile> {
    let f = draft.validate().map_err(ProfileError::Invalid)?;
    check_group(conn, f.group_id.as_deref())?;
    let tx = conn.transaction()?;
    let n = tx.execute(
        "UPDATE profiles SET name = ?2, host = ?3, port = ?4, username = ?5, group_id = ?6, auth = ?7,
             identity_file = ?8, jump = ?9, start_dir = ?10, keepalive_secs = ?11, terminal_theme = ?12,
             color = ?13, icon = ?14, updated_at = ?15, mac = ?16, reuse_password = ?17
         WHERE id = ?1",
        params![
            id,
            f.name,
            f.host.as_str(),
            f.port,
            f.username.as_ref().map(User::as_str),
            f.group_id,
            f.auth.as_str(),
            f.identity_file.as_ref().map(|p| p.to_string_lossy()),
            jump_spec(&f.jump),
            f.start_dir,
            f.keepalive_secs,
            f.terminal_theme,
            f.color,
            f.icon,
            now(),
            f.mac,
            f.reuse_password
        ],
    )?;
    if n == 0 {
        return Err(ProfileError::NotFound);
    }
    write_tags(&tx, id, &f.tags)?;
    tx.commit()?;
    get(conn, id)
}

/// Deletes the profile and returns its secret reference, which the caller must
/// remove from the credential store.
pub fn delete(conn: &Connection, id: &str) -> Result<Option<String>> {
    let secret_ref: Option<Option<String>> =
        conn.query_row("SELECT secret_ref FROM profiles WHERE id = ?1", [id], |r| r.get(0)).optional()?;
    let secret_ref = secret_ref.ok_or(ProfileError::NotFound)?;
    conn.execute("DELETE FROM profiles WHERE id = ?1", [id])?;
    Ok(secret_ref)
}

fn update_one(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> Result<()> {
    match conn.execute(sql, params)? {
        0 => Err(ProfileError::NotFound),
        _ => Ok(()),
    }
}

pub fn set_favorite(conn: &Connection, id: &str, favorite: bool) -> Result<()> {
    update_one(conn, "UPDATE profiles SET favorite = ?2 WHERE id = ?1", params![id, favorite])
}

/// Security policy is changed only through this explicit call (never via a
/// draft or an import), so the UI can require confirmation.
pub fn set_legacy_crypto(conn: &Connection, id: &str, allow: bool) -> Result<()> {
    update_one(conn, "UPDATE profiles SET legacy_crypto = ?2 WHERE id = ?1", params![id, allow])
}

pub fn set_group(conn: &Connection, id: &str, group_id: Option<&str>) -> Result<()> {
    check_group(conn, group_id)?;
    update_one(conn, "UPDATE profiles SET group_id = ?2 WHERE id = ?1", params![id, group_id])
}

pub fn touch(conn: &Connection, id: &str) -> Result<()> {
    update_one(conn, "UPDATE profiles SET last_used_at = ?2 WHERE id = ?1", params![id, now()])
}

pub fn secret_ref(conn: &Connection, id: &str) -> Result<Option<String>> {
    conn.query_row("SELECT secret_ref FROM profiles WHERE id = ?1", [id], |r| r.get(0)).optional()?.ok_or(ProfileError::NotFound)
}

pub fn set_secret_ref(conn: &Connection, id: &str, secret_ref: Option<&str>) -> Result<()> {
    update_one(conn, "UPDATE profiles SET secret_ref = ?2 WHERE id = ?1", params![id, secret_ref])
}

// ---- folders ----

#[derive(Debug, Clone, Serialize)]
pub struct Group {
    pub id: String,
    pub name: String,
}

fn group_name(name: &str) -> Result<String> {
    let mut errs = Vec::new();
    match text(Some(name), 60, "name", &mut errs) {
        Some(n) => Ok(n),
        None if errs.is_empty() => Err(ProfileError::Invalid(vec![FieldError { field: "name", message: "Enter a folder name.".into() }])),
        None => Err(ProfileError::Invalid(errs)),
    }
}

fn group_exists(conn: &Connection, id: &str) -> rusqlite::Result<bool> {
    conn.query_row("SELECT 1 FROM groups WHERE id = ?1", [id], |_| Ok(())).optional().map(|o| o.is_some())
}

pub fn list_groups(conn: &Connection) -> Result<Vec<Group>> {
    let mut stmt = conn.prepare("SELECT id, name FROM groups ORDER BY sort, name COLLATE NOCASE")?;
    let groups = stmt.query_map([], |r| Ok(Group { id: r.get(0)?, name: r.get(1)? }))?.collect::<rusqlite::Result<_>>()?;
    Ok(groups)
}

pub fn create_group(conn: &Connection, name: &str) -> Result<Group> {
    let group = Group { id: uuid::Uuid::new_v4().to_string(), name: group_name(name)? };
    conn.execute("INSERT INTO groups (id, name) VALUES (?1, ?2)", params![group.id, group.name])?;
    Ok(group)
}

pub fn rename_group(conn: &Connection, id: &str, name: &str) -> Result<()> {
    update_one(conn, "UPDATE groups SET name = ?2 WHERE id = ?1", params![id, group_name(name)?])
}

/// Deleting a folder keeps its connections; they become ungrouped.
pub fn delete_group(conn: &Connection, id: &str) -> Result<()> {
    update_one(conn, "DELETE FROM groups WHERE id = ?1", [id])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::open_in_memory;

    fn draft(name: &str, host: &str) -> ProfileDraft {
        ProfileDraft { name: name.into(), host: host.into(), ..Default::default() }
    }

    #[test]
    fn validates_every_field() {
        let bad = ProfileDraft {
            name: " ".into(),
            host: "-oProxyCommand=x".into(),
            port: Some(70000),
            username: Some("a;b".into()),
            identity_file: Some("/k/%d".into()),
            jump: Some("x;y".into()),
            start_dir: Some("/a\0".into()),
            keepalive_secs: Some(9999),
            color: Some("neon".into()),
            icon: Some("<script>".into()),
            tags: vec!["line\nbreak".into()],
            mac: Some("not-a-mac".into()),
            ..Default::default()
        };
        let errs = bad.validate().unwrap_err();
        let mut fields: Vec<_> = errs.iter().map(|e| e.field).collect();
        fields.sort();
        fields.dedup();
        assert_eq!(
            fields,
            ["color", "host", "icon", "identityFile", "jump", "keepaliveSecs", "mac", "name", "port", "startDir", "tags", "username"]
        );
    }

    #[test]
    fn crud_roundtrip() {
        let mut conn = open_in_memory().unwrap();
        let g = create_group(&conn, "Home Lab").unwrap();
        let mut d = draft("NAS", "nas.lan");
        d.port = Some(2222);
        d.username = Some("admin".into());
        d.group_id = Some(g.id.clone());
        d.jump = Some("ops@bastion:22".into());
        d.tags = vec!["storage".into(), "storage".into(), " lab ".into()];
        d.color = Some("teal".into());
        d.mac = Some("B8-27-EB-12-34-56".into());
        d.reuse_password = Some(false);

        let p = create(&mut conn, &d).unwrap();
        assert_eq!(p.fields.port, Some(2222));
        assert_eq!(p.fields.tags, ["lab", "storage"]);
        assert_eq!(p.fields.jump[0].to_spec(), "ops@bastion:22");
        assert!(!p.has_saved_secret && !p.legacy_crypto);
        assert_eq!((p.fields.mac.as_deref(), p.fields.reuse_password), (Some("b8:27:eb:12:34:56"), Some(false)));

        d.name = "NAS 2".into();
        d.tags.clear();
        let p2 = update(&mut conn, &p.id, &d).unwrap();
        assert_eq!((p2.fields.name.as_str(), p2.fields.tags.len()), ("NAS 2", 0));

        set_favorite(&conn, &p.id, true).unwrap();
        delete_group(&conn, &g.id).unwrap();
        let listed = list(&conn).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].favorite);
        assert_eq!(listed[0].fields.group_id, None, "folder deletion keeps the connection");

        set_secret_ref(&conn, &p.id, Some("ref-1")).unwrap();
        assert_eq!(delete(&conn, &p.id).unwrap(), Some("ref-1".into()));
        assert!(matches!(get(&conn, &p.id), Err(ProfileError::NotFound)));
        assert!(matches!(update(&mut conn, "nope", &draft("x", "x")), Err(ProfileError::NotFound)));
    }

    #[test]
    fn unknown_group_is_a_field_error() {
        let mut conn = open_in_memory().unwrap();
        let mut d = draft("x", "x");
        d.group_id = Some("missing".into());
        assert!(matches!(create(&mut conn, &d), Err(ProfileError::Invalid(e)) if e[0].field == "groupId"));
    }

    #[test]
    fn tampered_rows_are_skipped() {
        let mut conn = open_in_memory().unwrap();
        create(&mut conn, &draft("ok", "ok.lan")).unwrap();
        conn.execute("INSERT INTO profiles (id, name, host, created_at, updated_at) VALUES ('evil', 'e', '-oProxyCommand=sh', 0, 0)", [])
            .unwrap();
        let names: Vec<_> = list(&conn).unwrap().into_iter().map(|p| p.fields.name).collect();
        assert_eq!(names, ["ok"]);
    }
}
