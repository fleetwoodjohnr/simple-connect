//! Host-key decisions for the `KnownHostsCommand` helper.
//!
//! `ssh` accepts a key if it matches *any* known_hosts source, including lines
//! printed by the helper. The helper is therefore the point where a changed key
//! could be silently accepted, so it checks every file `ssh` reads and only ever
//! prints a key the user explicitly trusted.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// A host key offered by a server, as reported by `ssh` through `%H %t %K`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferedKey {
    /// known_hosts name: `host` or `[host]:port`.
    pub host: String,
    pub key_type: String,
    pub key_b64: String,
}

impl OfferedKey {
    /// Validates helper arguments before they are written to a known_hosts file
    /// (a newline or space here would inject extra entries).
    pub fn parse(host: &str, key_type: &str, key_b64: &str) -> Option<Self> {
        let host_ok = !host.is_empty() && host.len() <= 300 && !host.chars().any(|c| c.is_whitespace() || c.is_control() || c == ',');
        let type_ok = !key_type.is_empty()
            && key_type.len() <= 64
            && key_type.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'@' | b'.'));
        // The blob starts with its own algorithm name (RFC 4253 §6.6); it must match.
        let key_ok = key_b64.len() <= 16_384
            && STANDARD.decode(key_b64).is_ok_and(|blob| {
                let n = blob.get(..4).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize);
                blob.get(4..4 + n) == Some(key_type.as_bytes())
            });
        (host_ok && type_ok && key_ok).then(|| Self { host: host.into(), key_type: key_type.into(), key_b64: key_b64.into() })
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.key_b64).unwrap_or_default()
    }

    pub fn line(&self) -> String {
        format!("{} {} {}", self.host, self.key_type, self.key_b64)
    }

    /// Certificates are verified by `ssh` against `@cert-authority` entries.
    pub fn is_certificate(&self) -> bool {
        self.key_type.ends_with("-cert-v01@openssh.com")
    }
}

/// OpenSSH-style `SHA256:<base64, no padding>` fingerprint of a base64 key blob.
pub fn fingerprint(key_b64: &str) -> Option<String> {
    let blob = STANDARD.decode(key_b64.trim()).ok()?;
    Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob))))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownKey {
    pub key_type: String,
    pub fingerprint: String,
    pub file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum HostKeyStatus {
    Known,
    Unknown,
    Changed { previous: Vec<KnownKey> },
    Revoked,
}

/// Every known_hosts file `ssh` reads under the generated config.
pub fn sources(app_known_hosts: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = vec![app_known_hosts.to_path_buf()];
    if let Some(h) = home {
        v.push(h.join(".ssh/known_hosts"));
    }
    v.push("/etc/ssh/ssh_known_hosts".into());
    v.push("/etc/ssh/ssh_known_hosts2".into());
    v
}

struct Entry {
    marker: Option<String>,
    key_type: String,
    key_b64: String,
    file: PathBuf,
}

/// Uses `ssh-keygen -F`, which handles hashed names, `[host]:port` and patterns.
fn lookup(keygen: &Path, files: &[PathBuf], host: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    for file in files.iter().filter(|f| f.is_file()) {
        let Ok(out) = Command::new(keygen).arg("-F").arg(host).arg("-f").arg(file).output() else { continue };
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let first = parts.next().unwrap_or_default();
            let marker = first.starts_with('@').then(|| first.to_owned());
            if marker.is_some() {
                parts.next(); // host pattern after the marker
            }
            if let (Some(t), Some(k)) = (parts.next(), parts.next()) {
                entries.push(Entry { marker, key_type: t.into(), key_b64: k.into(), file: file.clone() });
            }
        }
    }
    entries
}

pub fn check(keygen: &Path, files: &[PathBuf], key: &OfferedKey) -> HostKeyStatus {
    let entries = lookup(keygen, files, &key.host);
    if entries.iter().any(|e| e.marker.as_deref() == Some("@revoked") && e.key_b64 == key.key_b64) {
        return HostKeyStatus::Revoked;
    }
    let plain: Vec<&Entry> = entries.iter().filter(|e| e.marker.is_none()).collect();
    if plain.iter().any(|e| e.key_b64 == key.key_b64) {
        return HostKeyStatus::Known;
    }
    if plain.is_empty() {
        return HostKeyStatus::Unknown;
    }
    HostKeyStatus::Changed {
        previous: plain
            .iter()
            .map(|e| KnownKey {
                key_type: e.key_type.clone(),
                fingerprint: fingerprint(&e.key_b64).unwrap_or_default(),
                file: e.file.clone(),
            })
            .collect(),
    }
}

/// Records a trusted key in the app's known_hosts file.
pub fn trust(app_known_hosts: &Path, key: &OfferedKey) -> std::io::Result<()> {
    crate::paths::ensure_private_file(app_known_hosts)?;
    let mut f = std::fs::OpenOptions::new().append(true).open(app_known_hosts)?;
    writeln!(f, "{}", key.line())
}

/// Removes every entry for `host` from `file` (OpenSSH keeps a `.old` backup).
pub fn forget(keygen: &Path, file: &Path, host: &str) -> std::io::Result<()> {
    if !file.is_file() {
        return Ok(());
    }
    let out = Command::new(keygen).arg("-R").arg(host).arg("-f").arg(file).output()?;
    if out.status.success() { Ok(()) } else { Err(std::io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_owned())) }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedHost {
    pub host: String,
    pub key_type: String,
    pub fingerprint: String,
}

/// Entries of the app's own (unhashed) known_hosts file, for the settings page.
pub fn list(app_known_hosts: &Path) -> Vec<TrustedHost> {
    std::fs::read_to_string(app_known_hosts)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('@'))
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            let (host, key_type, key) = (p.next()?, p.next()?, p.next()?);
            Some(TrustedHost { host: host.into(), key_type: key_type.into(), fingerprint: fingerprint(key)? })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIK4SRKnlQCejQkj52bLe3gZ6LBxCBX2JdOaWKhc2o0mF";
    const OTHER: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILL8w4g27VcZEW/ICpN0y72jIQQIfdmUHTVj/o5o33cC";

    fn keygen() -> PathBuf {
        super::super::openssh::OpenSsh::discover().unwrap().keygen
    }

    #[test]
    fn fingerprint_matches_openssh() {
        // Value printed by `ssh -v` for this key: "Server host key: ssh-ed25519 SHA256:RaNA…".
        assert_eq!(fingerprint(KEY).unwrap(), "SHA256:RaNAkPS+Ojr7MtUl1EZCX+pKlFEA5XXGGfb+93d2LOo");
    }

    #[test]
    fn rejects_injection_in_helper_args() {
        assert!(OfferedKey::parse("[h]:2222", "ssh-ed25519", KEY).is_some());
        assert!(OfferedKey::parse("h\nevil", "ssh-ed25519", KEY).is_none());
        assert!(OfferedKey::parse("h evil", "ssh-ed25519", KEY).is_none());
        assert!(OfferedKey::parse("h", "ssh ed25519", KEY).is_none());
        assert!(OfferedKey::parse("h", "ssh-ed25519", "not base64!").is_none());
        assert!(OfferedKey::parse("h", "ssh-ed25519", "NONE").is_none());
        assert!(OfferedKey::parse("h", "ssh-rsa", KEY).is_none(), "type must match the blob");
    }

    #[test]
    fn unknown_known_changed_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("known_hosts");
        let user = dir.path().join("user_known_hosts");
        let files = vec![app.clone(), user.clone()];
        let kg = keygen();
        let offered = OfferedKey::parse("[127.0.0.1]:2222", "ssh-ed25519", KEY).unwrap();

        assert!(matches!(check(&kg, &files, &offered), HostKeyStatus::Unknown));
        trust(&app, &offered).unwrap();
        assert!(matches!(check(&kg, &files, &offered), HostKeyStatus::Known));

        // A different key for the same host in the user's file → changed.
        std::fs::write(&user, format!("[127.0.0.1]:2222 ssh-ed25519 {OTHER}\n")).unwrap();
        forget(&kg, &app, "[127.0.0.1]:2222").unwrap();
        match check(&kg, &files, &offered) {
            HostKeyStatus::Changed { previous } => assert_eq!(previous[0].fingerprint, fingerprint(OTHER).unwrap()),
            s => panic!("expected changed, got {s:?}"),
        }

        std::fs::write(&user, format!("@revoked * ssh-ed25519 {KEY}\n")).unwrap();
        assert!(matches!(check(&kg, &files, &offered), HostKeyStatus::Revoked));
        assert_eq!(list(&app).len(), 0);
    }
}
