//! SSH key management through `ssh-keygen`. Private key material is never read
//! into the application except for the first line of the armour, which tells
//! whether the key is passphrase-protected.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::engine::Engine;
use super::known_hosts::fingerprint;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub path: PathBuf,
    pub key_type: String,
    pub fingerprint: String,
    pub comment: String,
    /// The full public key line, safe to show and copy.
    pub public_key: String,
    /// `None` when the private key file is missing or in an unknown format.
    pub encrypted: Option<bool>,
    /// FIDO2 / security-key backed (`sk-*`).
    pub hardware: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyKind {
    Ed25519,
    Ed25519Sk,
    Ecdsa,
    EcdsaSk,
    Rsa,
}

impl KeyKind {
    fn args(self) -> &'static [&'static str] {
        match self {
            KeyKind::Ed25519 => &["-t", "ed25519"],
            KeyKind::Ed25519Sk => &["-t", "ed25519-sk"],
            KeyKind::Ecdsa => &["-t", "ecdsa", "-b", "384"],
            KeyKind::EcdsaSk => &["-t", "ecdsa-sk"],
            KeyKind::Rsa => &["-t", "rsa", "-b", "4096"],
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Use a file name made of letters, digits, dots, dashes and underscores.")]
    BadName,
    #[error("A key named “{0}” already exists.")]
    Exists(String),
    #[error("The comment can't contain line breaks or be longer than 200 characters.")]
    BadComment,
    #[error("The passphrase was not accepted.")]
    WrongPassphrase,
    #[error("ssh-keygen failed: {0}")]
    Keygen(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn pub_path(private_path: &Path) -> PathBuf {
    let mut p = private_path.as_os_str().to_owned();
    p.push(".pub");
    p.into()
}

/// Reads `<key>.pub` (and peeks at the private key header) for one key.
pub fn read(private_path: &Path) -> Option<KeyInfo> {
    let line = std::fs::read_to_string(pub_path(private_path)).ok()?;
    let line = line.lines().next()?.trim().to_owned();
    let mut parts = line.splitn(3, ' ');
    let (key_type, blob) = (parts.next()?.to_owned(), parts.next()?);
    let comment = parts.next().unwrap_or_default().to_owned();
    Some(KeyInfo {
        path: private_path.to_path_buf(),
        fingerprint: fingerprint(blob)?,
        hardware: key_type.starts_with("sk-"),
        encrypted: is_encrypted(private_path),
        public_key: line.clone(),
        key_type,
        comment,
    })
}

/// Keys in `dir` (normally ~/.ssh): every `X` that has an `X.pub` next to it.
pub fn list(dir: &Path) -> Vec<KeyInfo> {
    let mut keys: Vec<KeyInfo> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let private = p.to_str()?.strip_suffix(".pub")?.to_owned();
            read(Path::new(&private))
        })
        .collect();
    keys.sort_by(|a, b| a.path.cmp(&b.path));
    keys
}

/// Whether the private key is passphrase-protected, from its header only.
fn is_encrypted(private_path: &Path) -> Option<bool> {
    use std::io::{BufRead, BufReader};
    let mut lines = BufReader::new(std::fs::File::open(private_path).ok()?).lines();
    let armour = lines.next()?.ok()?;
    if armour.contains("BEGIN OPENSSH PRIVATE KEY") {
        // "openssh-key-v1\0" then a length-prefixed cipher name ("none" if unencrypted).
        // Armour lines are 70 characters; decode the longest whole-quantum prefix.
        let line = lines.next()?.ok()?;
        let line = line.trim();
        let first = STANDARD.decode(&line[..line.len() / 4 * 4]).ok()?;
        let rest = first.strip_prefix(b"openssh-key-v1\0")?;
        let n = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        return Some(rest.get(4..4 + n)? != b"none");
    }
    if armour.starts_with("-----BEGIN") {
        // Legacy PEM marks encryption with a Proc-Type header.
        return Some(lines.next()?.ok()?.contains("ENCRYPTED"));
    }
    None
}

fn check_name(name: &str) -> Result<(), KeyError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with(['.', '-'])
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok { Ok(()) } else { Err(KeyError::BadName) }
}

fn keygen_error(out: &std::process::Output) -> KeyError {
    let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if err.contains("incorrect passphrase") || err.contains("Load key") { KeyError::WrongPassphrase } else { KeyError::Keygen(err) }
}

impl Engine {
    fn ssh_dir(&self) -> Result<PathBuf, KeyError> {
        let dir = self.home().ok_or_else(|| KeyError::Keygen("no home directory".into()))?.join(".ssh");
        crate::paths::private_dir(&dir)?;
        Ok(dir)
    }

    /// Generates a key in ~/.ssh. Security-key types ask the user to touch the
    /// key (and maybe enter a PIN) through the normal prompt flow.
    pub async fn generate_key(&self, kind: KeyKind, name: &str, comment: &str, passphrase: SecretString) -> Result<KeyInfo, KeyError> {
        check_name(name)?;
        if comment.len() > 200 || comment.chars().any(char::is_control) {
            return Err(KeyError::BadComment);
        }
        let path = self.ssh_dir()?.join(name);
        if path.exists() || pub_path(&path).exists() {
            return Err(KeyError::Exists(name.into()));
        }
        let mut args: Vec<OsString> = vec!["-q".into()];
        args.extend(kind.args().iter().map(OsString::from));
        args.extend(["-C".into(), comment.into(), "-f".into(), path.clone().into()]);
        // Asked twice: "Enter passphrase" and "Enter same passphrase again".
        let out = self.run_keygen(&args, vec![passphrase.clone(), passphrase]).await?;
        if !out.status.success() {
            return Err(keygen_error(&out));
        }
        read(&path).ok_or_else(|| KeyError::Keygen("the new key could not be read".into()))
    }

    pub async fn change_passphrase(&self, path: &Path, old: SecretString, new: SecretString) -> Result<(), KeyError> {
        let args: Vec<OsString> = vec!["-p".into(), "-f".into(), path.into()];
        let answers = if is_encrypted(path) == Some(true) { vec![old, new.clone(), new] } else { vec![new.clone(), new] };
        let out = self.run_keygen(&args, answers).await?;
        if out.status.success() { Ok(()) } else { Err(keygen_error(&out)) }
    }

    /// Copies a private key into ~/.ssh (0600) and writes its public half.
    pub async fn import_key(&self, src: &Path, name: &str, passphrase: SecretString) -> Result<KeyInfo, KeyError> {
        check_name(name)?;
        let dest = self.ssh_dir()?.join(name);
        if dest.exists() {
            return Err(KeyError::Exists(name.into()));
        }
        // Derive the public key first: proves the file is a key (and the passphrase right).
        let out = self.run_keygen(&["-y".into(), "-f".into(), src.into()], vec![passphrase]).await?;
        if !out.status.success() {
            return Err(keygen_error(&out));
        }
        let bytes = zeroize::Zeroizing::new(std::fs::read(src)?);
        crate::paths::write_private(&dest, &bytes)?;
        std::fs::write(pub_path(&dest), &out.stdout)?;
        read(&dest).ok_or_else(|| KeyError::Keygen("the imported key could not be read".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(check_name("id_ed25519_work").is_ok());
        for bad in ["", "../x", "a/b", ".hidden", "-x", "a b", "ü"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn reads_keys_and_encryption_state() {
        let dir = tempfile::tempdir().unwrap();
        for (name, pass) in [("plain", ""), ("locked", "pw")] {
            let st = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-C", "c", "-N", pass, "-f"])
                .arg(dir.path().join(name))
                .status()
                .unwrap();
            assert!(st.success());
        }
        let keys = list(dir.path());
        assert_eq!(keys.len(), 2);
        let locked = keys.iter().find(|k| k.path.ends_with("locked")).unwrap();
        let plain = keys.iter().find(|k| k.path.ends_with("plain")).unwrap();
        assert_eq!((locked.encrypted, plain.encrypted), (Some(true), Some(false)));
        assert_eq!(plain.key_type, "ssh-ed25519");
        assert!(plain.fingerprint.starts_with("SHA256:") && !plain.hardware);
    }
}
