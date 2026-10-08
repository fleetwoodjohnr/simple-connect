//! Encrypted local vault, used when no OS keyring is available or the user
//! prefers a master password.
//!
//! Key derivation: Argon2id (64 MiB, 3 passes, 4 lanes, random 16-byte salt).
//! Encryption: XChaCha20-Poly1305 with a fresh random 24-byte nonce on every
//! write. File layout (integers little-endian):
//!
//! ```text
//! "SCVAULT1" | m_cost u32 | t_cost u32 | p_cost u32 | salt[16] | nonce[24] | ciphertext+tag
//! ```
//!
//! Everything before the ciphertext is authenticated as associated data, so the
//! parameters, salt and nonce can't be altered undetected. The plaintext is a
//! JSON object `{ id: secret }`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::{CredentialStore, SecretError};

const MAGIC: &[u8; 8] = b"SCVAULT1";
const HEADER_LEN: usize = 8 + 12 + 16 + 24;
const DEFAULT_PARAMS: (u32, u32, u32) = (64 * 1024, 3, 4);

struct Unlocked {
    key: Zeroizing<[u8; 32]>,
    params: (u32, u32, u32),
    salt: [u8; 16],
    entries: HashMap<String, SecretString>,
}

pub struct VaultStore {
    path: PathBuf,
    state: Mutex<Option<Unlocked>>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    b
}

fn derive(password: &SecretString, salt: &[u8; 16], (m, t, p): (u32, u32, u32)) -> Result<Zeroizing<[u8; 32]>, SecretError> {
    // Bound attacker-supplied parameters: a crafted file must not exhaust memory.
    if !(8 * 1024..=1024 * 1024).contains(&m) || !(1..=20).contains(&t) || !(1..=16).contains(&p) {
        return Err(SecretError::Vault("unsupported key-derivation parameters".into()));
    }
    let params = Params::new(m, t, p, Some(32)).map_err(|e| SecretError::Vault(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.expose_secret().as_bytes(), salt, key.as_mut())
        .map_err(|e| SecretError::Vault(e.to_string()))?;
    Ok(key)
}

fn header(magic: &[u8; 8], params: (u32, u32, u32), salt: &[u8; 16], nonce: &[u8; 24]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(magic);
    for v in [params.0, params.1, params.2] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out
}

fn seal_with_key(magic: &[u8; 8], key: &[u8; 32], params: (u32, u32, u32), salt: &[u8; 16], plain: &[u8]) -> Result<Vec<u8>, SecretError> {
    let nonce = random::<24>();
    let mut out = header(magic, params, salt, &nonce);
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: &out })
        .map_err(|_| SecretError::Vault("encryption failed".into()))?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Encrypts `plain` under a key derived from `password` (fresh salt and nonce).
/// Used for encrypted backups; same format as the vault with a different magic.
pub fn seal(magic: &[u8; 8], password: &SecretString, plain: &[u8]) -> Result<Vec<u8>, SecretError> {
    let salt = random::<16>();
    let key = derive(password, &salt, DEFAULT_PARAMS)?;
    seal_with_key(magic, &key, DEFAULT_PARAMS, &salt, plain)
}

/// Plaintext plus the key material needed to re-seal it.
type Opened = (Zeroizing<Vec<u8>>, Zeroizing<[u8; 32]>, (u32, u32, u32), [u8; 16]);

/// Decrypts data produced by [`seal`].
fn open_inner(magic: &[u8; 8], password: &SecretString, data: &[u8]) -> Result<Opened, SecretError> {
    if data.len() < HEADER_LEN + 16 || &data[..8] != magic {
        return Err(SecretError::Vault("unrecognised file format".into()));
    }
    let u32_at = |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    let params = (u32_at(8), u32_at(12), u32_at(16));
    let salt: [u8; 16] = data[20..36].try_into().map_err(|_| SecretError::Vault("corrupt header".into()))?;
    let key = derive(password, &salt, params)?;
    let plain = XChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(XNonce::from_slice(&data[36..HEADER_LEN]), Payload { msg: &data[HEADER_LEN..], aad: &data[..HEADER_LEN] })
        .map_err(|_| SecretError::WrongPassword)?;
    Ok((Zeroizing::new(plain), key, params, salt))
}

pub fn open(magic: &[u8; 8], password: &SecretString, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    open_inner(magic, password, data).map(|(plain, ..)| plain)
}

impl VaultStore {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_path_buf(), state: Mutex::new(None) }
    }

    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    pub fn is_unlocked(&self) -> bool {
        self.state.lock().is_ok_and(|s| s.is_some())
    }

    /// Creates an empty vault protected by `password` and leaves it unlocked.
    pub fn create(&self, password: &SecretString) -> Result<(), SecretError> {
        if self.exists() {
            return Err(SecretError::Vault("a vault already exists".into()));
        }
        let salt = random::<16>();
        let unlocked = Unlocked { key: derive(password, &salt, DEFAULT_PARAMS)?, params: DEFAULT_PARAMS, salt, entries: HashMap::new() };
        self.persist(&unlocked)?;
        *self.state.lock().map_err(|_| SecretError::Locked)? = Some(unlocked);
        Ok(())
    }

    pub fn unlock(&self, password: &SecretString) -> Result<(), SecretError> {
        let data = std::fs::read(&self.path).map_err(|e| SecretError::Vault(e.to_string()))?;
        let (plain, key, params, salt) = open_inner(MAGIC, password, &data)?;
        let raw: HashMap<String, String> = serde_json::from_slice(&plain).map_err(|e| SecretError::Vault(e.to_string()))?;
        let entries = raw.into_iter().map(|(k, v)| (k, SecretString::from(v))).collect();
        *self.state.lock().map_err(|_| SecretError::Locked)? = Some(Unlocked { key, params, salt, entries });
        Ok(())
    }

    /// Forgets the key and all decrypted secrets (zeroized on drop).
    pub fn lock(&self) {
        if let Ok(mut s) = self.state.lock() {
            *s = None;
        }
    }

    pub fn change_password(&self, old: &SecretString, new: &SecretString) -> Result<(), SecretError> {
        self.unlock(old)?;
        let mut guard = self.state.lock().map_err(|_| SecretError::Locked)?;
        let u = guard.as_mut().ok_or(SecretError::Locked)?;
        u.salt = random::<16>();
        u.params = DEFAULT_PARAMS;
        u.key = derive(new, &u.salt, u.params)?;
        self.persist(u)
    }

    fn persist(&self, u: &Unlocked) -> Result<(), SecretError> {
        let map: HashMap<&str, &str> = u.entries.iter().map(|(k, v)| (k.as_str(), v.expose_secret())).collect();
        let plain = Zeroizing::new(serde_json::to_vec(&map).map_err(|e| SecretError::Vault(e.to_string()))?);
        let out = seal_with_key(MAGIC, &u.key, u.params, &u.salt, &plain)?;
        crate::paths::write_private(&self.path, &out).map_err(|e| SecretError::Vault(e.to_string()))
    }

    fn with<T>(&self, f: impl FnOnce(&mut Unlocked) -> Result<T, SecretError>) -> Result<T, SecretError> {
        let mut guard = self.state.lock().map_err(|_| SecretError::Locked)?;
        f(guard.as_mut().ok_or(SecretError::Locked)?)
    }
}

impl CredentialStore for VaultStore {
    fn get(&self, id: &str) -> Result<Option<SecretString>, SecretError> {
        self.with(|u| Ok(u.entries.get(id).cloned()))
    }
    fn set(&self, id: &str, secret: &SecretString) -> Result<(), SecretError> {
        self.with(|u| {
            u.entries.insert(id.into(), secret.clone());
            self.persist(u)
        })
    }
    fn delete(&self, id: &str) -> Result<(), SecretError> {
        self.with(|u| {
            if u.entries.remove(id).is_some() {
                self.persist(u)?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from(s)
    }

    #[test]
    fn roundtrip_lock_and_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let v = VaultStore::new(&path);
        v.create(&pw("master pw")).unwrap();
        v.set("password:1", &pw("hunter2")).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(7).any(|w| w == b"hunter2"), "secret is not stored in plaintext");
        assert!(!raw.windows(10).any(|w| w == b"password:1"), "ids are encrypted too");

        v.lock();
        assert!(matches!(v.get("password:1"), Err(SecretError::Locked)));
        assert!(matches!(v.unlock(&pw("wrong")), Err(SecretError::WrongPassword)));
        v.unlock(&pw("master pw")).unwrap();
        assert_eq!(v.get("password:1").unwrap().unwrap().expose_secret(), "hunter2");

        v.change_password(&pw("master pw"), &pw("new pw")).unwrap();
        v.lock();
        assert!(v.unlock(&pw("master pw")).is_err());
        v.unlock(&pw("new pw")).unwrap();
        v.delete("password:1").unwrap();
        assert!(v.get("password:1").unwrap().is_none());
    }

    #[test]
    fn nonce_changes_on_every_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let v = VaultStore::new(&path);
        v.create(&pw("p")).unwrap();
        let a = std::fs::read(&path).unwrap()[36..HEADER_LEN].to_vec();
        v.set("x", &pw("y")).unwrap();
        let b = std::fs::read(&path).unwrap()[36..HEADER_LEN].to_vec();
        assert_ne!(a, b);
    }

    #[test]
    fn tampering_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let v = VaultStore::new(&path);
        v.create(&pw("p")).unwrap();
        v.set("x", &pw("y")).unwrap();
        let good = std::fs::read(&path).unwrap();
        for i in [20, 40, HEADER_LEN + 3, good.len() - 1] {
            let mut bad = good.clone();
            bad[i] ^= 1;
            std::fs::write(&path, &bad).unwrap();
            assert!(v.unlock(&pw("p")).is_err(), "flip at {i} must be detected");
        }
        // Sealed backups round-trip and reject the wrong password.
        let sealed = seal(b"SCBACKUP", &pw("backup pw"), b"payload").unwrap();
        assert_eq!(open(b"SCBACKUP", &pw("backup pw"), &sealed).unwrap().as_slice(), b"payload");
        assert!(open(b"SCBACKUP", &pw("nope"), &sealed).is_err());
        assert!(open(MAGIC, &pw("backup pw"), &sealed).is_err(), "magic is checked");

        // Absurd KDF parameters are rejected before deriving.
        let mut bad = good.clone();
        bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &bad).unwrap();
        assert!(matches!(v.unlock(&pw("p")), Err(SecretError::Vault(_))));
    }
}
