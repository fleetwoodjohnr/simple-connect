//! Secret storage. Secrets never enter SQLite or logs: profiles hold an opaque
//! `secret_ref`, and the value lives in a [`CredentialStore`].

pub mod lock;
pub mod session_watch;
pub mod vault;

use std::collections::HashMap;
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("Simple Connect is locked. Unlock it to use saved passwords.")]
    Locked,
    #[error("The system keyring is unavailable: {0}")]
    Keyring(String),
    #[error("The encrypted vault couldn't be read or written: {0}")]
    Vault(String),
    #[error("The password is incorrect.")]
    WrongPassword,
}

/// Where secrets are kept. Implementations: [`KeyringStore`] (the OS keyring),
/// [`vault::VaultStore`] (encrypted file) and [`MemoryStore`] (tests).
pub trait CredentialStore: Send + Sync {
    fn get(&self, id: &str) -> Result<Option<SecretString>, SecretError>;
    fn set(&self, id: &str, secret: &SecretString) -> Result<(), SecretError>;
    fn delete(&self, id: &str) -> Result<(), SecretError>;
}

/// Id for a profile's saved password.
pub fn new_password_ref() -> String {
    format!("password:{}", uuid::Uuid::new_v4())
}

/// Ids of a profile's remote desktop passwords: a VNC password and an account
/// password (RDP, macOS) differ, so each kind is kept apart under the profile's reference.
pub fn desktop_secret_id(base: &str, account: bool) -> String {
    format!("{base}:{}", if account { "account" } else { "vnc" })
}

/// Id for a key file's saved passphrase (deterministic per path, no lookup table).
pub fn passphrase_ref(key_path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key_path.to_string_lossy().as_bytes());
    format!("passphrase:{}", digest.iter().take(16).map(|b| format!("{b:02x}")).collect::<String>())
}

const SERVICE: &str = "dev.simpleconnect.client";

/// OS keyring: Secret Service (GNOME Keyring, KWallet) on Linux. Windows
/// Credential Manager and macOS Keychain plug in here through their
/// keyring-core stores with the Windows/macOS ports.
pub struct KeyringStore;

impl KeyringStore {
    /// Connects to the platform keyring; fails if none is running.
    pub fn connect() -> Result<Self, SecretError> {
        #[cfg(target_os = "linux")]
        {
            let store = zbus_secret_service_keyring_store::Store::new().map_err(|e| SecretError::Keyring(e.to_string()))?;
            keyring_core::set_default_store(store);
            Ok(KeyringStore)
        }
        #[cfg(not(target_os = "linux"))]
        Err(SecretError::Keyring("no keyring backend for this platform yet".into()))
    }

    fn entry(id: &str) -> Result<keyring_core::Entry, SecretError> {
        keyring_core::Entry::new(SERVICE, id).map_err(|e| SecretError::Keyring(e.to_string()))
    }
}

impl CredentialStore for KeyringStore {
    fn get(&self, id: &str) -> Result<Option<SecretString>, SecretError> {
        match Self::entry(id)?.get_password() {
            Ok(p) => Ok(Some(SecretString::from(p))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretError::Keyring(e.to_string())),
        }
    }
    fn set(&self, id: &str, secret: &SecretString) -> Result<(), SecretError> {
        Self::entry(id)?.set_password(secret.expose_secret()).map_err(|e| SecretError::Keyring(e.to_string()))
    }
    fn delete(&self, id: &str) -> Result<(), SecretError> {
        match Self::entry(id)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretError::Keyring(e.to_string())),
        }
    }
}

/// In-memory store for tests.
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, SecretString>>);

impl CredentialStore for MemoryStore {
    fn get(&self, id: &str) -> Result<Option<SecretString>, SecretError> {
        Ok(self.0.lock().map_err(|_| SecretError::Locked)?.get(id).cloned())
    }
    fn set(&self, id: &str, secret: &SecretString) -> Result<(), SecretError> {
        self.0.lock().map_err(|_| SecretError::Locked)?.insert(id.into(), secret.clone());
        Ok(())
    }
    fn delete(&self, id: &str) -> Result<(), SecretError> {
        self.0.lock().map_err(|_| SecretError::Locked)?.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_are_stable_and_opaque() {
        let a = passphrase_ref(std::path::Path::new("/home/u/.ssh/id_ed25519"));
        assert_eq!(a, passphrase_ref(std::path::Path::new("/home/u/.ssh/id_ed25519")));
        assert!(!a.contains("home"), "the path itself is not exposed in the keyring");
        assert_ne!(new_password_ref(), new_password_ref());
    }

    /// Exercises the real Secret Service when available (developer desktops).
    #[test]
    #[ignore = "needs a running Secret Service"]
    fn keyring_roundtrip() {
        let store = KeyringStore::connect().unwrap();
        let id = format!("test:{}", uuid::Uuid::new_v4());
        assert!(store.get(&id).unwrap().is_none());
        store.set(&id, &SecretString::from("s3cret")).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap().expose_secret(), "s3cret");
        store.delete(&id).unwrap();
        assert!(store.get(&id).unwrap().is_none());
    }
}
