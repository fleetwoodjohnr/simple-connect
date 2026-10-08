//! Application directories with restrictive permissions.
//!
//! | dir     | Linux default                         | holds                         |
//! |---------|---------------------------------------|-------------------------------|
//! | config  | ~/.config/simple-connect              | reserved for user-editable config |
//! | data    | ~/.local/share/simple-connect         | app.db, known_hosts, vault.bin |
//! | state   | ~/.local/state/simple-connect         | logs                          |
//! | runtime | $XDG_RUNTIME_DIR/simple-connect       | control sockets, generated ssh configs |
//!
//! Every directory is 0700; files written through [`write_private`] are 0600.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const APP: &str = "simple-connect";

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
}

impl AppPaths {
    pub fn from_env() -> io::Result<Self> {
        let need = |d: Option<PathBuf>, what: &str| {
            d.map(|d| d.join(APP)).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot determine the {what} directory")))
        };
        let data = need(dirs::data_dir(), "data")?;
        Ok(Self {
            config: need(dirs::config_dir(), "config")?,
            // state_dir/runtime_dir only exist on Linux; fall back inside data elsewhere.
            state: dirs::state_dir().map(|d| d.join(APP)).unwrap_or_else(|| data.join("state")),
            runtime: dirs::runtime_dir().map(|d| d.join(APP)).unwrap_or_else(|| data.join("run")),
            data,
        })
    }

    /// All directories under one root, for tests.
    pub fn under(root: &Path) -> Self {
        Self { config: root.join("config"), data: root.join("data"), state: root.join("state"), runtime: root.join("run") }
    }

    pub fn ensure(&self) -> io::Result<()> {
        for d in [&self.config, &self.data, &self.state, &self.runtime, &self.logs()] {
            private_dir(d)?;
        }
        Ok(())
    }

    pub fn logs(&self) -> PathBuf {
        self.state.join("logs")
    }
}

/// Creates `dir` (and parents) and makes it 0700. Refuses a symlink or a
/// directory owned by another user, so a pre-planted path can't redirect our files.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = fs::symlink_metadata(dir)?;
        if !meta.is_dir() {
            return Err(io::Error::other(format!("{} is not a directory", dir.display())));
        }
        if meta.uid() != rustix::process::getuid().as_raw() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is owned by another user", dir.display())));
        }
        if meta.mode() & 0o777 != 0o700 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    // ponytail: Windows ACL hardening lands with the Windows port; %APPDATA% is per-user already.
    Ok(())
}

/// Creates (or truncates) a 0600 file.
pub fn create_private(path: &Path) -> io::Result<File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let f = opts.open(path)?;
    // `mode` only applies on creation; tighten a pre-existing file too.
    #[cfg(unix)]
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(f)
}

/// Creates `path` as an empty 0600 file if missing, or tightens an existing one.
/// Contents are left untouched.
pub fn ensure_private_file(path: &Path) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let f = opts.open(path)?;
    #[cfg(unix)]
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(())
}

/// Atomically replaces `path` with `bytes` (0600 temp file in the same dir, fsync, rename).
/// A crash leaves either the old or the new contents, never a torn file.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().ok_or_else(|| io::Error::other("path has no parent"))?;
    let name = path.file_name().ok_or_else(|| io::Error::other("path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp-{}-{}", name.to_string_lossy(), std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
    let result = (|| {
        let mut f = create_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn dirs_and_files_are_private() {
        let root = tempfile::tempdir().unwrap();
        let paths = AppPaths::under(root.path());
        paths.ensure().unwrap();
        assert_eq!(mode(&paths.data), 0o700);
        assert_eq!(mode(&paths.logs()), 0o700);

        // An existing, too-open directory is tightened.
        fs::set_permissions(&paths.config, fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&paths.config).unwrap();
        assert_eq!(mode(&paths.config), 0o700);

        let f = paths.data.join("known_hosts");
        write_private(&f, b"one").unwrap();
        write_private(&f, b"two").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"two");
        assert_eq!(mode(&f), 0o600);
        assert_eq!(fs::read_dir(&paths.data).unwrap().count(), 1, "no temp files left behind");
    }

    #[test]
    fn refuses_symlinked_dir() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("elsewhere");
        fs::create_dir(&target).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(private_dir(&link).is_err());
    }
}
