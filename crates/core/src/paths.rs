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

// Darwin Unix socket addresses are limited to 104 bytes. Application Support
// and the per-user temporary directory can exceed this limit before a socket
// filename is even appended. Ownership is checked by private_dir before use.
#[cfg(any(target_os = "macos", test))]
fn macos_runtime(uid: u32) -> PathBuf {
    Path::new("/tmp").join(format!("sc-{uid}"))
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
}

impl AppPaths {
    pub fn from_env() -> io::Result<Self> {
        if let Some(root) = std::env::var_os("SIMPLE_CONNECT_HOME") {
            let root = Path::new(&root);
            if !root.is_absolute() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "SIMPLE_CONNECT_HOME must be absolute"));
            }
            return Ok(Self::under(root));
        }
        let need = |d: Option<PathBuf>, what: &str| {
            d.map(|d| d.join(APP)).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot determine the {what} directory")))
        };
        let data = need(dirs::data_dir(), "data")?;
        #[cfg(target_os = "macos")]
        let runtime = macos_runtime(rustix::process::getuid().as_raw());
        #[cfg(not(target_os = "macos"))]
        let runtime = dirs::runtime_dir().map(|d| d.join(APP)).unwrap_or_else(|| data.join("run"));
        Ok(Self {
            config: need(dirs::config_dir(), "config")?,
            // state_dir/runtime_dir only exist on Linux; fall back inside data elsewhere.
            state: dirs::state_dir().map(|d| d.join(APP)).unwrap_or_else(|| data.join("state")),
            runtime,
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
    #[cfg(windows)]
    restrict_windows_path(dir)?;
    Ok(())
}

/// Replace all existing access entries with a protected, current-user-only
/// DACL. Directory entries inherit to newly created children, so private files
/// are protected from their creation rather than only after they are opened.
#[cfg(windows)]
#[allow(unsafe_code)] // Isolated Windows ACL FFI; callers receive a safe fallible API.
fn restrict_windows_path(path: &Path) -> io::Result<()> {
    use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
            SetNamedSecurityInfoW,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let metadata = fs::symlink_metadata(path)?;
    // Reject junctions and other reparse points as well as ordinary symlinks.
    if metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "private paths must not be reparse points"));
    }
    let sid = crate::ssh::helper::current_user_sid()?;
    // Elevated tokens can create objects owned by their TokenOwner group
    // (typically Administrators), rather than their TokenUser SID.
    let allowed_owners = [sid.clone(), crate::ssh::helper::current_owner_sid()?];
    let inheritance = if metadata.is_dir() { "OICI" } else { "" };
    let sddl: Vec<u16> = format!("D:P(A;{inheritance};FA;;;{sid})").encode_utf16().chain(Some(0)).collect();
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "private path contains NUL"));
    }
    wide.push(0);
    let mut owner = null_mut();
    let mut owner_descriptor = null_mut();
    // SAFETY: path and out-pointers remain live throughout the call. The owner
    // SID borrows the returned descriptor and is compared before it is freed.
    let owner_status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut owner_descriptor,
        )
    };
    if owner_status != 0 {
        return Err(io::Error::from_raw_os_error(owner_status as i32));
    }
    // SAFETY: conversion consumes a valid NUL-terminated SID and returns its
    // own allocation. Neither SID is accessed after its allocation is freed.
    let same_owner = unsafe {
        let matches = allowed_owners.iter().any(|sid| {
            let sid_wide: Vec<u16> = sid.encode_utf16().chain(Some(0)).collect();
            let mut current_sid = null_mut();
            let converted = ConvertStringSidToSidW(sid_wide.as_ptr(), &mut current_sid);
            let matches = converted != 0 && !owner.is_null() && EqualSid(owner, current_sid) != 0;
            if !current_sid.is_null() {
                LocalFree(current_sid);
            }
            matches
        });
        LocalFree(owner_descriptor);
        matches
    };
    if !same_owner {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "private path is owned by another user"));
    }
    let mut descriptor = null_mut();
    // SAFETY: Both strings are NUL terminated and the descriptor out-pointer is
    // writable. Successful conversion owns one LocalAlloc allocation.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    // SAFETY: descriptor is live for both ACL extraction and installation. The
    // ACL borrows descriptor; LocalFree is called only after installation ends.
    let result = unsafe {
        if GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) == 0 {
            Err(io::Error::last_os_error())
        } else if present == 0 || dacl.is_null() {
            Err(io::Error::other("private security descriptor has no DACL"))
        } else {
            let status = SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null(),
            );
            if status == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(status as i32)) }
        }
    };
    // SAFETY: descriptor came from the successful conversion above and has not
    // otherwise been freed. No pointer into it is used after this call.
    unsafe { LocalFree(descriptor) };
    result
}

/// Creates (or truncates) a 0600 file.
pub fn create_private(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    reject_windows_reparse(path)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let f = opts.open(path)?;
    // `mode` only applies on creation; tighten a pre-existing file too.
    #[cfg(unix)]
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    #[cfg(windows)]
    restrict_windows_path(path)?;
    Ok(f)
}

/// Creates `path` as an empty 0600 file if missing, or tightens an existing one.
/// Contents are left untouched.
pub fn ensure_private_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    reject_windows_reparse(path)?;
    let mut opts = fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let f = opts.open(path)?;
    #[cfg(unix)]
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    #[cfg(windows)]
    restrict_windows_path(path)?;
    drop(f);
    Ok(())
}

#[cfg(windows)]
fn reject_windows_reparse(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_attributes() & 0x400 != 0 => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "private paths must not be reparse points"))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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

    #[test]
    fn macos_socket_directory_is_short_and_user_specific() {
        let a = macos_runtime(501);
        let b = macos_runtime(502);
        assert_ne!(a, b);
        assert_eq!(a, Path::new("/tmp/sc-501"));
        assert!(a.join("helper-123456789.sock").as_os_str().len() < 104);
        assert!(!a.to_string_lossy().contains(' '));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn private_files_support_unicode_paths_and_atomic_replacement() {
        let root = tempfile::tempdir().unwrap();
        let paths = AppPaths::under(&root.path().join("User with spaces café"));
        paths.ensure().unwrap();
        let path = paths.data.join("known_hosts");
        write_private(&path, b"original").unwrap();
        ensure_private_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"original");
        write_private(&path, b"replacement").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
    }
}
