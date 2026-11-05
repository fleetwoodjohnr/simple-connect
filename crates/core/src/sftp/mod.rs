//! SFTP over the connection's ControlMaster (`ssh -S <socket> -s <host> sftp`):
//! no second authentication, and the protocol is spoken in-process.
//!
//! Remote paths are POSIX-style strings (Windows OpenSSH servers use `/C:/…`).
//! Names from remote listings are untrusted: they are only joined onto local
//! paths through [`crate::validate::join_local`].

pub mod local;
pub mod transfer;

use std::path::Path;
use std::process::Stdio;

use futures_util::StreamExt;
use openssh_sftp_client::metadata::{MetaData, Permissions, RawPermissions};
use openssh_sftp_client::{Sftp, SftpOptions};
use serde::Serialize;
use tokio::process::{Child, Command};

use crate::ssh::mux::{Destination, Master};
use crate::ssh::openssh::OpenSsh;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    /// For symlinks: whether the target is a directory (so it can be opened).
    pub target_is_dir: bool,
    pub size: u64,
    /// Seconds since the Unix epoch.
    pub modified: Option<u64>,
    /// Unix permission bits (e.g. 0o755), when known.
    pub mode: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum SftpError {
    #[error("The file browser couldn't start: {0}")]
    Start(String),
    #[error("{0}")]
    Remote(String),
    #[error("The path isn't valid.")]
    InvalidPath,
    #[error("{0}")]
    Local(#[from] std::io::Error),
    #[error("The file is larger than the {0} MB editor limit.")]
    TooLarge(u64),
    #[error("Transfer cancelled.")]
    Cancelled,
}

impl From<openssh_sftp_client::Error> for SftpError {
    fn from(e: openssh_sftp_client::Error) -> Self {
        use openssh_sftp_client::Error as E;
        use openssh_sftp_client::error::SftpErrorKind as K;
        let msg = match &e {
            E::SftpError(K::NoSuchFile, _) => "The file or folder no longer exists.".to_owned(),
            E::SftpError(K::PermDenied, _) => "Permission denied on the server.".to_owned(),
            E::SftpError(_, m) => format!("The server reported: {m}"),
            _ => format!("The SFTP connection failed: {e}"),
        };
        SftpError::Remote(msg)
    }
}

pub type Result<T> = std::result::Result<T, SftpError>;

pub fn remote_join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

pub fn remote_parent(path: &str) -> String {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => "/".into(),
        Some((parent, _)) => parent.into(),
    }
}

fn entry_from(name: String, meta: &MetaData) -> Entry {
    let ft = meta.file_type();
    let kind = match ft {
        Some(t) if t.is_dir() => EntryKind::Dir,
        Some(t) if t.is_file() => EntryKind::File,
        Some(t) if t.is_symlink() => EntryKind::Symlink,
        _ => EntryKind::Other,
    };
    Entry {
        name,
        kind,
        target_is_dir: kind == EntryKind::Dir,
        size: meta.len().unwrap_or(0),
        modified: meta.modified().map(|t| u64::from(t.into_raw())),
        mode: meta.permissions().map(|p| p.as_raw().bits() & 0o7777),
    }
}

/// One SFTP session riding on a master connection.
pub struct RemoteFs {
    pub sftp: Sftp,
    _child: std::sync::Arc<tokio::sync::Mutex<Child>>,
    pub home: String,
}

impl RemoteFs {
    pub async fn open(ossh: &OpenSsh, master: &Master, dest: &Destination) -> Result<RemoteFs> {
        let mut args = master.client_args(dest);
        args.extend(["-s".into(), "--".into(), dest.host.as_str().into(), "sftp".into()]);
        let mut child = Command::new(&ossh.ssh)
            .args(args)
            .envs(master.env.clone())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| SftpError::Start(e.to_string()))?;
        let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let (Some(stdin), Some(stdout)) = (stdin, stdout) else { return Err(SftpError::Start("no pipes".into())) };
        let child = std::sync::Arc::new(tokio::sync::Mutex::new(child));
        let weak_child = std::sync::Arc::downgrade(&child);
        let mut exited = master.exit_signal();
        tokio::spawn(async move {
            while !*exited.borrow() {
                if exited.changed().await.is_err() {
                    break;
                }
            }
            if let Some(child) = weak_child.upgrade() {
                let mut child = child.lock().await;
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        });
        let sftp = Sftp::new(stdin, stdout, SftpOptions::default()).await.map_err(|e| SftpError::Start(e.to_string()))?;
        let home = sftp.fs().canonicalize(".").await?.to_string_lossy().into_owned();
        Ok(RemoteFs { sftp, _child: child, home })
    }

    pub async fn list(&self, dir: &str) -> Result<Vec<Entry>> {
        let mut fs = self.sftp.fs();
        let read = fs.open_dir(dir).await?.read_dir();
        let mut read = std::pin::pin!(read);
        let mut out = Vec::new();
        while let Some(item) = read.next().await {
            let item = item?;
            let name = item.filename().to_string_lossy().into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let mut e = entry_from(name, &item.metadata());
            if e.kind == EntryKind::Symlink {
                e.target_is_dir = fs.metadata(remote_join(dir, &e.name)).await.is_ok_and(|m| m.file_type().is_some_and(|t| t.is_dir()));
            }
            out.push(e);
        }
        Ok(out)
    }

    pub async fn stat(&self, path: &str) -> Result<Entry> {
        let meta = self.sftp.fs().metadata(path).await?;
        let name = path.rsplit('/').next().unwrap_or(path).to_owned();
        Ok(entry_from(name, &meta))
    }

    pub async fn exists(&self, path: &str) -> bool {
        self.sftp.fs().symlink_metadata(path).await.is_ok()
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        Ok(self.sftp.fs().create_dir(path).await?)
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        Ok(self.sftp.fs().rename(from, to).await?)
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        let perm = Permissions::from_raw(RawPermissions::from_bits_truncate(mode & 0o7777));
        Ok(self.sftp.fs().set_permissions(path, perm).await?)
    }

    /// Deletes a file, or a directory tree (depth-first, without following symlinks).
    pub async fn remove(&self, path: &str) -> Result<()> {
        let mut fs = self.sftp.fs();
        let meta = fs.symlink_metadata(path).await?;
        if !meta.file_type().is_some_and(|t| t.is_dir()) {
            return Ok(fs.remove_file(path).await?);
        }
        let mut stack = vec![(path.to_owned(), false)];
        while let Some((dir, visited)) = stack.pop() {
            if visited {
                fs.remove_dir(&dir).await?;
                continue;
            }
            stack.push((dir.clone(), true));
            for e in self.list(&dir).await? {
                let child = remote_join(&dir, &e.name);
                if e.kind == EntryKind::Dir {
                    stack.push((child, false));
                } else {
                    fs.remove_file(&child).await?;
                }
            }
        }
        Ok(())
    }

    /// Reads a whole file for the editor, refusing anything over `limit` bytes.
    pub async fn read_limited(&self, path: &str, limit: u64) -> Result<Vec<u8>> {
        let size = self.stat(path).await?.size;
        if size > limit {
            return Err(SftpError::TooLarge(limit / 1_000_000));
        }
        Ok(self.sftp.fs().read(path).await?.to_vec())
    }

    /// Saves editor contents: writes a temporary file next to the target, copies
    /// the original mode, then renames over it, so a failure never leaves a
    /// half-written file.
    pub async fn write_atomic(&self, path: &str, data: &[u8]) -> Result<()> {
        let mode = self.stat(path).await.ok().and_then(|e| e.mode);
        let name = path.rsplit('/').next().unwrap_or("file");
        let tmp = remote_join(&remote_parent(path), &format!(".{name}.sc-save-{}", &crate::ssh::helper::random_token()[..8]));
        let mut fs = self.sftp.fs();
        fs.write(&tmp, data).await?;
        if let Some(m) = mode {
            let _ = self.chmod(&tmp, m).await;
        }
        let renamed = if self.sftp.support_posix_rename() {
            fs.rename(&tmp, path).await
        } else {
            // Plain SFTP rename refuses to replace; this fallback is not atomic.
            let _ = fs.remove_file(path).await;
            fs.rename(&tmp, path).await
        };
        if renamed.is_err() {
            let _ = fs.remove_file(&tmp).await;
        }
        Ok(renamed?)
    }
}

/// True if `p` resolves inside one of the app's private directories.
/// Symlinks are resolved on both sides, so a link pointing into the app's data
/// can't be used to reach it. For a path that doesn't exist yet, its parent is resolved.
pub fn is_app_private(p: &Path, paths: &crate::paths::AppPaths) -> bool {
    let canon = |x: &Path| std::fs::canonicalize(x).ok();
    let target = canon(p).or_else(|| Some(canon(p.parent()?)?.join(p.file_name()?)));
    [&paths.config, &paths.data, &paths.state, &paths.runtime]
        .iter()
        .any(|d| p.starts_with(d) || matches!((&target, canon(d)), (Some(t), Some(cd)) if t.starts_with(&cd)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_paths() {
        assert_eq!(remote_join("/home/u", "a b"), "/home/u/a b");
        assert_eq!(remote_join("/", "etc"), "/etc");
        assert_eq!(remote_parent("/home/u/file"), "/home/u");
        assert_eq!(remote_parent("/home"), "/");
        assert_eq!(remote_parent("/"), "/");
        assert_eq!(remote_parent("/C:/Users/x/"), "/C:/Users");
    }

    #[cfg(unix)]
    #[test]
    fn private_data_cannot_be_reached_through_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let paths = crate::paths::AppPaths::under(&root.path().join("app"));
        paths.ensure().unwrap();
        let link = root.path().join("innocent");
        std::os::unix::fs::symlink(&paths.data, &link).unwrap();
        assert!(is_app_private(&paths.data.join("app.db"), &paths));
        assert!(is_app_private(&link, &paths));
        assert!(is_app_private(&link.join("app.db"), &paths), "new file under a linked dir");
        assert!(!is_app_private(&root.path().join("elsewhere.txt"), &paths));
    }
}
