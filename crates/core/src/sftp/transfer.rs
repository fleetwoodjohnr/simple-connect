//! Streaming file transfers. Files are never loaded whole: data moves in
//! `CHUNK`-sized requests with up to `WINDOW` in flight, so memory stays below
//! `CHUNK * WINDOW` per transfer while high-latency links stay busy.
//!
//! Data first lands in `<name>.sc-part`. A paused or failed transfer resumes from
//! the size of that file. Only a completed transfer is renamed into place.
//! SHA-256 is computed while streaming and can be compared with the remote file.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::BytesMut;
use futures_util::StreamExt;
use futures_util::stream::{FuturesOrdered, FuturesUnordered};
use openssh_sftp_client::file::File as RemoteFile;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::{RemoteFs, Result, SftpError, remote_join, remote_parent};

const CHUNK: u32 = 256 * 1024;
const WINDOW: usize = 16;
pub const PART_SUFFIX: &str = ".sc-part";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Upload,
    Download,
}

/// Shared between a running transfer and whoever may stop it.
#[derive(Debug, Default)]
pub struct Control {
    stop: AtomicBool,
}

impl Control {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub bytes: u64,
    /// Hex SHA-256 of the whole file as transferred.
    pub sha256: String,
}

fn part_path(dest: &Path) -> PathBuf {
    let mut p = dest.as_os_str().to_owned();
    p.push(PART_SUFFIX);
    p.into()
}

/// Opens (or creates) the local `.sc-part` without following symlinks, so a link
/// planted in the download folder can't redirect the write.
async fn open_local_part(path: &Path) -> std::io::Result<tokio::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32).mode(0o600);
    }
    let path = path.to_path_buf();
    let f = tokio::task::spawn_blocking(move || opts.open(path)).await.map_err(std::io::Error::other)??;
    Ok(tokio::fs::File::from_std(f))
}

/// Hashes the first `len` bytes of a local file (to resume a running digest).
async fn hash_prefix(path: &Path, len: u64, hasher: &mut Sha256) -> std::io::Result<()> {
    let mut f = tokio::fs::File::open(path).await?.take(len);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        hasher.update(&buf[..n]);
    }
}

async fn read_at(mut f: RemoteFile, offset: u64, len: u32) -> Result<(u64, Option<BytesMut>)> {
    f.seek(SeekFrom::Start(offset)).await.map_err(|e| SftpError::Remote(e.to_string()))?;
    Ok((offset, f.read(len, BytesMut::with_capacity(len as usize)).await?))
}

/// Downloads `remote` to `dest` (which must not be a directory). Resumes from an
/// existing `.sc-part`. `on_progress(done, total)` is called after each chunk.
pub async fn download(
    fs: &RemoteFs,
    remote: &str,
    dest: &Path,
    control: &Control,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<Outcome> {
    let total = fs.stat(remote).await?.size;
    let part = part_path(dest);
    let mut local = open_local_part(&part).await?;
    let mut done = local.metadata().await?.len();
    if done > total {
        // Remote file shrank since the partial download: start over.
        local.set_len(0).await?;
        done = 0;
    }
    let mut hasher = Sha256::new();
    hash_prefix(&part, done, &mut hasher).await?;
    on_progress(done, total);

    let file = fs.sftp.open(remote).await?;
    let mut pending = FuturesOrdered::new();
    let mut next = done;
    let mut eof = false;
    while !eof || !pending.is_empty() {
        while !eof && pending.len() < WINDOW && next < total {
            let len = CHUNK.min((total - next) as u32);
            pending.push_back(read_at(file.clone(), next, len));
            next += u64::from(len);
        }
        if next >= total {
            eof = true;
        }
        let Some(res) = pending.next().await else { break };
        let (offset, data) = res?;
        if control.stopped() {
            local.flush().await?;
            return Err(SftpError::Cancelled);
        }
        let mut data = data.unwrap_or_default();
        // SFTP allows short reads; fill any gap before writing in order.
        let mut filled = offset + data.len() as u64;
        let expected = (offset + u64::from(CHUNK)).min(total);
        while filled < expected {
            match read_at(file.clone(), filled, (expected - filled) as u32).await? {
                (_, Some(more)) if !more.is_empty() => {
                    filled += more.len() as u64;
                    data.extend_from_slice(&more);
                }
                _ => {
                    eof = true; // file shrank while downloading
                    break;
                }
            }
        }
        local.write_all(&data).await?;
        hasher.update(&data);
        done += data.len() as u64;
        on_progress(done, total);
    }
    local.sync_all().await?;
    drop(local);
    tokio::fs::rename(&part, dest).await?;
    Ok(Outcome { bytes: done, sha256: hex(&hasher.finalize()) })
}

/// Uploads `src` to `remote`, through `<remote>.sc-part`, resuming from its size.
pub async fn upload(
    fs: &RemoteFs,
    src: &Path,
    remote: &str,
    overwrite: bool,
    control: &Control,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<Outcome> {
    let mut local = tokio::fs::File::open(src).await?;
    let total = local.metadata().await?.len();
    let part = format!("{remote}{PART_SUFFIX}");
    let mut done = fs.stat(&part).await.map(|e| e.size).unwrap_or(0);
    if done > total {
        done = 0;
    }
    let mut hasher = Sha256::new();
    hash_prefix(src, done, &mut hasher).await?;
    local.seek(SeekFrom::Start(done)).await?;
    on_progress(done, total);

    let file = fs.sftp.options().write(true).create(true).truncate(done == 0).open(&part).await?;
    let mut pending = FuturesUnordered::new();
    let mut offset = done;
    let mut buf = vec![0u8; CHUNK as usize];
    loop {
        if control.stopped() {
            while pending.next().await.is_some() {}
            return Err(SftpError::Cancelled);
        }
        let n = local.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        let mut f = file.clone();
        let chunk = buf[..n].to_vec();
        let at = offset;
        pending.push(async move {
            f.seek(SeekFrom::Start(at)).await.map_err(|e| SftpError::Remote(e.to_string()))?;
            f.write_all(&chunk).await?;
            Ok::<u64, SftpError>(chunk.len() as u64)
        });
        offset += n as u64;
        if pending.len() >= WINDOW
            && let Some(r) = pending.next().await
        {
            done += r?;
            on_progress(done, total);
        }
    }
    while let Some(r) = pending.next().await {
        done += r?;
        on_progress(done, total);
    }
    file.close().await?;

    if fs.exists(remote).await {
        if !overwrite {
            return Err(SftpError::Remote("The destination already exists.".into()));
        }
        if !fs.sftp.support_posix_rename() {
            fs.sftp.fs().remove_file(remote).await?;
        }
    }
    fs.rename(&part, remote).await?;
    Ok(Outcome { bytes: done, sha256: hex(&hasher.finalize()) })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Remote SHA-256 via `sha256sum`, run through the master. `None` when the
/// server has no POSIX `sha256sum` (e.g. Windows) – verification is skipped, not failed.
pub async fn remote_sha256(
    ossh: &crate::ssh::openssh::OpenSsh,
    master: &crate::ssh::mux::Master,
    dest: &crate::ssh::mux::Destination,
    remote: &str,
) -> Option<String> {
    let mut args = master.client_args(dest);
    args.extend(["-T".into(), "--".into(), dest.host.as_str().into()]);
    args.push(format!("sha256sum -- {}", crate::ssh::shell::quote(remote)).into());
    let out = tokio::process::Command::new(&ossh.ssh).args(args).stdin(std::process::Stdio::null()).output().await.ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let digest = text.split_whitespace().next()?;
    (out.status.success() && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then(|| digest.to_ascii_lowercase())
}

/// Lists every file under a remote directory as `(remote path, relative parts)`,
/// creating nothing. Guards against hostile trees with depth and count limits.
pub async fn walk_remote(fs: &RemoteFs, root: &str) -> Result<Vec<(String, Vec<String>, bool)>> {
    const MAX_ENTRIES: usize = 200_000;
    const MAX_DEPTH: usize = 64;
    let mut out = Vec::new();
    let mut stack = vec![(root.to_owned(), Vec::<String>::new())];
    while let Some((dir, rel)) = stack.pop() {
        if rel.len() > MAX_DEPTH || out.len() > MAX_ENTRIES {
            return Err(SftpError::Remote("The folder is too deep or too large to transfer.".into()));
        }
        for e in fs.list(&dir).await? {
            let mut r = rel.clone();
            r.push(e.name.clone());
            let path = remote_join(&dir, &e.name);
            match e.kind {
                super::EntryKind::Dir => {
                    out.push((path.clone(), r.clone(), true));
                    stack.push((path, r));
                }
                super::EntryKind::File => out.push((path, r, false)),
                // Symlinks and special files are skipped: following links could loop
                // or escape the selected folder.
                _ => {}
            }
        }
    }
    Ok(out)
}

/// Every file under a local directory (symlinks skipped), as relative parts.
pub fn walk_local(root: &Path) -> std::io::Result<Vec<(PathBuf, Vec<String>, bool)>> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), Vec::<String>::new())];
    while let Some((dir, rel)) = stack.pop() {
        for item in std::fs::read_dir(&dir)? {
            let item = item?;
            let ft = item.file_type()?;
            let mut r = rel.clone();
            r.push(item.file_name().to_string_lossy().into_owned());
            if ft.is_dir() {
                out.push((item.path(), r.clone(), true));
                stack.push((item.path(), r));
            } else if ft.is_file() {
                out.push((item.path(), r, false));
            }
        }
    }
    Ok(out)
}

/// Remote counterpart of a relative path under `root`.
pub fn remote_under(root: &str, rel: &[String]) -> String {
    rel.iter().fold(root.to_owned(), |acc, part| remote_join(&acc, part))
}

/// Local counterpart of a relative path under `root`. Each untrusted remote
/// component is validated, so `..` or `/` in a name can't escape `root`.
pub fn local_under(root: &Path, rel: &[String]) -> std::result::Result<PathBuf, crate::validate::ValidationError> {
    rel.iter().try_fold(root.to_path_buf(), |acc, part| crate::validate::join_local(&acc, part))
}

/// `name (1).ext`, `name (2).ext`, … for "keep both".
pub fn numbered(name: &str, n: u32) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

pub fn remote_dir_of(path: &str) -> String {
    remote_parent(path)
}

pub type Shared = Arc<Control>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(numbered("report.pdf", 2), "report (2).pdf");
        assert_eq!(numbered(".bashrc", 1), ".bashrc (1)");
        assert_eq!(numbered("Makefile", 1), "Makefile (1)");
        assert_eq!(remote_under("/srv", &["a".into(), "b c".into()]), "/srv/a/b c");
        let root = Path::new("/home/u/Downloads");
        assert!(local_under(root, &["ok".into(), "file".into()]).is_ok());
        assert!(local_under(root, &["..".into(), ".bashrc".into()]).is_err());
        assert!(local_under(root, &["a/../../x".into()]).is_err());
    }
}
