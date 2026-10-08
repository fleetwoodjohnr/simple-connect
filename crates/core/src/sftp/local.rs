//! Local side of the file manager. Paths arrive from the (untrusted) frontend
//! and have already passed [`crate::validate::local_path`].

use std::path::Path;
use std::time::UNIX_EPOCH;

use super::{Entry, EntryKind};

pub fn list(dir: &Path) -> std::io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    for item in std::fs::read_dir(dir)? {
        let Ok(item) = item else { continue };
        let Ok(meta) = item.path().symlink_metadata() else { continue };
        let kind = if meta.is_dir() {
            EntryKind::Dir
        } else if meta.is_file() {
            EntryKind::File
        } else if meta.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::Other
        };
        let target = std::fs::metadata(item.path()).ok();
        #[cfg(unix)]
        let mode = Some(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777);
        #[cfg(not(unix))]
        let mode = None;
        out.push(Entry {
            name: item.file_name().to_string_lossy().into_owned(),
            kind,
            target_is_dir: target.as_ref().is_some_and(|m| m.is_dir()),
            size: target.as_ref().map_or(meta.len(), |m| m.len()),
            modified: meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()),
            mode,
        });
    }
    Ok(out)
}

pub fn mkdir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

/// Refuses to replace an existing destination.
pub fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    if to.symlink_metadata().is_ok() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "A file with that name already exists."));
    }
    std::fs::rename(from, to)
}

/// Moves to the desktop trash rather than deleting, so mistakes are recoverable.
pub fn trash(path: &Path) -> std::io::Result<()> {
    trash::delete(path).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_and_renames_without_clobbering() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.txt"), "x").unwrap();
        std::fs::write(d.path().join("b.txt"), "y").unwrap();
        mkdir(&d.path().join("sub dir")).unwrap();
        let mut names: Vec<_> = list(d.path()).unwrap().into_iter().map(|e| (e.name, e.kind)).collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(names[2], ("sub dir".to_owned(), EntryKind::Dir));
        assert!(rename(&d.path().join("a.txt"), &d.path().join("b.txt")).is_err());
        assert_eq!(std::fs::read_to_string(d.path().join("b.txt")).unwrap(), "y");
    }
}
