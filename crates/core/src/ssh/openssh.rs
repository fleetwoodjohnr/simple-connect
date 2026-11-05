//! Locates the system OpenSSH client and discovers what it supports.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::SshError;

/// `KnownHostsCommand` (8.5) and `SSH_ASKPASS_REQUIRE` (8.4) are required for
/// fail-closed host verification and GUI prompts.
pub const MIN_VERSION: (u32, u32) = (8, 5);

#[derive(Debug, Clone)]
pub struct OpenSsh {
    pub ssh: PathBuf,
    pub keygen: PathBuf,
    pub version: (u32, u32),
    pub version_string: String,
    pub kex: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub key_algorithms: Vec<String>,
}

impl OpenSsh {
    pub fn discover() -> Result<Self, SshError> {
        let bundled = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("openssh")));
        let locate = |name: &str| {
            bundled.as_ref().map(|d| d.join(format!("{name}.exe"))).filter(|p| cfg!(windows) && p.is_file()).or_else(|| find_in_path(name))
        };
        let ssh = locate("ssh").ok_or(SshError::OpenSshMissing)?;
        let keygen = locate("ssh-keygen").ok_or(SshError::OpenSshMissing)?;
        let out = Command::new(&ssh).arg("-V").output().map_err(|_| SshError::OpenSshMissing)?;
        let version_string = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        let version = parse_version(&version_string).ok_or(SshError::OpenSshMissing)?;
        if version < MIN_VERSION {
            return Err(SshError::OpenSshTooOld(version_string));
        }
        let query = |what: &str| -> Vec<String> {
            Command::new(&ssh)
                .args(["-Q", what])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_owned).collect())
                .unwrap_or_default()
        };
        Ok(Self {
            kex: query("kex"),
            ciphers: query("cipher"),
            macs: query("mac"),
            key_algorithms: query("HostKeyAlgorithms"),
            ssh,
            keygen,
            version,
            version_string,
        })
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) { format!("{name}.exe") } else { name.to_owned() };
    std::env::var_os("PATH").iter().flat_map(std::env::split_paths).map(|dir| dir.join(&exe)).find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    p.is_file()
}

/// "OpenSSH_10.2p1, OpenSSL …", "OpenSSH_for_Windows_9.5p1, LibreSSL …" → (10, 2)
pub fn parse_version(s: &str) -> Option<(u32, u32)> {
    let rest = s.split("OpenSSH_").nth(1)?;
    let rest = rest.strip_prefix("for_Windows_").unwrap_or(rest);
    let mut nums = rest.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty());
    Some((nums.next()?.parse().ok()?, nums.next()?.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("OpenSSH_10.2p1, OpenSSL 3.5.9 29 Sep 2026"), Some((10, 2)));
        assert_eq!(parse_version("OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2"), Some((9, 5)));
        assert_eq!(parse_version("OpenSSH_8.4p1 Debian-5"), Some((8, 4)));
        assert_eq!(parse_version("Dropbear"), None);
    }

    #[test]
    fn discovers_local_openssh() {
        // The development machine and CI have OpenSSH installed.
        let o = OpenSsh::discover().unwrap();
        assert!(o.version >= MIN_VERSION);
        assert!(o.kex.iter().any(|k| k == "curve25519-sha256"));
        assert!(o.ciphers.iter().any(|c| c == "chacha20-poly1305@openssh.com"));
    }
}
