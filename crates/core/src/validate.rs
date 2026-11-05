//! Validators for every value that crosses a trust boundary (frontend IPC, imports,
//! quick-connect strings, remote listings) before it reaches `ssh` arguments,
//! generated config or the filesystem.
//!
//! Rules are deliberately strict: anything that could be read as an option
//! (`-oProxyCommand=…`), a shell metacharacter (OpenSSH turns `ProxyJump` into a
//! shell `ProxyCommand`), a config-file token or a path escape is rejected.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("Enter a host name or IP address.")]
    EmptyHost,
    #[error("“{0}” isn't a valid host name or IP address.")]
    InvalidHost(String),
    #[error("Enter a user name.")]
    EmptyUser,
    #[error("The user name contains characters that aren't allowed.")]
    InvalidUser,
    #[error("Port must be a number from 1 to 65535.")]
    InvalidPort,
    #[error("“{0}” isn't a valid jump host. Use user@host:port.")]
    InvalidJump(String),
    #[error("Too many jump hosts (maximum {MAX_JUMP_HOPS}).")]
    TooManyJumps,
    #[error("The path must be absolute and must not contain “..”.")]
    InvalidLocalPath,
    #[error("The remote path is empty or contains invalid characters.")]
    InvalidRemotePath,
    #[error("“{0}” isn't a valid file name.")]
    InvalidFileName(String),
    #[error("Enter a MAC address like b8:27:eb:12:34:56.")]
    InvalidMac,
}

pub type Result<T> = std::result::Result<T, ValidationError>;

pub const MAX_JUMP_HOPS: usize = 8;
const MAX_PATH_BYTES: usize = 4096;

/// A validated host: DNS name / ssh_config alias, IPv4 or IPv6 literal.
/// Stored without brackets; use [`Host::for_destination`] when building `[v6]:port` strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Host(String);

impl Host {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() {
            return Err(ValidationError::EmptyHost);
        }
        let unbracketed = s.strip_prefix('[').and_then(|r| r.strip_suffix(']'));
        if let Some(inner) = unbracketed {
            return inner.parse::<Ipv6Addr>().map(|_| Host(inner.to_owned())).map_err(|_| ValidationError::InvalidHost(s.to_owned()));
        }
        if s.parse::<Ipv6Addr>().is_ok() || s.parse::<Ipv4Addr>().is_ok() || is_dns_name(s) {
            return Ok(Host(s.to_owned()));
        }
        Err(ValidationError::InvalidHost(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_ipv6(&self) -> bool {
        self.0.contains(':')
    }

    /// `host` or `[v6]` — the form used inside `host:port` jump specs.
    pub fn for_destination(&self) -> String {
        if self.is_ipv6() { format!("[{}]", self.0) } else { self.0.clone() }
    }
}

impl TryFrom<String> for Host {
    type Error = ValidationError;
    fn try_from(s: String) -> Result<Self> {
        Host::parse(&s)
    }
}
impl From<Host> for String {
    fn from(h: Host) -> String {
        h.0
    }
}

/// RFC 1123 labels, plus `_` (common in internal names and ssh_config aliases).
/// Leading `-` is rejected so a host can never be read as an option.
fn is_dns_name(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// A validated remote user name.
///
/// Allows Unicode letters/digits plus `. _ - @ \` (covers `user@domain` and
/// `DOMAIN\user` on Windows servers). Rejects whitespace, control characters,
/// shell metacharacters, a leading `-` and a trailing `\`, which is stricter than
/// OpenSSH's own `valid_ruser()` check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct User(String);

impl User {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() {
            return Err(ValidationError::EmptyUser);
        }
        let ok = s.len() <= 256
            && !s.starts_with('-')
            && !s.ends_with('\\')
            && s.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '\\'));
        if ok { Ok(User(s.to_owned())) } else { Err(ValidationError::InvalidUser) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Jump-host users end up inside the shell `ProxyCommand` that OpenSSH builds
    /// for `ProxyJump`, so only a portable POSIX subset is allowed there.
    fn is_jump_safe(&self) -> bool {
        self.0.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    }
}

impl TryFrom<String> for User {
    type Error = ValidationError;
    fn try_from(s: String) -> Result<Self> {
        User::parse(&s)
    }
}
impl From<User> for String {
    fn from(u: User) -> String {
        u.0
    }
}

pub fn port(input: &str) -> Result<u16> {
    match input.trim().parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(ValidationError::InvalidPort),
    }
}

/// One `ProxyJump` hop: `[user@]host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpHop {
    pub user: Option<User>,
    pub host: Host,
    pub port: Option<u16>,
}

impl JumpHop {
    pub fn parse(input: &str) -> Result<Self> {
        let bad = || ValidationError::InvalidJump(input.to_owned());
        let s = input.trim();
        let (user, rest) = match s.rsplit_once('@') {
            Some((u, r)) => (Some(User::parse(u).map_err(|_| bad())?), r),
            None => (None, s),
        };
        let (host, port) = split_host_port(rest).ok_or_else(bad)?;
        let hop = JumpHop { user, host: Host::parse(host).map_err(|_| bad())?, port: port.map(self::port).transpose().map_err(|_| bad())? };
        if hop.user.as_ref().is_some_and(|u| !u.is_jump_safe()) {
            return Err(bad());
        }
        Ok(hop)
    }

    /// Canonical `ProxyJump` form, e.g. `admin@[fd00::1]:2222`.
    pub fn to_spec(&self) -> String {
        let mut s = String::new();
        if let Some(u) = &self.user {
            s.push_str(u.as_str());
            s.push('@');
        }
        s.push_str(&self.host.for_destination());
        if let Some(p) = self.port {
            s.push_str(&format!(":{p}"));
        }
        s
    }
}

/// Parses a comma-separated `ProxyJump` chain.
pub fn jump_chain(input: &str) -> Result<Vec<JumpHop>> {
    let hops = input.split(',').map(JumpHop::parse).collect::<Result<Vec<_>>>()?;
    if hops.len() > MAX_JUMP_HOPS {
        return Err(ValidationError::TooManyJumps);
    }
    Ok(hops)
}

/// Splits `host`, `host:port`, `[v6]`, `[v6]:port`. A bare IPv6 literal (several
/// colons, no brackets) is returned whole with no port.
pub(crate) fn split_host_port(s: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        return match after {
            "" => Some((inner, None)),
            _ => Some((inner, Some(after.strip_prefix(':')?))),
        };
    }
    match s.matches(':').count() {
        0 => Some((s, None)),
        1 => s.split_once(':').map(|(h, p)| (h, Some(p))),
        _ => Some((s, None)),
    }
}

/// A local path from the frontend: absolute, NUL-free, no `..` components.
pub fn local_path(input: &str) -> Result<PathBuf> {
    let p = Path::new(input);
    let ok = !input.is_empty()
        && input.len() <= MAX_PATH_BYTES
        && !input.contains('\0')
        && p.is_absolute()
        && !p.components().any(|c| c == Component::ParentDir);
    if ok { Ok(p.to_path_buf()) } else { Err(ValidationError::InvalidLocalPath) }
}

/// A private-key path. `~/` is expanded; `%` (OpenSSH token expansion), `"` (config
/// quoting) and control characters are rejected because the path reaches `ssh`.
pub fn identity_file(input: &str) -> Result<PathBuf> {
    let expanded = match (input.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest).to_string_lossy().into_owned(),
        _ => input.to_owned(),
    };
    if expanded.contains(['%', '"']) || expanded.chars().any(char::is_control) {
        return Err(ValidationError::InvalidLocalPath);
    }
    local_path(&expanded)
}

/// A MAC address in common notations (`aa:bb:…`, `AA-BB-…`, `aabb.ccdd.eeff`),
/// normalised to lowercase and colon-separated.
pub fn mac(input: &str) -> Result<String> {
    let hex: Vec<char> = input.trim().chars().filter(|c| !matches!(c, ':' | '-' | '.')).collect();
    if hex.len() != 12 || !hex.iter().all(char::is_ascii_hexdigit) {
        return Err(ValidationError::InvalidMac);
    }
    let pairs: Vec<String> = hex.chunks(2).map(|p| p.iter().collect::<String>().to_ascii_lowercase()).collect();
    Ok(pairs.join(":"))
}

/// A remote SFTP path. SFTP passes paths as length-prefixed strings (no shell), so
/// only emptiness, NUL and length are checked here; traversal matters when remote
/// names are joined onto *local* paths, see [`file_name`].
pub fn remote_path(input: &str) -> Result<&str> {
    if input.is_empty() || input.len() > MAX_PATH_BYTES || input.contains('\0') {
        return Err(ValidationError::InvalidRemotePath);
    }
    Ok(input)
}

/// Windows interprets these characters and DOS device stems specially, even
/// inside an otherwise ordinary directory. Kept portable so tests on Unix also
/// exercise names that could address a device or an NTFS alternate data stream.
fn windows_file_name(input: &str) -> bool {
    if input.ends_with(['.', ' '])
        || input.chars().any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
    {
        return false;
    }
    let stem = input.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return false;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(number) = stem.strip_prefix(prefix)
            && matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
        {
            return false;
        }
    }
    true
}

/// A single path component, e.g. a name from a remote directory listing that is
/// about to be joined onto a local directory. Rejects separators, `.`/`..` and NUL.
/// Windows also rejects DOS devices, alternate data streams and names that Win32 normalizes.
pub fn file_name(input: &str) -> Result<&str> {
    let ok = !input.is_empty()
        && input.len() <= 255
        && input != "."
        && input != ".."
        && !input.contains(['/', '\0'])
        && (!cfg!(windows) || windows_file_name(input));
    if ok { Ok(input) } else { Err(ValidationError::InvalidFileName(input.escape_debug().to_string())) }
}

/// Joins an untrusted remote name onto a trusted local directory.
pub fn join_local(dir: &Path, name: &str) -> Result<PathBuf> {
    Ok(dir.join(file_name(name)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        for ok in ["example.com", "nas", "my_host.lan", "192.168.1.10", "::1", "[fe80::1]", "fqdn.example.com."] {
            assert!(Host::parse(ok).is_ok(), "{ok}");
        }
        assert_eq!(Host::parse("[::1]").map(|h| h.for_destination()), Ok("[::1]".into()));
        for bad in [
            "",
            "-oProxyCommand=sh",
            "a b",
            "host;id",
            "$(id)",
            "a..b",
            "-host",
            "host-",
            "exa mple",
            "host\nx",
            "ho`st",
            "ünïcode.example",
            "[1.2.3.4]",
            "[::1",
            "%h",
            "a/b",
        ] {
            assert!(Host::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn users() {
        for ok in ["root", "john.doe", "svc_deploy", "user@corp.example", "CORP\\user", "jörg"] {
            assert!(User::parse(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-oops", "a b", "a;b", "a'b", "a\"b", "$(id)", "a`b", "x\\", "a\nb", "a|b", "%u", "a/b"] {
            assert!(User::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ports() {
        assert_eq!(port("22"), Ok(22));
        assert_eq!(port(" 65535 "), Ok(65535));
        for bad in ["0", "65536", "-1", "22 -oX", "", "0x16"] {
            assert!(port(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn jumps() {
        let chain = jump_chain("admin@bastion:2222,10.0.0.5,ops@[fd00::1]:22").unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].to_spec(), "admin@bastion:2222");
        assert_eq!(chain[1].to_spec(), "10.0.0.5");
        assert_eq!(chain[2].to_spec(), "ops@[fd00::1]:22");
        // Users that are fine on the command line but unsafe inside ProxyCommand.
        for bad in ["a;b@host", "CORP\\u@host", "u@host:0", "host:ssh", "-J@x", "u@-host", "", "a@b@c d"] {
            assert!(jump_chain(bad).is_err(), "{bad:?}");
        }
        assert_eq!(jump_chain(&["h"; 9].join(",")), Err(ValidationError::TooManyJumps));
    }

    #[test]
    fn local_paths() {
        let absolute = if cfg!(windows) { "C:/Users/u/file name ünï 'q'.txt" } else { "/home/u/file name ünï 'q'.txt" };
        assert!(local_path(absolute).is_ok());
        for bad in ["", "relative/x", "/a/../b", "/a\0b"] {
            assert!(local_path(bad).is_err(), "{bad:?}");
        }
        assert!(identity_file("~/.ssh/id_ed25519").is_ok());
        for bad in ["/k/%d", "/k/\"q", "/k/a\nb", "rel"] {
            assert!(identity_file(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn windows_remote_names_are_safe_single_components() {
        for bad in [
            "file:secret",
            "file::$DATA",
            "NUL",
            "nul.txt",
            "Con",
            "CON.txt",
            "CON .txt",
            "PRN",
            "AUX",
            "COM1",
            "com9.log",
            "LPT1.txt",
            "lpt9",
            "COM¹",
            "LPT².txt",
            "CONIN$",
            "CONOUT$",
            "trailing.",
            "trailing ",
            "a<b",
            "a>b",
            "a:b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            "a\\b",
            "a\nb",
            "a\tb",
            "a\u{7f}b",
        ] {
            assert!(!windows_file_name(bad), "{bad:?}");
            if cfg!(windows) {
                assert!(file_name(bad).is_err(), "{bad:?}");
                assert!(join_local(Path::new("C:/Downloads"), bad).is_err(), "{bad:?}");
            } else {
                assert!(file_name(bad).is_ok(), "POSIX names must remain unchanged: {bad:?}");
            }
        }
        for good in ["report.txt", "name with spaces.txt", "café", "COM10", "LPT10", "NUL-file", ".hidden"] {
            assert!(windows_file_name(good), "{good:?}");
            assert!(file_name(good).is_ok(), "{good:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_local_paths_and_identity_files() {
        for good in [r"C:\Users\u\.ssh\id_ed25519", "C:/Users/u/.ssh/id_ed25519", r"\\server\share\key"] {
            assert_eq!(identity_file(good).unwrap(), PathBuf::from(good));
        }
        for bad in [r"C:relative\key", "C:relative/key", r"\Users\u\key", "/Users/u/key", r"C:\Users\..\key", "C:/Users/../key"] {
            assert!(local_path(bad).is_err(), "{bad:?}");
            assert!(identity_file(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn macs() {
        assert_eq!(mac("B8:27:EB:12:34:56"), Ok("b8:27:eb:12:34:56".into()));
        assert_eq!(mac("b8-27-eb-12-34-56"), Ok("b8:27:eb:12:34:56".into()));
        assert_eq!(mac("b827.eb12.3456"), Ok("b8:27:eb:12:34:56".into()));
        for bad in ["", "b8:27:eb:12:34", "zz:27:eb:12:34:56", "b8:27:eb:12:34:56:78", "b8:27:eb:12:34:5\n"] {
            assert!(mac(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn remote_names() {
        assert!(file_name("ordinary name.txt").is_ok());
        if !cfg!(windows) {
            assert!(file_name("ok name; $(rm -rf ~) 'q' \"d\".txt").is_ok());
            assert!(file_name("new\nline").is_ok(), "newlines are legal on POSIX; UI must render them visibly");
        }
        for bad in ["", ".", "..", "../x", "a/b", "/etc/passwd", "a\0b"] {
            assert!(file_name(bad).is_err(), "{bad:?}");
        }
        let dir = Path::new("/home/u/Downloads");
        assert_eq!(join_local(dir, "x.iso").unwrap(), dir.join("x.iso"));
        assert!(join_local(dir, "../../.bashrc").is_err());
        assert!(remote_path("").is_err());
        assert!(remote_path("/a\0").is_err());
        assert_eq!(remote_path("../relative ok"), Ok("../relative ok"));
    }
}
