//! Read-only view of host aliases in the user's `~/.ssh/config`, shown in the
//! connection list. Connecting to an alias hands the alias to OpenSSH, which
//! resolves the real settings itself; this parser only extracts display fields.
//! The file is never modified.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::validate::Host;

const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_INCLUDE_DEPTH: usize = 5;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfigHost {
    pub alias: String,
    pub host_name: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
}

/// Aliases from `~/.ssh/config` (and files it includes). Missing or unreadable → empty.
pub fn read_user_config() -> Vec<SshConfigHost> {
    let Some(ssh_dir) = dirs::home_dir().map(|h| h.join(".ssh")) else { return Vec::new() };
    let mut out = Vec::new();
    read_file(&ssh_dir.join("config"), &ssh_dir, 0, &mut out);
    out
}

fn read_file(path: &Path, ssh_dir: &Path, depth: usize, out: &mut Vec<SshConfigHost>) {
    let too_big = fs::metadata(path).map_or(true, |m| !m.is_file() || m.len() > MAX_FILE_BYTES);
    if too_big {
        return;
    }
    if let Ok(text) = fs::read_to_string(path) {
        parse(&text, ssh_dir, depth, out);
    }
}

pub fn parse(text: &str, ssh_dir: &Path, depth: usize, out: &mut Vec<SshConfigHost>) {
    // Indices into `out` for the aliases of the current Host block.
    let mut current: Vec<usize> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.find(|c: char| c.is_whitespace() || c == '=') {
            Some(i) => (&line[..i], line[i..].trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim()),
            None => (line, ""),
        };
        let unquote = |v: &str| v.trim_matches('"').to_owned();
        match key.to_ascii_lowercase().as_str() {
            "host" => {
                current.clear();
                for pattern in value.split_whitespace().map(unquote) {
                    if pattern.contains(['*', '?', '!']) || Host::parse(&pattern).is_err() {
                        continue;
                    }
                    let idx = out.iter().position(|h| h.alias == pattern).unwrap_or_else(|| {
                        out.push(SshConfigHost { alias: pattern.clone(), ..Default::default() });
                        out.len() - 1
                    });
                    current.push(idx);
                }
            }
            "match" => current.clear(),
            "include" if depth < MAX_INCLUDE_DEPTH => {
                for pattern in value.split_whitespace().map(unquote) {
                    for file in expand_include(&pattern, ssh_dir) {
                        read_file(&file, ssh_dir, depth + 1, out);
                    }
                }
            }
            k @ ("hostname" | "user" | "port" | "identityfile" | "proxyjump") => {
                let v = unquote(value);
                for &i in &current {
                    // OpenSSH semantics: the first value obtained wins.
                    let h = &mut out[i];
                    match k {
                        "hostname" => _ = h.host_name.get_or_insert_with(|| v.clone()),
                        "user" => _ = h.user.get_or_insert_with(|| v.clone()),
                        "port" => h.port = h.port.or_else(|| v.parse().ok()),
                        "identityfile" => _ = h.identity_file.get_or_insert_with(|| v.clone()),
                        _ => _ = h.proxy_jump.get_or_insert_with(|| v.clone()),
                    }
                }
            }
            _ => {}
        }
    }
}

/// `Include` paths are relative to ~/.ssh; `*`/`?` are supported in the file name.
fn expand_include(pattern: &str, ssh_dir: &Path) -> Vec<PathBuf> {
    let path = match pattern.strip_prefix("~/") {
        Some(rest) => ssh_dir.parent().map_or_else(|| ssh_dir.join(rest), |home| home.join(rest)),
        None => ssh_dir.join(pattern), // join() keeps absolute patterns as-is
    };
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };
    if !name.contains(['*', '?']) {
        return vec![path];
    }
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_str().is_some_and(|n| glob(name.as_bytes(), n.as_bytes())))
        .map(|e| e.path())
        .collect();
    files.sort();
    files
}

fn glob(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob(&p[1..], s) || (!s.is_empty() && glob(p, &s[1..])),
        (Some(b'?'), Some(_)) => glob(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => glob(&p[1..], &s[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aliases_and_includes() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("config.d")).unwrap();
        fs::write(dir.path().join("config.d/work.conf"), "Host db\n  HostName 10.0.0.5\n  ProxyJump bastion\n").unwrap();
        fs::write(dir.path().join("config.d/skip.txt"), "Host notincluded\n").unwrap();
        let text = r#"
# comment
Host production prod-alias *.wild !neg
    HostName 192.168.1.100
    User john
    Port=2222
    IdentityFile "~/.ssh/id_ed25519"
    User ignored-second-value

Host -oProxyCommand=evil
    HostName x

Match host foo
    User matched

Include config.d/*.conf
Host *
    User fallback
"#;
        let mut out = Vec::new();
        parse(text, dir.path(), 0, &mut out);
        let aliases: Vec<_> = out.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, ["production", "prod-alias", "db"]);
        assert_eq!(out[0].host_name.as_deref(), Some("192.168.1.100"));
        assert_eq!(out[0].user.as_deref(), Some("john"));
        assert_eq!(out[0].port, Some(2222));
        assert_eq!(out[0].identity_file.as_deref(), Some("~/.ssh/id_ed25519"));
        assert_eq!(out[2].proxy_jump.as_deref(), Some("bastion"));
    }

    #[test]
    fn include_loops_terminate() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("config"), "Include config\nHost a\n").unwrap();
        let mut out = Vec::new();
        read_file(&dir.path().join("config"), dir.path(), 0, &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn globbing() {
        assert!(glob(b"*.conf", b"a.conf"));
        assert!(glob(b"h?st", b"host"));
        assert!(!glob(b"*.conf", b"a.txt"));
    }
}
