//! Generates the per-session `ssh_config` that carries the security policy.
//!
//! OpenSSH uses the first value it finds for each option, so the policy block is
//! written first and then the user's and the system's configs are included: they
//! can add settings (identity files, users, proxies) but cannot weaken the policy.

use std::fmt::Write as _;
use std::path::Path;

use super::openssh::OpenSsh;

/// Modern algorithms, in preference order. Intersected with `ssh -Q` so older
/// clients never see names they reject.
const KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp521",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
];
const CIPHERS: &[&str] =
    &["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"];
const MACS: &[&str] =
    &["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256"];
/// SHA-1 based / obsolete key algorithms, removed from OpenSSH's defaults with
/// `-list` (which keeps OpenSSH's preference for algorithms it already knows).
const WEAK_KEYS: &[&str] = &["ssh-rsa", "ssh-rsa-cert-v01@openssh.com", "ssh-dss", "ssh-dss-cert-v01@openssh.com"];

/// Compatibility additions for old servers and appliances. Opt-in per profile with
/// a warning. Never includes DES, 3DES, RC4 or SSHv1.
const LEGACY_KEX: &[&str] = &["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1"];
const LEGACY_CIPHERS: &[&str] = &["aes256-cbc", "aes192-cbc", "aes128-cbc"];
const LEGACY_MACS: &[&str] = &["hmac-sha1-etm@openssh.com", "hmac-sha1"];

#[derive(Debug, Clone)]
pub struct Policy {
    pub include_user_config: bool,
    pub legacy_crypto: bool,
    pub keepalive_secs: u16,
    pub connect_timeout_secs: u16,
}

impl Default for Policy {
    fn default() -> Self {
        Self { include_user_config: true, legacy_crypto: false, keepalive_secs: 30, connect_timeout_secs: 15 }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("The path {0} contains characters that can't be used in an SSH configuration.")]
pub struct UnsafePath(pub String);

/// Quotes a path for ssh_config. OpenSSH expands `%` tokens and `${VAR}` in these
/// options and splits on quotes, so paths containing `% $ " ' \` or control
/// characters are refused rather than escaped.
pub fn quote_path(p: &Path) -> Result<String, UnsafePath> {
    let native = p.to_str().ok_or_else(|| UnsafePath(p.display().to_string()))?;
    let normalized = if cfg!(windows) { native.replace('\\', "/") } else { native.to_owned() };
    let s = normalized.as_str();
    if s.chars().any(|c| matches!(c, '%' | '$' | '"' | '\'' | '\\') || c.is_control()) {
        return Err(UnsafePath(s.to_owned()));
    }
    Ok(format!("\"{s}\""))
}

/// Explicit Windows proxy chain. Command-line tags distinguish each hop while
/// retaining the original host name for the user's ssh_config Host aliases.
/// Native Win32 OpenSSH lacks multiplexing and its implicit -J command leaves
/// -F paths unquoted. Its bundled version supports -P/Match tagged (OpenSSH 9.4+).
pub fn windows_route(ossh: &OpenSsh, config: &Path, dest: &super::mux::Destination, route: &str) -> Result<String, UnsafePath> {
    if dest.jump.is_empty() {
        return Ok(String::new());
    }
    // Tags are local generated identifiers, never a shell/config expression.
    if route.is_empty() || !route.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(UnsafePath("invalid route identifier".into()));
    }
    let ssh = quote_path(&ossh.ssh)?;
    let config = quote_path(config)?;
    let mut text = String::from("# Explicit quoted jump route.\n");
    for index in 0..=dest.jump.len() {
        if index < dest.jump.len() {
            let _ = writeln!(text, "Match tagged {route}-{index}");
        } else {
            let _ = writeln!(text, "Match !tagged {route}-*");
        }
        if index == 0 {
            text.push_str("    ProxyCommand none\n");
            continue;
        }
        let hop = &dest.jump[index - 1];
        let _ = write!(text, "    ProxyCommand {ssh} -F {config} -P {route}-{} -W \"[%h]:%p\"", index - 1);
        if let Some(user) = &hop.user {
            let _ = write!(text, " -l \"{}\"", user.as_str());
        }
        if let Some(port) = hop.port {
            let _ = write!(text, " -p {port}");
        }
        let _ = writeln!(text, " -- {}", hop.host.as_str());
    }
    text.push_str("Match all\n");
    Ok(text)
}

fn pick(preferred: &[&str], extra: &[&str], supported: &[String]) -> String {
    preferred.iter().chain(extra).filter(|a| supported.iter().any(|s| s == *a)).copied().collect::<Vec<_>>().join(",")
}

pub struct ConfigPaths<'a> {
    pub helper_exe: &'a Path,
    pub app_known_hosts: &'a Path,
    pub home: Option<&'a Path>,
}

pub fn render(ossh: &OpenSsh, paths: &ConfigPaths, policy: &Policy) -> Result<String, UnsafePath> {
    let exe = quote_path(paths.helper_exe)?;
    let mut known = vec![quote_path(paths.app_known_hosts)?];
    let user_cfg = paths.home.map(|h| h.join(".ssh/config"));
    if let Some(home) = paths.home {
        known.push(quote_path(&home.join(".ssh/known_hosts"))?);
    }

    let mut c = String::from("# Generated by Simple Connect for a single session. Do not edit.\nHost *\n");
    let mut opt = |k: &str, v: &str| {
        let _ = writeln!(c, "    {k} {v}");
    };
    opt("StrictHostKeyChecking", "yes");
    opt("CheckHostIP", "no");
    opt("UpdateHostKeys", "no");
    opt("HashKnownHosts", "no");
    opt("KnownHostsCommand", &format!("{exe} --sc-known-hosts %I %H %t %K"));
    opt("UserKnownHostsFile", &known.join(" "));
    opt("GlobalKnownHostsFile", "/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2");
    opt("ControlMaster", "no");
    opt("ControlPersist", "no");
    opt("ForwardAgent", "no");
    opt("ForwardX11", "no");
    opt("ForwardX11Trusted", "no");
    opt("PermitLocalCommand", "no");
    opt("ClearAllForwardings", "yes");
    opt("EscapeChar", "none");
    opt("BatchMode", "no");
    opt("NumberOfPasswordPrompts", "3");
    opt("ConnectTimeout", &policy.connect_timeout_secs.to_string());
    opt("ServerAliveInterval", &policy.keepalive_secs.to_string());
    opt("ServerAliveCountMax", "3");
    opt("TCPKeepAlive", "yes");
    opt("SendEnv", "LANG LC_*");

    let (lk, lc, lm) = if policy.legacy_crypto { (LEGACY_KEX, LEGACY_CIPHERS, LEGACY_MACS) } else { (&[][..], &[][..], &[][..]) };
    opt("KexAlgorithms", &pick(KEX, lk, &ossh.kex));
    opt("Ciphers", &pick(CIPHERS, lc, &ossh.ciphers));
    opt("MACs", &pick(MACS, lm, &ossh.macs));
    let weak = pick(WEAK_KEYS, &[], &ossh.key_algorithms);
    if !weak.is_empty() {
        let sign = if policy.legacy_crypto { '+' } else { '-' };
        opt("HostKeyAlgorithms", &format!("{sign}{weak}"));
        opt("PubkeyAcceptedAlgorithms", &format!("{sign}{weak}"));
    }
    if ossh.version >= (9, 1) {
        opt("RequiredRSASize", if policy.legacy_crypto { "1024" } else { "2048" });
    }

    if policy.include_user_config
        && let Some(cfg) = user_cfg.filter(|p| p.is_file())
    {
        opt("Include", &quote_path(&cfg)?);
    }
    if Path::new("/etc/ssh/ssh_config").is_file() {
        opt("Include", "/etc/ssh/ssh_config");
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ossh() -> OpenSsh {
        let all = |xs: &[&[&str]]| xs.iter().flat_map(|x| x.iter().map(|s| s.to_string())).collect::<Vec<_>>();
        OpenSsh {
            ssh: "ssh".into(),
            keygen: "ssh-keygen".into(),
            version: (10, 2),
            version_string: String::new(),
            kex: all(&[&KEX[3..], LEGACY_KEX]),
            ciphers: all(&[CIPHERS, LEGACY_CIPHERS, &["3des-cbc"]]),
            macs: all(&[MACS, LEGACY_MACS]),
            key_algorithms: all(&[&["ssh-ed25519", "ssh-rsa", "rsa-sha2-512"]]),
        }
    }

    fn paths() -> (PathBuf, PathBuf) {
        ("/opt/Simple Connect/simple-connect".into(), "/home/u/.local/share/simple-connect/known_hosts".into())
    }

    #[test]
    fn modern_policy() {
        let (exe, kh) = paths();
        let cfg = render(&ossh(), &ConfigPaths { helper_exe: &exe, app_known_hosts: &kh, home: None }, &Policy::default()).unwrap();
        assert!(cfg.starts_with("# Generated"));
        assert!(cfg.contains("    StrictHostKeyChecking yes\n"));
        assert!(cfg.contains("KnownHostsCommand \"/opt/Simple Connect/simple-connect\" --sc-known-hosts %I %H %t %K"));
        assert!(cfg.contains("KexAlgorithms curve25519-sha256,"), "unsupported names are dropped: {cfg}");
        assert!(!cfg.contains("sha1") && !cfg.contains("cbc"));
        assert!(cfg.contains("HostKeyAlgorithms -ssh-rsa\n"));
        assert!(!cfg.contains("3des"));
    }

    #[test]
    fn legacy_policy_never_allows_3des() {
        let (exe, kh) = paths();
        let p = Policy { legacy_crypto: true, ..Policy::default() };
        let cfg = render(&ossh(), &ConfigPaths { helper_exe: &exe, app_known_hosts: &kh, home: None }, &p).unwrap();
        assert!(cfg.contains("aes256-cbc") && cfg.contains("diffie-hellman-group14-sha1"));
        assert!(cfg.contains("HostKeyAlgorithms +ssh-rsa\n"));
        assert!(!cfg.contains("3des"));
    }

    #[test]
    fn unsafe_paths_are_refused() {
        for bad in ["/a/%d", "/a/${HOME}", "/a/\"q", "/a/'q", "/a/\nb"] {
            assert!(quote_path(Path::new(bad)).is_err(), "{bad:?}");
        }
        #[cfg(unix)]
        assert!(quote_path(Path::new("/a/\\b")).is_err());
        #[cfg(windows)]
        assert_eq!(quote_path(Path::new(r"C:\Users\Some User\.ssh\id")).unwrap(), "\"C:/Users/Some User/.ssh/id\"");
        assert_eq!(quote_path(Path::new("/a b/c")).unwrap(), "\"/a b/c\"");
    }
    #[test]
    fn explicit_route_quotes_paths_and_keeps_original_hop_names() {
        let mut client = ossh();
        client.ssh = "/opt/Program Files/OpenSSH/ssh.exe".into();
        let dest = super::super::mux::Destination {
            host: crate::validate::Host::parse("target.example").unwrap(),
            user: None,
            port: None,
            jump: crate::validate::jump_chain("ops@first:2222,second").unwrap(),
            identity_file: None,
            auth: crate::profiles::AuthMethod::Auto,
        };
        let text = windows_route(&client, Path::new("/some user/run/session.conf"), &dest, "route").unwrap();
        assert!(text.starts_with("# Explicit quoted jump route.\nMatch tagged route-0\n    ProxyCommand none\n"));
        assert!(text.contains("Match tagged route-1\n    ProxyCommand \"/opt/Program Files/OpenSSH/ssh.exe\" -F \"/some user/run/session.conf\" -P route-0 -W \"[%h]:%p\" -l \"ops\" -p 2222 -- first\n"));
        assert!(text.contains("Match !tagged route-*\n"));
        assert!(text.ends_with(" -- second\nMatch all\n"));
        assert!(windows_route(&client, Path::new("/safe"), &dest, "bad tag").is_err());
        // Exercise OpenSSH's actual parser when tagged routing is supported.
        if let Ok(system) = OpenSsh::discover()
            && system.version >= (9, 4)
        {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("config with spaces");
            let text = windows_route(&system, &file, &dest, "route").unwrap() + "Host *\n    BatchMode yes\n";
            std::fs::write(&file, text).unwrap();
            for (tag, expected) in [("route-0", ""), ("route-1", " -P route-0 "), ("unrelated", " -P route-1 ")] {
                let output = std::process::Command::new(&system.ssh)
                    .args(["-G", "-F"])
                    .arg(&file)
                    .args(["-P", tag, "--", "first"])
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
                if tag == "route-0" {
                    assert!(!String::from_utf8_lossy(&output.stdout).lines().any(|line| line.starts_with("proxycommand ")));
                }
                assert!(String::from_utf8_lossy(&output.stdout).contains(expected), "{}", String::from_utf8_lossy(&output.stdout));
            }
        }
    }
}
