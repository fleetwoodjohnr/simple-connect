//! Parses Quick Connect input such as `user@host`, `host:2222`,
//! `ssh -p 2222 user@host`, `ssh -J bastion user@host` or `ssh://user@host:2222`.
//!
//! Only a small set of options is understood (`-p -l -J -i`); everything else is
//! rejected rather than passed through, so pasted text can never inject `-o` options.

use std::path::PathBuf;

use serde::Serialize;

use crate::validate::{self, Host, JumpHop, User, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickConnect {
    pub user: Option<User>,
    pub host: Host,
    pub port: Option<u16>,
    pub jump: Vec<JumpHop>,
    pub identity_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuickConnectError {
    #[error(transparent)]
    Invalid(#[from] ValidationError),
    #[error("Enter a destination such as user@host.")]
    MissingDestination,
    #[error("The option {0} isn't supported in Quick Connect.")]
    UnsupportedOption(String),
    #[error("The option {0} needs a value.")]
    MissingValue(String),
    #[error("{0} is given twice with different values.")]
    Conflict(&'static str),
    #[error("Unexpected “{0}”. Remote commands aren't supported in Quick Connect.")]
    Unexpected(String),
}

type Result<T> = std::result::Result<T, QuickConnectError>;

pub fn parse(input: &str) -> Result<QuickConnect> {
    let mut tokens = input.split_whitespace().peekable();
    if tokens.peek() == Some(&"ssh") {
        tokens.next();
    }

    let (mut user, mut port, mut jump, mut identity, mut dest) = (None, None, Vec::new(), None, None);

    while let Some(tok) = tokens.next() {
        if tok.len() > 1 && tok.starts_with('-') {
            let flag_len = 1 + tok[1..].chars().next().map_or(0, char::len_utf8);
            let flag = &tok[..flag_len];
            let value = match &tok[flag_len..] {
                "" => tokens.next().ok_or_else(|| QuickConnectError::MissingValue(flag.into()))?,
                attached => attached,
            };
            match flag {
                "-p" => set_once(&mut port, validate::port(value)?, "Port")?,
                "-l" => set_once(&mut user, User::parse(value)?, "User")?,
                "-J" => jump = validate::jump_chain(value)?,
                "-i" => identity = Some(validate::identity_file(value)?),
                _ => return Err(QuickConnectError::UnsupportedOption(flag.into())),
            }
        } else if dest.is_none() {
            dest = Some(tok);
        } else {
            return Err(QuickConnectError::Unexpected(tok.into()));
        }
    }

    let dest = dest.ok_or(QuickConnectError::MissingDestination)?;
    let dest = dest.strip_prefix("ssh://").map(|d| d.trim_end_matches('/')).unwrap_or(dest);
    let (dest_user, rest) = match dest.rsplit_once('@') {
        Some((u, r)) => (Some(User::parse(u)?), r),
        None => (None, dest),
    };
    let (host, dest_port) = validate::split_host_port(rest).ok_or_else(|| ValidationError::InvalidHost(rest.into()))?;

    if let Some(u) = dest_user {
        set_once(&mut user, u, "User")?;
    }
    if let Some(p) = dest_port {
        set_once(&mut port, validate::port(p)?, "Port")?;
    }

    Ok(QuickConnect { user, host: Host::parse(host)?, port, jump, identity_file: identity })
}

fn set_once<T: PartialEq>(slot: &mut Option<T>, value: T, what: &'static str) -> Result<()> {
    match slot {
        Some(existing) if *existing != value => Err(QuickConnectError::Conflict(what)),
        _ => {
            *slot = Some(value);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> QuickConnect {
        parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    #[test]
    fn destinations() {
        let q = ok("user@192.168.1.100");
        assert_eq!((q.user.unwrap().as_str(), q.host.as_str(), q.port), ("user", "192.168.1.100", None));

        let q = ok("ssh user@example.com -p 2222");
        assert_eq!((q.host.as_str(), q.port), ("example.com", Some(2222)));

        let q = ok("  ssh -p2222 -l admin nas  ");
        assert_eq!((q.user.unwrap().as_str(), q.port), ("admin", Some(2222)));

        assert_eq!(ok("pi:2200").port, Some(2200));
        assert_eq!(ok("ssh://root@[fd00::2]:2022/").port, Some(2022));
        assert_eq!(ok("ssh://root@[fd00::2]:2022/").host.as_str(), "fd00::2");
        assert_eq!(ok("fe80::1").host.as_str(), "fe80::1");
        assert_eq!(ok("a@corp@host").user.unwrap().as_str(), "a@corp");

        let q = ok("ssh -J ops@bastion:22,jump2 db");
        assert_eq!(q.jump.len(), 2);

        assert!(ok("-i /home/u/.ssh/id_ed25519 host").identity_file.is_some());
    }

    #[test]
    fn rejects() {
        use QuickConnectError::*;
        assert_eq!(parse(""), Err(MissingDestination));
        assert_eq!(parse("ssh"), Err(MissingDestination));
        assert_eq!(parse("ssh -oProxyCommand=sh host"), Err(UnsupportedOption("-o".into())));
        assert_eq!(parse("-ü host"), Err(UnsupportedOption("-ü".into())));
        assert_eq!(parse("ssh host -p"), Err(MissingValue("-p".into())));
        assert_eq!(parse("ssh host uptime"), Err(Unexpected("uptime".into())));
        assert_eq!(parse("a@host -l b"), Err(Conflict("User")));
        assert_eq!(parse("host:22 -p 23"), Err(Conflict("Port")));
        assert!(matches!(parse("user@-oProxyCommand=x"), Err(Invalid(_))));
        assert!(matches!(parse("us;er@host"), Err(Invalid(_))));
        assert!(matches!(parse("host:99999"), Err(Invalid(_))));
        assert!(matches!(parse("-i relative/key host"), Err(Invalid(_))));
        assert!(matches!(parse("-J 'x;id' host"), Err(Invalid(_))));
    }
}
