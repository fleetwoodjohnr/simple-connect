//! Recognises a password prompt waiting at the end of terminal output (sudo, su,
//! doas), so the app can *offer* the SSH login password. Nothing is sent from
//! here: sending needs the user's keypress and is checked again in the backend.
//!
//! Only the last line counts, after stripping terminal escape sequences. Prompts
//! naming a user must name the session's user, and an SSH password prompt for
//! another host (a nested `ssh`) is never offered.

use std::sync::LazyLock;

use regex::Regex;

const TAIL: usize = 512;

static ESCAPES: LazyLock<Regex> = LazyLock::new(|| {
    // CSI sequences, OSC strings (BEL or ST terminated) and two-byte escapes.
    Regex::new(r"\x1b\[[0-9;?<=>!]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]").expect("static regex")
});

static PROMPTS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^\[sudo\] password for (?P<user>[^:\s]+):$",
        r"^\[sudo: authenticate\] password:$",
        r"^password:$",
        r"^doas \((?P<user>[^@\s)]+)@[^)\s]+\) password:$",
        r"^(?P<user>[^@\s']+)@(?P<host>[^'\s]+)'s password:$",
        r"^\((?P<user>[^@\s)]+)@(?P<host>[^)\s]+)\) password:$",
    ]
    .iter()
    .map(|p| Regex::new(&format!("(?i){p}")).expect("static regex"))
    .collect()
});

pub struct PromptDetector {
    tail: Vec<u8>,
    user: Option<String>,
    host: String,
    /// A matching prompt is currently waiting.
    pub showing: bool,
}

impl PromptDetector {
    pub fn new(user: Option<&str>, host: &str) -> Self {
        Self { tail: Vec::with_capacity(TAIL), user: user.map(str::to_owned), host: host.to_owned(), showing: false }
    }

    /// Feeds terminal output. Returns `Some(visible)` when the prompt appears or goes away.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<bool> {
        self.tail.extend_from_slice(bytes);
        if self.tail.len() > TAIL {
            self.tail.drain(..self.tail.len() - TAIL);
        }
        let now = self.matches();
        (now != self.showing).then(|| {
            self.showing = now;
            now
        })
    }

    /// The user typed or the password was sent: forget the current prompt.
    /// Returns whether a prompt was showing.
    pub fn reset(&mut self) -> bool {
        self.tail.clear();
        std::mem::take(&mut self.showing)
    }

    fn matches(&self) -> bool {
        let text = String::from_utf8_lossy(&self.tail);
        let text = ESCAPES.replace_all(&text, "");
        let line = text.rsplit('\n').next().unwrap_or_default();
        let line = line.rsplit('\r').next().unwrap_or_default().trim();
        PROMPTS.iter().any(|re| {
            re.captures(line).is_some_and(|c| {
                let user_ok = match (c.name("user"), &self.user) {
                    (Some(u), Some(mine)) => u.as_str() == mine,
                    _ => true,
                };
                let host_ok = c.name("host").is_none_or(|h| h.as_str().eq_ignore_ascii_case(&self.host));
                user_ok && host_ok
            })
        })
    }
}

/// Whether an authentication prompt asks for the password of the session's
/// target (and so may be remembered for reuse). `ssh_password_prompt` is true
/// for OpenSSH's own `user@host's password:`; otherwise it is a
/// keyboard-interactive prompt, which newer OpenSSH prefixes with `(user@host)`.
pub fn is_login_prompt(prompt: &str, ssh_password_prompt: bool, user: Option<&str>, host: &str, direct: bool) -> bool {
    let p = prompt.trim();
    if ssh_password_prompt {
        let Some((who, h)) = p.strip_suffix("'s password:").and_then(|w| w.rsplit_once('@')) else { return false };
        return h.eq_ignore_ascii_case(host) && user.is_none_or(|u| u == who);
    }
    static KBD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)^(?:\((?P<user>[^@\s)]+)@(?P<host>[^)\s]+)\)\s*)?password:$").expect("static regex"));
    KBD.captures(p).is_some_and(|c| match c.name("host") {
        Some(h) => h.as_str().eq_ignore_ascii_case(host) && user.is_none_or(|u| c.name("user").is_some_and(|cu| cu.as_str() == u)),
        // Without the prefix the prompt could come from a jump host.
        None => direct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> PromptDetector {
        PromptDetector::new(Some("pw"), "192.168.1.25")
    }

    #[test]
    fn detects_common_prompts() {
        for prompt in [
            "[sudo] password for pw: ",
            "\x1b[1m[sudo] password for pw:\x1b[0m ",
            "[sudo: authenticate] Password: ",
            "Password: ",
            "doas (pw@atlas) password: ",
            "\x1b]0;title\x07Password:",
        ] {
            let mut d = det();
            assert_eq!(d.feed(format!("$ sudo id\r\n{prompt}").as_bytes()), Some(true), "{prompt:?}");
        }
    }

    #[test]
    fn ignores_prompts_for_someone_else() {
        for prompt in ["[sudo] password for root: ", "bob@192.168.1.25's password: ", "pw@otherhost's password: ", "(pw@other) Password: "]
        {
            assert_eq!(det().feed(prompt.as_bytes()), None, "{prompt:?}");
        }
        assert_eq!(det().feed(b"pw@192.168.1.25's password: "), Some(true));
    }

    #[test]
    fn only_the_last_line_counts() {
        let mut d = det();
        assert_eq!(d.feed(b"Password: "), Some(true));
        assert_eq!(d.feed(b"\r\nSorry, try again.\r\n$ "), Some(false), "more output hides it");
        assert_eq!(d.feed(b"echo Password: is a word\r\n"), None);
        // A prompt split across chunks.
        let mut d = det();
        assert_eq!(d.feed(b"[sudo] passw"), None);
        assert_eq!(d.feed(b"ord for pw: "), Some(true));
        assert!(d.reset());
        assert!(!d.showing);
    }

    #[test]
    fn login_prompts_must_be_for_the_target() {
        assert!(is_login_prompt("pw@192.168.1.25's password: ", true, Some("pw"), "192.168.1.25", true));
        assert!(!is_login_prompt("ops@bastion's password: ", true, Some("pw"), "192.168.1.25", false));
        assert!(is_login_prompt("(pw@192.168.1.25) Password: ", false, Some("pw"), "192.168.1.25", false));
        assert!(!is_login_prompt("(ops@bastion) Password: ", false, Some("pw"), "192.168.1.25", false));
        assert!(is_login_prompt("Password: ", false, None, "nas", true));
        assert!(!is_login_prompt("Password: ", false, None, "nas", false), "unprefixed prompt behind a jump host");
        assert!(!is_login_prompt("Verification code: ", false, None, "nas", true));
    }
}
