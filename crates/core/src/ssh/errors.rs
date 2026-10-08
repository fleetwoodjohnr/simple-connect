//! Turns `ssh` exit status and stderr into a friendly message plus details.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    DnsFailed,
    Refused,
    Timeout,
    Unreachable,
    AuthFailed,
    TooManyAuthFailures,
    HostKeyRejected,
    HostKeyChanged,
    NoCommonAlgorithms,
    ClosedByRemote,
    ConfigProblem,
    Cancelled,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectFailure {
    pub kind: FailureKind,
    pub message: String,
    /// Technical output (non-debug stderr lines), shown in an expandable section.
    pub details: String,
}

impl FailureKind {
    pub fn message(self) -> &'static str {
        match self {
            FailureKind::DnsFailed => "The server's name couldn't be found. Check the host name and your network or DNS settings.",
            FailureKind::Refused => "The server refused the connection. Check the port, and that an SSH server is running.",
            FailureKind::Timeout => "The server didn't respond in time. It may be offline, or a firewall may be blocking the port.",
            FailureKind::Unreachable => "The server can't be reached from this network.",
            FailureKind::AuthFailed => "Sign-in was rejected. Check the user name, password or key.",
            FailureKind::TooManyAuthFailures => {
                "The server stopped after too many sign-in attempts. Choose a specific key in the connection settings."
            }
            FailureKind::HostKeyRejected => "The connection was stopped because the server's identity wasn't trusted.",
            FailureKind::HostKeyChanged => "The connection was stopped because the server's identity has changed since you last connected.",
            FailureKind::NoCommonAlgorithms => {
                "The server only supports outdated encryption. You can allow legacy algorithms for this connection, \
                 at reduced security."
            }
            FailureKind::ClosedByRemote => "The remote server unexpectedly closed the SSH connection.",
            FailureKind::ConfigProblem => "OpenSSH couldn't use the SSH configuration. See the details below.",
            FailureKind::Cancelled => "The connection was cancelled.",
            FailureKind::Unknown => "The connection failed.",
        }
    }
}

/// Classifies a failed `ssh` run from its stderr (debug lines included or not).
pub fn classify(stderr_lines: &[String]) -> ConnectFailure {
    let relevant: Vec<&str> = stderr_lines.iter().map(String::as_str).filter(|l| !l.starts_with("debug") && !l.trim().is_empty()).collect();
    let has = |needle: &str| relevant.iter().any(|l| l.contains(needle));
    let kind = if has("REMOTE HOST IDENTIFICATION HAS CHANGED") {
        FailureKind::HostKeyChanged
    } else if has("Host key verification failed") || has("host key is known for") || has("KnownHostsCommand") {
        FailureKind::HostKeyRejected
    } else if has("Could not resolve hostname") {
        FailureKind::DnsFailed
    } else if has("Connection refused") {
        FailureKind::Refused
    } else if has("timed out") {
        FailureKind::Timeout
    } else if has("No route to host") || has("Network is unreachable") {
        FailureKind::Unreachable
    } else if has("Too many authentication failures") {
        FailureKind::TooManyAuthFailures
    } else if has("Permission denied") {
        FailureKind::AuthFailed
    } else if has("Unable to negotiate") || has("no matching") {
        FailureKind::NoCommonAlgorithms
    } else if has("Bad owner or permissions") || has("Bad configuration option") || has("Unsupported option") {
        FailureKind::ConfigProblem
    } else if has("Connection closed by") || has("Connection reset") || has("kex_exchange_identification") || has("closed by remote host") {
        FailureKind::ClosedByRemote
    } else {
        FailureKind::Unknown
    };
    let tail = relevant.len().saturating_sub(20);
    ConnectFailure { kind, message: kind.message().to_owned(), details: relevant[tail..].join("\n") }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(lines: &[&str]) -> FailureKind {
        classify(&lines.iter().map(|s| s.to_string()).collect::<Vec<_>>()).kind
    }

    #[test]
    fn classifies_common_failures() {
        assert_eq!(kind(&["ssh: Could not resolve hostname nope: Name or service not known"]), FailureKind::DnsFailed);
        assert_eq!(kind(&["ssh: connect to host 127.0.0.1 port 1: Connection refused"]), FailureKind::Refused);
        assert_eq!(kind(&["ssh: connect to host 10.9.9.9 port 22: Connection timed out"]), FailureKind::Timeout);
        assert_eq!(kind(&["pw@h: Permission denied (publickey,password)."]), FailureKind::AuthFailed);
        assert_eq!(
            kind(&["No ED25519 host key is known for [h]:2222 and you have requested strict checking.", "Host key verification failed."]),
            FailureKind::HostKeyRejected
        );
        assert_eq!(
            kind(&["@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @", "Host key verification failed."]),
            FailureKind::HostKeyChanged
        );
        assert_eq!(
            kind(&[
                "Unable to negotiate with 1.2.3.4 port 22: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1"
            ]),
            FailureKind::NoCommonAlgorithms
        );
        assert_eq!(kind(&["kex_exchange_identification: read: Connection reset by peer"]), FailureKind::ClosedByRemote);
        assert_eq!(kind(&["debug1: Connection closed by x", "weird"]), FailureKind::Unknown, "debug lines are ignored");
    }
}
