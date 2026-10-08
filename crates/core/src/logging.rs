//! Centralised, privacy-conscious logging.
//!
//! The first line of defence is that secrets never reach `tracing`: secret types
//! (`secrecy::SecretString`, vault keys) don't implement `Display` and redact their
//! `Debug`; askpass replies, terminal input and clipboard contents are never logged.
//! [`redact`] is the backstop, applied to every formatted line before it is written.
//!
//! Logs are written to `<state>/logs`, rotated daily and limited to 7 files. The
//! directory is 0700 (see [`crate::paths`]).

use std::borrow::Cow;
use std::io::{self, Write};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

static RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        // Whole or truncated PEM / OpenSSH private key blocks.
        (r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)", "[REDACTED PRIVATE KEY]"),
        // key=value / key: value / "key": "value" for secret-looking keys. Unquoted
        // values are redacted to end of line: over-redaction beats a partial leak.
        (
            r#"(?i)\b(password|passphrase|passwd|pwd|secret|token|api[_-]?key|authorization)("?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\r\n]+)"#,
            "${1}${2}[REDACTED]",
        ),
        (r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]"),
    ]
    .into_iter()
    .map(|(re, with)| (Regex::new(re).expect("static regex"), with))
    .collect()
});

pub fn redact(line: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(line);
    for (re, with) in RULES.iter() {
        if let Cow::Owned(s) = re.replace_all(&out, *with) {
            out = Cow::Owned(s);
        }
    }
    out
}

/// Writer adaptor that redacts each formatted event. `tracing_subscriber::fmt`
/// formats an event into one buffer and writes it in one call.
pub struct Redacting<W>(pub W);

impl<W: Write> Write for Redacting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_all(redact(&String::from_utf8_lossy(buf)).as_bytes())?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Installs the global subscriber. Keep the returned guard alive for the life of
/// the process; dropping it flushes buffered lines. Level comes from `SC_LOG`
/// (`info` by default).
pub fn init(log_dir: &Path) -> Result<WorkerGuard, Box<dyn std::error::Error + Send + Sync>> {
    let appender = Builder::new()
        .rotation(Rotation::DAILY)
        .filename_prefix("simple-connect")
        .filename_suffix("log")
        .max_log_files(7)
        .build(log_dir)?;
    let (file, guard) = tracing_appender::non_blocking(appender);
    let filter = EnvFilter::try_from_env("SC_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr = cfg!(debug_assertions).then(|| fmt::layer().with_writer(|| Redacting(io::stderr())));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_ansi(false).with_writer(move || Redacting(file.clone())))
        .with(stderr)
        .try_init()?;
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets() {
        let cases = [
            ("login password=hunter2 ok", "login password=[REDACTED]"),
            ("Passphrase: correct horse", "Passphrase: [REDACTED]"),
            (r#"{"token": "abc.def", "user":"u"}"#, r#"{"token": [REDACTED], "user":"u"}"#),
            ("Authorization: Bearer eyJhbGciOi.x.y", "Authorization: [REDACTED]"),
            ("hdr bearer abc123", "hdr Bearer [REDACTED]"),
            (
                "k=-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY----- tail",
                "k=[REDACTED PRIVATE KEY] tail",
            ),
            ("cut -----BEGIN RSA PRIVATE KEY-----\nMIIEow", "cut [REDACTED PRIVATE KEY]"),
            ("connected to nas as admin", "connected to nas as admin"),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), want, "{input:?}");
        }
    }

    #[test]
    fn writer_redacts() {
        let mut w = Redacting(Vec::new());
        w.write_all(b"secret=xyz\n").unwrap();
        assert_eq!(w.0, b"secret=[REDACTED]\n");
    }
}
