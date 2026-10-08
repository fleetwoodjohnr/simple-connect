//! The single place where a string is embedded in a remote shell command.
//!
//! SSH sends commands to the server as one string that the remote login shell
//! parses, so remote filenames must be quoted. POSIX single quotes make every
//! character literal except `'` itself, which is written as `'\''`.

/// Quotes `s` as one POSIX shell word.
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_sh() {
        for name in
            ["plain", "with space", "it's", "'", "''", "$(id)", "`id`", "a;b|c&d", "new\nline", "-rf", "~", "*", "ünï 🚀", "\\", "\"q\""]
        {
            let out = std::process::Command::new("/bin/sh").arg("-c").arg(format!("printf %s {}", quote(name))).output().unwrap();
            assert_eq!(String::from_utf8(out.stdout).unwrap(), name, "{name:?}");
        }
    }
}
