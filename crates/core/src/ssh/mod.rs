//! Orchestration of the system OpenSSH client. See ARCHITECTURE.md.

pub mod config;
pub mod engine;
pub mod errors;
pub mod helper;
pub mod keys;
pub mod known_hosts;
pub mod mux;
pub mod openssh;
pub mod prompt;
pub mod shell;
pub mod terminal;

#[derive(Debug, Clone, thiserror::Error)]
pub enum SshError {
    #[error("OpenSSH wasn't found. Install the OpenSSH client (package openssh-clients or openssh-client).")]
    OpenSshMissing,
    #[error("The installed OpenSSH is too old ({0}). Version 8.5 or newer is required.")]
    OpenSshTooOld(String),
}
