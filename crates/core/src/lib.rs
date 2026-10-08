//! Security-critical core of Simple Connect. Has no Tauri/GTK dependency so every
//! rule here can be unit-tested in isolation. See ARCHITECTURE.md.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod app;
pub mod discovery;
pub mod logging;
pub mod paths;
pub mod profiles;
pub mod quick_connect;
pub mod security;
pub mod settings;
pub mod sftp;
pub mod ssh;
pub mod storage;
pub mod validate;
