# Development

## Prerequisites (Linux)

* Rust (stable, 1.90+) via [rustup](https://rustup.rs) — `source ~/.cargo/env` if `cargo` isn't on `PATH`
* Node.js 20+ and npm
* OpenSSH client 8.5+ (`ssh -V`)
* WebKitGTK 4.1 and GTK 3 development files:

```sh
# Fedora
sudo dnf install webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel gtk3-devel \
  librsvg2-devel libappindicator-gtk3-devel libxdo-devel openssl-devel
# Debian / Ubuntu
sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libgtk-3-dev \
  librsvg2-dev libayatana-appindicator3-dev libxdo-dev libssl-dev build-essential
```

* For integration tests: `podman` (or set up `docker` with the same commands)
* For end-to-end tests: `cargo install tauri-driver` and `WebKitWebDriver`
  (Fedora: part of `webkit2gtk4.1`; Debian: `webkit2gtk-driver`)

The security core (`crates/core`) needs none of the GTK packages, so it can be built and
tested anywhere Rust and OpenSSH are available.

## Run

```sh
npm install
npm run tauri dev          # Vite dev server + app with hot reload
```

Logs go to stderr in debug builds and to `~/.local/state/simple-connect/logs/`.
Set `SC_LOG=debug` (any `tracing` filter) for more detail.

## Layout

```
crates/core/        security-critical logic; no GUI dependencies (see ARCHITECTURE.md)
  src/app/          session manager, prompts, transfers, tunnels (driven by the UI)
  src/ssh/          OpenSSH orchestration: config, master, helper, known_hosts, terminal, keys
  src/sftp/         SFTP client, streaming transfers, local file operations
  src/security/     credential stores (keyring, vault), lock verifier, session-lock watcher
  src/profiles/     connection profiles, ~/.ssh/config reader, export/import
  tests/            integration tests against a real sshd in podman
src-tauri/          thin Tauri shell: IPC commands, state, event bridge
src/                React + TypeScript frontend
tests/sshd/         disposable test SSH server image
tests/e2e/          WebDriver smoke test of the real app
```

## Tests

```sh
cargo test --workspace                       # unit tests (core: validation, crypto, parsing, …)
npm test                                     # frontend unit tests (vitest)

# Integration: real OpenSSH server in podman (builds tests/sshd automatically)
cargo test -p simple-connect-core --tests -- --ignored --test-threads=4

# Real Secret Service round trip (needs a desktop keyring)
cargo test -p simple-connect-core --lib keyring_roundtrip -- --ignored

# End to end: drives the app through WebDriver against the test server
npm run tauri build -- --debug --no-bundle
tests/e2e/run.sh                             # screenshots land in target/e2e/
```

The integration tests cover: password and key login, wrong and cancelled passwords,
unknown and changed host keys, secrets never appearing in `/proc/*/cmdline`, the
multiplexed terminal (and PTY size), SFTP with hostile file names, a 96 MiB
upload/download interrupted and resumed with SHA-256 verification, atomic editor
saves, local and SOCKS tunnels, folder transfers with conflict resolution, automatic
reconnect with saved-password reuse, key generation and passphrase changes.

`desktop_it` runs against `tests/desktop` (sshd plus Xvfb, headless Sway, TigerVNC and
xrdp). It covers detection, X11 and Wayland screen sharing, virtual desktops across
dropped connections, VNC passwords, RDP over TLS with input and resize, a legacy-only
RDP server being refused, and forwarding errors. The end-to-end test uses the same
image. See [REMOTE_DESKTOP.md](REMOTE_DESKTOP.md) for what is tested where.

Before sending changes:

```sh
cargo clippy --workspace --all-targets && cargo fmt --check
npx tsc --noEmit && npm test
```

## Conventions

* **New IPC command:** implement it in `src-tauri/src/commands/`, add it to
  `generate_handler!` in `main.rs` **and** to `COMMANDS` in `src-tauri/build.rs`. The build
  script generates the capability that allows it; anything not listed is rejected.
* Treat every IPC argument as hostile: validate with `simple_connect_core::validate` or a
  typed `Deserialize` that validates, and return `CmdError` with a user-facing message.
* Never pass secrets on a command line, never log them, never send them to the webview.
* Never build a local shell command. Remote commands use fixed text plus
  `ssh::shell::quote`.
* Keep security logic in `crates/core` with tests; keep the Tauri layer as glue.
* UI copy: plain language, sentence case, errors that say what happened and what to do.
