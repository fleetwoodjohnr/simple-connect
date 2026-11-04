# Architecture

Simple Connect is a desktop SSH terminal, SFTP and remote desktop client. It is a Tauri 2 application:
a Rust backend owns every security-relevant decision, and a React/TypeScript frontend
renders the UI inside the system webview. The SSH protocol itself is handled by the
**system OpenSSH client** (`ssh`, `ssh-keygen`); the application orchestrates it.

## Guiding decisions

| Decision | Why |
|---|---|
| Use system OpenSSH, not an in-process SSH library | OpenSSH is the reference implementation with decades of audits and fuzzing. Host-key enforcement happens inside `ssh` (`StrictHostKeyChecking yes`), so an application bug cannot accept an untrusted key. FIDO2/security keys, certificates, agents and `~/.ssh/config` work natively. |
| One ControlMaster per connection | The terminal, SFTP and tunnels share a single authenticated SSH connection (`ssh -S <socket>`), so opening the file browser never re-authenticates. |
| Security logic lives in `crates/core` | The core crate has no Tauri/GTK dependency. It is unit-tested in isolation and the Tauri layer stays a thin, auditable IPC adapter. |
| The frontend is untrusted | Every IPC argument is validated in Rust. The webview has no shell, filesystem or HTTP plugins; it can only call our allow-listed commands. |
| Secrets never touch SQLite, logs or argv | Secrets live in the OS keyring or an encrypted vault, wrapped in `secrecy`/`zeroize` types. Child processes receive them only through the askpass pipe. |

## Process model

```
┌──────────────────────────── simple-connect (user privileges) ───────────────────────────┐
│  Webview (React)  ──invoke/Channel──▶  Tauri commands ──▶ simple-connect-core           │
│                                                         │                               │
│                                     helper socket ◀─────┤  ($XDG_RUNTIME_DIR, 0700,     │
│                                    (SO_PEERCRED +       │   per-session random token)   │
│                                     session token)      │                               │
└─────────────────────────────────────────▲───────────────┼───────────────────────────────┘
                                          │               │ spawn (argument arrays only)
              simple-connect --sc-askpass │               ▼
              simple-connect --sc-known-hosts      ssh -M -S ctl.sock -N  (master, per tab)
                                          │          ├── ssh -S ctl.sock -tt      (terminal, in a PTY)
                                          └──────────├── ssh -S ctl.sock -s sftp  (SFTP over stdio)
                                                     ├── ssh -S ctl.sock -O forward|cancel (tunnels)
                                                     └── ssh -S ctl.sock -W 127.0.0.1:port|socket (remote desktop)
```

* **Master.** `ssh -F <generated config> -M -S <socket> -N -v -- <destination>` with
  stdin closed and stderr piped. It authenticates once; the `-v` output is parsed for the
  security panel (negotiated kex, cipher, MAC, host key, auth method, server version).
* **Helper mode.** `ssh` re-executes the application binary as `SSH_ASKPASS` and as the
  `KnownHostsCommand`. In helper mode `main()` returns before Tauri starts. The helper
  connects to the running app over a Unix socket, authenticates with a per-session token
  (passed via the child's environment) and the socket's peer UID, forwards the prompt or
  host key, and prints the answer. If anything fails it prints nothing and exits non-zero,
  so `ssh` fails closed.

## Generated ssh_config

Every connection gets a 0600 config file in `$XDG_RUNTIME_DIR/simple-connect/`. OpenSSH
uses the first value it finds for each option, so the policy block comes first and cannot
be weakened by the user's config:

```
Host *
    StrictHostKeyChecking yes
    KnownHostsCommand "<exe>" --sc-known-hosts %H %I %p %t %K
    UserKnownHostsFile "<data>/known_hosts" "~/.ssh/known_hosts"
    UpdateHostKeys no
    ForwardAgent no
    ForwardX11 no
    PermitLocalCommand no
    ServerAliveInterval <profile>      ServerAliveCountMax <profile>
    ConnectTimeout <profile>
    KexAlgorithms / Ciphers / MACs / HostKeyAlgorithms / PubkeyAcceptedAlgorithms
        = modern allow-list ∩ `ssh -Q …` (see SSH_SECURITY.md)
    ClearAllForwardings yes   EscapeChar none   ControlMaster no   ControlPersist no
Include ~/.ssh/config        # only if "Use ~/.ssh/config" is enabled
Include /etc/ssh/ssh_config
```

The full policy is described in [SSH_SECURITY.md](SSH_SECURITY.md).

`ssh` passes `-F` on to the `ssh -W` processes it spawns for `ProxyJump`, so bastion
hops get the same policy.

## Host-key verification

1. `ssh` reads the app's `known_hosts` and `~/.ssh/known_hosts`, then runs the
   `KnownHostsCommand` with the host, IP, port, key type and base64 key.
2. The helper sends these to the app. The app computes the SHA-256 fingerprint itself and
   looks up the host in both files (`ssh-keygen -F`, which handles hashed entries).
   * Matches a known key → return nothing; `ssh` already matched it.
   * Host unknown → **trust dialog** (host, IP, algorithm, fingerprint). Trust appends
     the key to the app's `known_hosts` and returns the line; reject returns nothing.
   * Host known with a different key → **changed-key warning** with both fingerprints.
     Rejecting is the default. Accepting requires typing the hostname and replaces the
     entry in the app file only.
3. With `StrictHostKeyChecking yes`, an empty answer, a crash or a timeout means `ssh`
   refuses to connect. `@revoked` and `@cert-authority` markers are enforced by `ssh`.

`~/.ssh/known_hosts` is never modified unless the user explicitly asks.

## Authentication

* **Keys and agent.** `ssh` reads keys and talks to the agent natively, including
  FIDO2 `-sk` keys and certificates.
* **Passwords and passphrases.** These go through askpass (`SSH_ASKPASS_REQUIRE=force`).
  * A saved password is filled automatically **only** for OpenSSH's own
    `user@host's password:` prompt, and only when `user@host` matches the expected hop.
  * Keyboard-interactive prompts contain server-controlled text, so they are always
    shown to the user.
  * PIN prompts open a dialog. "Confirm user presence" prompts appear as a non-blocking
    notice.
* **Key management.** Keys are managed with `ssh-keygen`. New passphrases are supplied
  through askpass, never on the command line.

## Remote desktop

The **Remote Desktop** view reuses the session's master. Nothing listens on a local
port, and every remote desktop server is reached on the remote computer itself.

* **Probe.** A fixed POSIX script reads the user's own sessions, tools and X sessions
  (Windows: two `reg query` commands). In parallel, `ssh -W` forwards fingerprint ports
  3389/3390 (X.224 negotiation) and 5900–5903 (RFB banner). The result is ranked
  *offers* and fixed *setup recipes*. The webview sends back a method and validated
  numbers or names, never a host, path or command.
* **Launch.** For screen sharing (TigerVNC `x0vncserver` on X11, `wayvnc` on wlroots)
  and virtual desktops (`Xvnc` plus an X session), a fixed `sh` script started with
  `ssh -T` creates a 0600 Unix socket in `~/.cache/simple-connect/rd/` and reports
  `READY <path>`.
  * A share stops when the script's stdin closes, so it lives exactly as long as the
    connection.
  * A virtual desktop runs in its own process group until its session ends, and is
    reattached on the next connection.
* **VNC.** `ssh -W <socket or 127.0.0.1:port>`. The backend performs the RFB security
  handshake (None, VNC password, Apple ARD) and presents RFB 3.8 with security None to
  noVNC in the webview. noVNC talks to an `IpcSocket` shim, which carries bytes over a
  Tauri `Channel` (with acknowledgements and backpressure) and `desktop_write`.
* **RDP.** The same forward is run by IronRDP on a dedicated thread with its own
  current-thread runtime, because IronRDP's futures aren't `Send`.
  * Security: X.224 negotiation (TLS or NLA only), then TLS via rustls with no CA
    check and no key log, then CredSSP (NTLM).
  * Display: decoded rectangles are coalesced and sent as RGBA to a `<canvas>`.
  * Input arrives as typed events (`desktop_input`).
  * Display Control resizes and reactivation are handled, and text clipboard runs over
    CLIPRDR.
* **Credentials.** Credentials use the session's prompt machinery. Saved desktop
  passwords sit under the profile's `rd_secret_ref`, split by kind. The SSH password
  is reused only for the same account.
* **Reconnects.** When the session reconnects, the view reopens the same method.

## Modules

```
crates/core/src/
  validate.rs          trust-boundary validators: hostname, username, port, paths, jump specs, file names
  quick_connect.rs     parses "user@host", "ssh -p 2222 user@host", "ssh://user@host:port", "-J"
  paths.rs             XDG directories (0700), private and atomic file writes (0600)
  logging.rs           tracing setup + redaction layer
  settings.rs          typed settings with secure defaults, clamped on load
  discovery.rs         user-initiated LAN scan: local subnets only, TCP probe + SSH banner, ARP, names
  desktop/             remote desktop: request validation, launch scripts, targets
    probe.rs           what a computer offers (fixed scripts, port fingerprints), setup recipes
    rfb.rs             VNC security handshake in the backend; the synthetic None handshake for noVNC
    rdp.rs             IronRDP connection on its own thread: TLS, NLA, decoding, input, clipboard
  app/                 the application core driven by the UI:
    mod.rs             sessions, reconnect with backoff, prompts, saved-secret autofill, terminals
    transfers.rs       transfer queue: folders, concurrency, conflicts, pause/resume, verification
    tunnels.rs         -L / -R / -D via `ssh -O forward|cancel`, restored after reconnect
    desktop.rs         a session's remote desktops: forwards, sign-in, streaming with backpressure
    sysinfo.rs         unprivileged remote system information (fixed command)
  ssh/
    openssh.rs         locate ssh/ssh-keygen, check version (>= 8.5), `ssh -Q` discovery
    config.rs          generated per-session ssh_config (policy first, then includes)
    engine.rs          ties discovery, config, helper and master together; host-key bookkeeping
    mux.rs             ControlMaster lifecycle, `-v` parsing into SecurityInfo, client arguments
    helper.rs          askpass + KnownHostsCommand bridge (Unix socket, peer UID, session token)
    known_hosts.rs     lookups via `ssh-keygen -F`, fingerprints, trust/replace
    terminal.rs        PTY running `ssh -S … -tt`, batching and backpressure
    prompt.rs          recognises sudo/su password prompts in terminal output
    keys.rs            ssh-keygen wrapper: generate (incl. FIDO2), import, change passphrase
    shell.rs           the single POSIX quoting function for remote commands
    errors.rs          stderr → friendly message + technical details
  sftp/                SFTP over the master, streaming pipelined transfers, local file ops
  security/            CredentialStore (keyring, vault), lock verifier, logind lock watcher
  profiles/            profiles and folders, ~/.ssh/config reader, export/import
  storage/             SQLite connection and forward-only migrations
src-tauri/src/
  main.rs              helper-mode dispatch, then the Tauri builder
  state.rs             process state, UI event bridge, credential-store selection
  commands/            #[tauri::command] adapters: validate → call core → map errors
src/ (React)
  components/ pages/ terminal/ file-manager/ connections/ settings/ security/ tunnels/
  desktop/ (Remote Desktop view, noVNC and RDP viewers, toolbar, scan codes)
  stores/ (zustand)  services/ (typed IPC + event bridge)  hooks/  types/
tests/sshd/            disposable OpenSSH server image for integration tests
tests/desktop/         the same plus Xvfb, Sway, TigerVNC and xrdp for remote desktop tests
tests/e2e/             WebDriver smoke test of the packaged app
```

## Data at rest

| Data | Location | Protection |
|---|---|---|
| Profiles, groups, tags, settings, tunnels | `~/.local/share/simple-connect/app.db` (SQLite) | 0600 file in a 0700 directory; no secrets, only `secret_ref` IDs |
| Passwords, passphrases | OS keyring (Secret Service / Keychain / Credential Manager) **or** `vault.bin` | keyring: OS-protected. Vault: Argon2id (64 MiB, t=3, p=4) → XChaCha20-Poly1305, random salt, fresh nonce per write, header bound as AAD |
| App lock verifier | settings | Argon2id PHC string |
| Trusted host keys | `~/.local/share/simple-connect/known_hosts` | OpenSSH format, 0600 |
| Logs | `~/.local/state/simple-connect/logs/` | 0600, rotated, redacted |
| Runtime sockets, generated configs | `$XDG_RUNTIME_DIR/simple-connect/` | 0700 tmpfs, removed on exit |

Remote files opened in the editor are held **in memory** (subject to a size limit) and
are never written to a local temporary file.

## IPC

* Commands are request/response (`invoke`). Streams such as terminal output and
  transfer progress use `tauri::ipc::Channel`.
* Every command validates its arguments in Rust before acting. Errors cross the boundary
  as `{ code, message, details }`, where `message` is user-friendly and `details` are
  technical and shown on demand.
* Capabilities grant only the application's own commands plus the dialog, clipboard,
  updater and process plugins. The CSP is `default-src 'self'` and allows no remote
  origins.

## Portability

Platform-specific code sits behind small seams:

* `CredentialStore`: Secret Service now; Windows Credential Manager and macOS Keychain later.
* Helper transport: Unix socket now; a named pipe on Windows.
* `ssh/mux.rs`: Win32-OpenSSH has historically lacked ControlMaster. There, each
  subview would run its own `ssh` (the agent or askpass keeps this transparent) without
  changing the rest of the engine.
