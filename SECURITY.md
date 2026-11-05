# Security

Simple Connect is built to fail closed: whenever a security decision can't be made
with certainty, the connection is refused. See [THREAT_MODEL.md](THREAT_MODEL.md) for
threats and mitigations, and [SSH_SECURITY.md](SSH_SECURITY.md) for the SSH policy.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Report privately through
the repository's *Security → Report a vulnerability* (GitHub private advisories), with:

* the version (Settings → About) and your OpenSSH version (`ssh -V`),
* steps to reproduce, and what an attacker gains.

You'll get an acknowledgement within a week. Fixes are released before details are
published, and reporters are credited unless they prefer otherwise.

## What is stored, and where

| Data | Location | Protection |
|---|---|---|
| Connections, folders, tags, device MAC addresses, settings | `~/.local/share/simple-connect/app.db` | File 0600, directory 0700. **No secrets** — only opaque references. |
| Saved passwords (SSH and remote desktop) and key passphrases | System keyring (Secret Service: GNOME Keyring, KWallet…) **or** `vault.bin` | Keyring: protected by your login. Vault: Argon2id (64 MiB, 3 passes, 4 lanes) → XChaCha20-Poly1305, random salt, fresh nonce per write, header authenticated. |
| Trusted host keys | `~/.local/share/simple-connect/known_hosts` | 0600, OpenSSH format. |
| Logs | `~/.local/state/simple-connect/logs/` | Directory 0700, rotated daily (7 files), redacted. |
| Control sockets, generated SSH configs | `$XDG_RUNTIME_DIR/simple-connect/` | tmpfs, 0700, removed on exit; stale ones are cleaned at startup. |
| On the remote computer: sockets of desktop servers Simple Connect starts | `~/.cache/simple-connect/rd/` | Directory 0700, sockets 0600, no TCP ports. Removed when sharing stops or the virtual desktop ends. |

Files opened in the editor are kept **in memory only** — no local temporary copy is
written — and are saved back atomically (temporary file + rename on the server).

Logs never contain passwords, private keys, passphrases, tokens, clipboard contents
or terminal input. Secret types can't be formatted into logs, and a redaction filter
scrubs key blocks and `password=`/`token=`-style values as a backstop.

## Defaults

* Host-key verification: always on; changed keys are blocked until you decide.
* Modern algorithms only; legacy algorithms are a per-connection opt-in with a warning.
* Agent and X11 forwarding: off. Tunnels: only the ones you create; loopback only
  unless you confirm otherwise.
* Clipboard: text you copy from Simple Connect is cleared after 30 s if it's still there.
* Multi-line paste into a terminal asks first.
* Automatic reconnect never re-sends commands.
* The SSH login password is offered at `sudo`/`su` prompts only when you press Enter.
  It stays in the backend, is forgotten when you disconnect, and can be turned off
  globally or per connection.
* The network scanner runs only when you press Scan, and only on your own local subnet.
* No telemetry, accounts or network services; updates are checked only when you ask.

## App lock

With a lock password (or the encrypted vault's master password), the app can lock
manually, after inactivity, when the computer sleeps and when the desktop session
locks (systemd-logind). While locked, the window content is covered and inert, saved
secrets are unavailable to connections, and the vault key is dropped from memory.
Open connections keep running.

Secrets in memory are wrapped in `secrecy`/`zeroize` types and wiped when dropped. This
reduces, but cannot eliminate, copies in memory: the operating system, the webview and
OpenSSH hold their own buffers. Treat a compromised user account as compromised.

## Updates

The in-app updater accepts an update only over HTTPS and only if its minisign
signature verifies against the public key built into the app and its signed version
matches the manifest. Automatic checks run at startup and daily, and can be disabled
in Settings → About. Download/installation requires explicit action after closing
sessions, unfinished transfers, and unsaved files. DEB/RPM updates use native package
installation with administrator authorization. Signing credentials live in repository
Actions secrets and an ignored private backup, never in version control.

## Security review (pre-release)

Reviewed against the threat model before 0.1.0:

| Area | Result |
|---|---|
| Command/option injection | No local shell is ever spawned; all `ssh`/`ssh-keygen` calls use argument arrays with `--` before the destination. Hosts, users, ports, jump specs, key paths and tunnel specs are validated by strict grammars (unit-tested with hostile inputs). The only remote shell strings (checksum, copy, system info, start folder) use a single POSIX quoting function tested against `/bin/sh` with hostile names. |
| Path traversal | Remote names are validated per component before being joined to local paths; downloads write to `.sc-part` files opened with `O_NOFOLLOW`; the app's private directories are refused by every local file command. Tested with `../`, `/`, NUL, newline and bidi names against a real server. |
| Host keys | Unknown → refused unless trusted; changed → refused unless trusted after typing the host name; helper crash → refused. Covered by integration tests against a real sshd, including a key rotation. |
| Secrets | Not in argv (tested via `/proc`), not in SQLite, not in logs (redaction tests), not returned to the webview. Saved only after a successful sign-in; auto-filled only for OpenSSH's own password prompt. |
| IPC | 76 commands, each in an explicit allow-list generated at build time; no shell/fs/http plugins; strict CSP without remote origins; every argument validated in Rust. Tauri's `freezePrototype` is disabled because xterm.js is incompatible with it. |
| Imports | Size-limited, unknown fields rejected, every profile re-validated, security policy never imported; tampered database rows are skipped on read. |
| Dependencies | `npm audit`: no findings. `cargo audit` gates every release. The 0.1.0 preparation updated vulnerable cryptographic, TLS, root-certificate, and zlib dependencies, and removed unused legacy ZIP update extraction. One unreachable RSA advisory is documented below; informational upstream maintenance notices remain visible. |

Known limitations: the first connection to a server is trust-on-first-use; a
compromised webview could drive the UI (accept prompts, type into terminals); X11
clipboard managers may retain copied text; initial Windows installers have no Authenticode certificate and macOS uses ad-hoc signing without notarization.


## RSA advisory exception

`.cargo/audit.toml` ignores only [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html),
the Marvin timing attack on RSA private-key operations. Upstream currently provides
no patched release. The dependency enters through IronRDP's CredSSP stack; Simple
Connect never constructs its smart-card credentials or performs RSA decryption:

- `crates/core/src/desktop/rdp.rs` constructs only `Credentials::UsernamePassword`,
  configures rustls with `with_no_client_auth`, and passes `None` for the Kerberos
  configuration to `connect_finalize`.
- IronRDP connector 0.10's `credssp.rs` maps that `None` configuration directly to
  `ClientMode::Ntlm`. Its private RSA smart-card path requires
  `Credentials::SmartCard`, which the app does not construct.
- SSH/key generation uses external OpenSSH; no SSH private key is passed to the Rust
  `rsa` dependency. Public certificate verification does not expose a private RSA key.

Reassess this exception before adding smart-card authentication, Kerberos/PKU2U,
client TLS certificates, or any Rust RSA decryption/signing. Keep all other advisories
as release blockers. The exception does not disable informational audit output.
