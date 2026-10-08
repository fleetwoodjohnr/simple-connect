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
| Saved passwords and key passphrases | System keyring (Secret Service: GNOME Keyring, KWallet…) **or** `vault.bin` | Keyring: protected by your login. Vault: Argon2id (64 MiB, 3 passes, 4 lanes) → XChaCha20-Poly1305, random salt, fresh nonce per write, header authenticated. |
| Trusted host keys | `~/.local/share/simple-connect/known_hosts` | 0600, OpenSSH format. |
| Logs | `~/.local/state/simple-connect/logs/` | Directory 0700, rotated daily (7 files), redacted. |
| Control sockets, generated SSH configs | `$XDG_RUNTIME_DIR/simple-connect/` | tmpfs, 0700, removed on exit; stale ones are cleaned at startup. |

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
signature verifies against the public key built into the app. Until a release key is
configured (see [BUILDING.md](BUILDING.md)), every update is rejected. Distribution
packages (deb/rpm) should be updated through your package manager.

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
| Dependencies | `npm audit`: no findings. `cargo audit`: no vulnerabilities (after updating `time` and `plist`/`quick-xml`); two informational warnings remain in Tauri's GTK3 stack — `glib` `VariantStrIter` unsoundness (API not used here) and the unmaintained build-time `proc-macro-error`. Both audits run before each release. |

Known limitations: the first connection to a server is trust-on-first-use; a
compromised webview could drive the UI (accept prompts, type into terminals); X11
clipboard managers may retain copied text; Windows and macOS are not yet supported.
