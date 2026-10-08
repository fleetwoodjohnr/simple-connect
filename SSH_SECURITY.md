# SSH security

How Simple Connect uses OpenSSH, and which guarantees that gives you.

## The engine is OpenSSH

Simple Connect does not implement SSH. Every connection is made by the system `ssh`
client (OpenSSH **8.5 or newer**; the version is checked at startup and older clients
are refused). The application only:

* writes a per-connection configuration file with a strict policy,
* answers OpenSSH's prompts (passwords, passphrases, host-key decisions) through a
  local helper, and
* multiplexes the terminal, SFTP and tunnels over OpenSSH's ControlMaster socket.

All cryptography — key exchange, ciphers, MACs, signatures, key parsing — is OpenSSH's.

## Algorithm policy

Each connection gets an explicit allow-list, intersected with what the local
`ssh -Q` reports, so names an older client doesn't know are dropped rather than
causing an error.

| | Allowed, in order of preference |
|---|---|
| Key exchange | `mlkem768x25519-sha256`, `sntrup761x25519-sha512`(`@openssh.com`), `curve25519-sha256`(`@libssh.org`), `ecdh-sha2-nistp521/384/256`, `diffie-hellman-group-exchange-sha256`, `diffie-hellman-group18-sha512`, `-group16-sha512`, `-group14-sha256` |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr` |
| MACs (CTR ciphers only) | `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `umac-128-etm` (`@openssh.com`), `hmac-sha2-512`, `hmac-sha2-256` |
| Host keys / user keys | OpenSSH's defaults **minus** `ssh-rsa` (SHA-1), `ssh-dss` and their certificate forms. RSA keys use SHA-2 signatures; `RequiredRSASize 2048` on OpenSSH ≥ 9.1. |

Host-key algorithms use OpenSSH's removal syntax (`-ssh-rsa,…`) instead of a
replacement list, so OpenSSH keeps preferring the algorithm whose key you already
trust for that host.

**Never allowed**, even in compatibility mode: DES, 3DES, RC4/arcfour, SSH protocol 1,
MD5 MACs, `none` cipher.

### Legacy (compatibility) mode

For old network equipment, a single saved connection can opt in to: `diffie-hellman-group14-sha1`,
`diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1`, AES-CBC, HMAC-SHA1 and
`ssh-rsa` (SHA-1) signatures with `RequiredRSASize 1024`.

* It can only be turned on from the connection's settings, after a confirmation. It is
  never part of an import or the quick-connect syntax.
* While connected, the status bar and the connection's security panel say
  "Connected with legacy algorithms" with an amber lock.
* When a server only offers obsolete algorithms, the error says so and points to this option.

## Host-key verification

Verification is always on and cannot be disabled.

The generated configuration sets:

```
StrictHostKeyChecking yes        # unknown or mismatching keys abort the connection
CheckHostIP no
UpdateHostKeys no                # keys never change silently
KnownHostsCommand "<app>" --sc-known-hosts %I %H %t %K
UserKnownHostsFile <app data>/known_hosts ~/.ssh/known_hosts
```

OpenSSH reads both known_hosts files (and `/etc/ssh/ssh_known_hosts*`), then runs
the `KnownHostsCommand`, i.e. Simple Connect, with the key the server offered. The app:

1. checks that the key blob's embedded algorithm name matches the claimed type, and
   that the host field has no whitespace or control characters,
2. looks the host up in **every** file OpenSSH reads, with `ssh-keygen -F` (handles
   hashed names, `[host]:port` and wildcards),
3. decides:

| Situation | Result |
|---|---|
| Key already known | Nothing is printed; OpenSSH matches it itself. |
| `@revoked` | The helper exits with an error; OpenSSH aborts. |
| Certificate | Left to OpenSSH and your `@cert-authority` lines. |
| Host unknown | **Trust dialog**: host, IP (direct connections), key type, SHA-256 fingerprint and its picture. |
| Different key known | **Changed-key warning**: both fingerprints, the possible causes, **Disconnect** focused; trusting requires typing the host name. |

On trust, the line is appended to the app's `known_hosts` (and, only if you turned it
on, to `~/.ssh/known_hosts`) and printed for OpenSSH. If you decline, or the helper
fails, times out or crashes, it exits non-zero, which makes OpenSSH terminate the
connection. **Every failure path denies.**

Jump hosts are verified the same way: OpenSSH passes the generated configuration (`-F`)
to the `ssh -W` processes it starts for `ProxyJump`.

### The fingerprint picture

Next to every fingerprint, Simple Connect draws a 7×7 symmetric glyph derived from the
SHA-256 bytes (like OpenSSH's `VisualHostKey`). The same key always draws the same
picture, so a changed key is noticeable at a glance. It supplements the full
fingerprint; compare the text when it matters.

## Authentication

| Method | How |
|---|---|
| SSH agent | OpenSSH talks to `SSH_AUTH_SOCK` directly (works with FIDO2 keys held by the agent). |
| Key files | Passed to OpenSSH with `-i`; paths containing `%`, `$`, quotes or control characters are refused because OpenSSH expands tokens in them. |
| FIDO2 security keys (`ed25519-sk`, `ecdsa-sk`) | Native OpenSSH. "Touch your key" appears as a notice; PIN prompts open a dialog. |
| Certificates | Native OpenSSH (`CertificateFile` in your `~/.ssh/config`, or a `-cert.pub` next to the key). |
| Password / keyboard-interactive | OpenSSH asks through `SSH_ASKPASS` (forced). |

### Saved passwords are filled in narrowly

A saved password is only supplied for OpenSSH's own `user@host's password:` prompt,
when `user@host` matches the saved connection, once per attempt. Keyboard-interactive
prompts contain text chosen by the server, so they are always shown to you and never
auto-filled. A password you ask to save is stored only **after** sign-in succeeds.

Secrets never appear in process arguments (`/proc/*/cmdline` is world-readable). The
integration tests scan every process's command line while a secret is in flight.

### Reusing the login password at sudo prompts

For password-authenticated sessions, the password that signed in to the target can be
offered when `sudo`, `su` or `doas` asks for it inside the terminal (on by default; it
can be turned off in Settings → Security or per connection).

* The backend watches the terminal's last line for a known prompt and shows a hint.
  **Enter** sends the password and **Esc** declines; any other key types normally and
  withdraws the offer.
* The password is written to the terminal by the backend. It never travels to the
  webview, is never logged, and is zeroized when the session ends.
* It is offered only if the prompt names the session's user (and host, for SSH-style
  prompts). A password typed for a jump host is never kept.

## The helper channel

`ssh` re-executes Simple Connect's own binary as askpass / KnownHostsCommand. That
short-lived process:

* connects to a Unix socket in `$XDG_RUNTIME_DIR/simple-connect/` (directory 0700,
  socket 0600),
* is accepted only if the peer UID matches (`SO_PEERCRED`) **and** it presents the
  per-connection random token (256 bits) passed in its environment,
* forwards the prompt and prints the answer. It never decides anything itself.

## Hardened defaults in the generated config

```
ForwardAgent no            ForwardX11 no            ForwardX11Trusted no
PermitLocalCommand no      ClearAllForwardings yes  EscapeChar none
ControlMaster no           ControlPersist no        BatchMode no
ServerAliveInterval 30     ServerAliveCountMax 3    ConnectTimeout 15
```

Port forwards exist only when you create them in the tunnel manager. Listening on a
non-loopback address needs an explicit confirmation.

Your `~/.ssh/config` (if enabled) and `/etc/ssh/ssh_config` are `Include`d **after** the
policy block. OpenSSH uses the first value it sees for each option, so they can add
settings (users, keys, proxies) but cannot weaken the policy. The files are never
modified.

## Checking it yourself

The generated configuration for a live connection is in
`$XDG_RUNTIME_DIR/simple-connect/<session>.conf`. To see what OpenSSH resolves for a host:

```sh
ssh -G -F "$XDG_RUNTIME_DIR"/simple-connect/<session>.conf host | grep -Ei 'kex|cipher|mac|hostkey|stricthost'
```
