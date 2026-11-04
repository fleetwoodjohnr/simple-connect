# Threat Model

## Scope and assets

**Assets:** SSH private keys and passphrases, saved passwords (SSH and remote desktop),
vault master password, trusted host keys, connection inventory (hostnames, usernames),
the contents of remote and local files, terminal I/O, remote desktop screens and input,
and the integrity of the application binary.

**Trust boundaries:**
1. The network and remote servers. These are untrusted until host-key verification
   succeeds, and even after that only partially trusted (a server can be malicious).
2. The webview. Treated as untrusted input to the Rust backend.
3. Imported files: profile exports and `~/.ssh/config`.
4. Other local users. Untrusted; the same local user is trusted.
5. The update channel.

**Out of scope:** an attacker who already runs code as the same local user or as root
(they can read process memory, keylog, or replace binaries); a compromised OpenSSH
binary; hardware attacks.

## Threats

### T1. Stolen laptop
- **Attack path:** The disk is read offline. The attacker looks for credentials,
  connection inventory and known hosts.
- **Impact:** Lateral movement into every saved server.
- **Mitigation:**
  - No plaintext secrets on disk. Passwords and passphrases live in the OS keyring or
    in a vault encrypted with Argon2id + XChaCha20-Poly1305.
  - Private keys stay in OpenSSH's encrypted format; key generation recommends a
    passphrase.
  - App files are 0600 in 0700 directories.
  - App auto-lock drops the vault key from memory.
  - SECURITY.md recommends full-disk encryption.
- **Residual risk:** Hostnames, usernames and the known_hosts file are readable without
  disk encryption. The keyring is only as strong as the login password. Unencrypted
  user-supplied keys stay unencrypted.

### T2. Malicious remote SSH server
- **Attack path:** A server the user connects to (legitimately or through a hijacked
  host) sends crafted data:
  - terminal escape sequences (OSC 52 clipboard writes, title spoofing, huge output)
  - keyboard-interactive prompts imitating password prompts
  - SFTP listings with hostile names (`../`, `/`, NUL, newlines, bidi overrides)
  - oversized files or endless directory trees
  - forwarded-channel requests
- **Impact:** Clipboard poisoning, credential phishing, local file overwrite, resource
  exhaustion.
- **Mitigation:**
  - xterm.js runs without the clipboard (OSC 52) addon, and output is batched with
    backpressure.
  - Saved passwords are filled only for OpenSSH's own password prompt for the expected
    `user@host`. Keyboard-interactive prompts are always shown and labelled as coming
    from the server.
  - Every remote name is validated as a single path component before it is joined
    locally: `/`, `..`, `.` and NUL are rejected, the result must stay under the target
    directory, and files are created without following symlinks.
  - Bidi and control characters are rendered visibly.
  - The editor has a size limit, and recursive transfers have depth and count guards.
  - The generated config sets `ForwardAgent no` and `ForwardX11 no`, and remote
    forwards exist only when the user creates them.
  - Bugs in the SSH protocol parser are OpenSSH's attack surface, which is the
    most-audited client available.
- **Residual risk:** A malicious server can still show misleading terminal content.
  Users can be socially engineered into typing secrets into a shell.

### T3. Man-in-the-middle
- **Attack path:** The attacker intercepts the TCP connection (ARP/DNS spoofing, rogue
  Wi-Fi) and presents their own host key.
- **Impact:** Credential theft and full session compromise.
- **Mitigation:**
  - `StrictHostKeyChecking yes` is enforced by `ssh` itself and the policy block comes
    first in the generated config.
  - Unknown hosts require explicit trust after the full SHA-256 fingerprint is shown.
  - A changed key gets a blocking warning showing both fingerprints; rejecting is the
    default and accepting requires typing the hostname.
  - The helper fails closed: on a crash or timeout `ssh` refuses.
  - Jump hosts are verified the same way.
  - `UpdateHostKeys no` means keys never change silently.
- **Residual risk:** The first connection is trust-on-first-use. Users can be tricked
  into trusting a wrong fingerprint on first contact. Mitigated by showing the
  fingerprint prominently and documenting out-of-band verification.

### T4. Compromised network (passive or active)
- **Attack path:** Traffic is recorded for later decryption, or downgrade attacks are
  attempted.
- **Impact:** Disclosure of session contents.
- **Mitigation:**
  - The algorithm allow-list is modern AEAD ciphers with post-quantum-hybrid and
    Curve25519 kex, intersected with what local OpenSSH supports.
  - CBC ciphers, SHA-1 kex/signatures, DSA, 3DES and RC4 are excluded by default.
  - Strict-kex (Terrapin countermeasure) is handled by OpenSSH.
  - "Legacy crypto" is a per-profile opt-in with a persistent warning.
- **Residual risk:** Traffic analysis (timing, volume) still reveals activity patterns.
  A legacy-enabled profile is weaker by the user's choice.

### T5. Malicious filename
- **Attack path:** A remote or local file named e.g. `;rm -rf ~`, `$(curl …)`,
  `-oProxyCommand=…`, `a\nb`, `‮gpj.exe` or `../../.bashrc`.
- **Impact:** Command injection, option injection, path traversal, user deception.
- **Mitigation:**
  - Filenames are only ever passed to SFTP protocol operations (structured, no shell)
    or as `Path` arguments.
  - The few remote shell commands (checksum, system info) use fixed programs, with
    filenames passed through one tested POSIX single-quote function after `--`.
  - Local process arguments are arrays; no local shell is ever spawned.
  - Names are validated on join (see T2).
  - The UI shows control and bidi characters visibly.
- **Residual risk:** Remote checksum depends on the remote shell being POSIX. On
  non-POSIX servers it is disabled, not attempted.

### T6. Command injection (local)
- **Attack path:** Crafted profile fields (hostname `-oProxyCommand=sh`, username with
  `;`, port `22 -o…`, jump host `a;b`) or quick-connect strings flow into `ssh`
  arguments. OpenSSH turns `ProxyJump` into a shell `ProxyCommand`.
- **Impact:** Arbitrary code execution as the user.
- **Mitigation:**
  - `std::process::Command` with argument arrays; no `sh -c` anywhere.
  - `--` comes before the destination.
  - Hostnames are restricted to DNS names, IPv4 and IPv6 literals; none may start with `-`.
  - Usernames reject control characters, whitespace, shell metacharacters and a leading `-`.
  - Ports are parsed as `u16` and must be non-zero.
  - Jump specs use a strict `[user@]host[:port]` grammar with the same character sets.
  - Users never get a free-form `-o` passthrough.
  - OpenSSH ≥ 9.6 also rejects metacharacters in user and host names.
- **Residual risk:** The user's own `~/.ssh/config` can define `ProxyCommand`,
  `LocalCommand` or `Match exec`. This is the user's trusted file, and including it can
  be turned off in settings.

### T7. Path traversal
- **Attack path:** The frontend (or a malicious server listing) asks the backend to
  read or write outside the intended location, e.g. `../../.ssh/authorized_keys`, or a
  symlink planted in a download directory.
- **Impact:** Overwriting dotfiles or reading private data.
- **Mitigation:**
  - Local paths must be absolute and may not contain `..`. Paths inside the
    application's own data directories are refused, with symlinks resolved, by every
    local file command (listing, transfers, exports).
  - Downloads create files without following symlinks and confirm overwrites.
  - Remote names are validated per component.
  - Edited files are written back to the exact remote path the user opened.
- **Residual risk:** The local panel deliberately lets the user browse their own home
  directory, so a compromised webview could upload readable user files to a connected,
  verified host (see T8).

### T8. Compromised frontend or webview
- **Attack path:** An XSS through rendered remote data (filenames, banners, prompts) or
  a webview bug lets an attacker run JavaScript in the app.
- **Impact:** The attacker can call any exposed command.
- **Mitigation:**
  - React escapes all text; there is no `dangerouslySetInnerHTML`.
  - CSP is `default-src 'self'` with no remote origins, and devtools are off in release
    builds. (Tauri's `freezePrototype` hardening is off: xterm.js assigns `toString` on
    namespace objects, which a frozen `Object.prototype` forbids.)
  - Capabilities expose only our own commands; there are no shell, fs or http plugins.
  - Every command validates its arguments as untrusted input.
  - No command returns secrets to the frontend. Passwords flow from the keyring to
    askpass inside Rust.
  - Host-key trust requires a UI decision, but the final enforcement is `ssh`'s
    known_hosts. Changed-key acceptance additionally requires typing the hostname.
- **Residual risk:** A compromised webview could drive the UI: accept prompts on the
  user's behalf, send keystrokes to open terminals, or transfer files between local and
  connected hosts. This is accepted, and the CSP and lack of remote content make
  injection difficult.

### T9. Malicious imported configuration
- **Attack path:** The user imports a profile export or a `~/.ssh/config` from someone
  else that contains injection payloads, a huge file, a weakened policy, or a jump-host
  chain through an attacker's machine.
- **Impact:** Command injection, a downgraded policy, or traffic routed via an attacker.
- **Mitigation:**
  - Imports are parsed into typed structures with size limits, and every field goes
    through the same validators as manual input.
  - Unknown keys are rejected.
  - Imported profiles never carry security policy (legacy crypto, host-key settings) or
    raw `-o` options.
  - Imported `~/.ssh/config` entries are read-only aliases. Other files are never
    `Include`d; only the user's own `~/.ssh/config` can be.
  - Imported jump chains are shown in the route view before connecting, and host keys
    are still verified.
- **Residual risk:** A user can knowingly connect through an attacker-provided bastion.
  Host verification still protects the end-to-end session to the target.

### T10. Stolen configuration database
- **Attack path:** `app.db` is copied via backup, a sync tool or malware.
- **Impact:** Disclosure of the connection inventory.
- **Mitigation:**
  - The database contains no secrets, only opaque `secret_ref` IDs.
  - The file is 0600.
  - Exports exclude secrets by default; including them forces the encrypted backup
    format.
- **Residual risk:** The inventory itself (hostnames, users, tags) is disclosed.

### T11. Leaked logs
- **Attack path:** Logs are attached to bug reports or read by backup tools.
- **Impact:** Credential or privacy leaks.
- **Mitigation:**
  - Secret types (`SecretString`, the vault key) have no `Display` and a redacting
    `Debug`.
  - Askpass replies, terminal input and clipboard contents are never logged.
  - A redaction layer scrubs private-key blocks, `password=`/`token=` patterns and
    bearer tokens as a backstop.
  - Log files are 0600, rotated, and stored locally only.
  - There is no telemetry.
- **Residual risk:** Logs contain hostnames and usernames for diagnostics. The user can
  clear logs from the settings.

### T12. Clipboard theft
- **Attack path:** Other applications read the clipboard, or a clipboard manager keeps
  history. A remote host writes the clipboard via OSC 52.
- **Impact:** Disclosure of copied secrets or commands; injection of malicious paste
  content.
- **Mitigation:**
  - The app copies only on explicit user action, and never copies secrets
    automatically.
  - Optional auto-clear runs after 15, 30 or 60 seconds, and only clears if the
    clipboard still holds what the app copied.
  - OSC 52 is disabled.
  - Multi-line paste into the terminal asks for confirmation (bracketed paste is
    respected).
- **Residual risk:** Under X11 any client can read the clipboard while it is set, and
  clipboard managers may keep history.

### T13. Update supply-chain attack
- **Attack path:** The update server, CDN or DNS is compromised and serves a malicious
  build.
- **Impact:** Code execution on every installation.
- **Mitigation:**
  - Tauri updater over HTTPS with mandatory minisign signature verification against a
    public key embedded at build time. Unsigned or wrongly signed updates are refused.
  - The private signing key is kept offline and never in the repository.
  - Updates are user-initiated, and the release notes and version are shown.
  - Distribution packages (deb/rpm) rely on the distribution's own signing.
  - Dependencies are pinned through lockfiles and checked with `cargo audit` and
    `npm audit` before each release.
- **Residual risk:** If the signing key is compromised, attackers can ship updates.
  The project also inherits dependency (crates.io/npm) compromise risk at build time.

### T14. Local IPC hijack (helper socket)
- **Attack path:** Another local process connects to the helper socket to obtain
  passwords, or to answer host-key prompts.
- **Impact:** Credential theft, or forced trust of a host key.
- **Mitigation:**
  - The socket lives in `$XDG_RUNTIME_DIR/simple-connect/` (0700, owned by the user).
  - Peer UID is checked with `SO_PEERCRED`.
  - Every request must carry the per-session random token, which is known only to that
    `ssh` child's environment (`/proc/<pid>/environ` is readable only by the same user).
  - The helper only *forwards* prompts; it never accepts trust decisions from the
    socket. Decisions come from the UI.
- **Residual risk:** Same-user malware is out of scope; it can already read the
  keyring session.

### T15. Secrets on process command lines
- **Attack path:** `/proc/<pid>/cmdline` is world-readable, so a passphrase passed as
  `ssh-keygen -N secret` would be exposed.
- **Impact:** Credential disclosure to other local users.
- **Mitigation:** Secrets never appear in argv. They are passed only through the
  askpass stdout pipe. An integration test scans `/proc/*/cmdline` while a key is being
  generated.
- **Residual risk:** None known.

### T16. Reusing the login password at terminal prompts
- **Attack path:** With "Offer your SSH password at sudo prompts" on (the default), the
  login password of a password-authenticated session is kept in memory. A program on
  the server prints something that looks like a password prompt to make the user press
  Enter, or the user runs `ssh` to another host from inside the session.
- **Impact:** The login password is typed into something other than sudo/su.
- **Mitigation:**
  - Only the server the session is connected to can receive the password, and it
    already received it during password authentication.
  - Nothing is sent without the user pressing Enter (or clicking the hint).
  - The prompt is recognised by the backend from the terminal's last line: `sudo`,
    sudo-rs, `su`'s `Password:` and `doas`. Prompts naming a user or host must name the
    session's own, so a nested `ssh` to another host is never offered the password.
  - Any keystroke withdraws the offer, and the backend refuses to send unless it
    currently sees a prompt itself. The password never crosses IPC to the webview.
  - The password kept is the one that actually signed in to the target, never one
    typed for a jump host. It is zeroized when the session closes, and is unavailable
    while the app is locked.
  - The behaviour can be turned off globally or per connection.
- **Residual risk:** A fake prompt with terminal echo on would display the password on
  screen (only that server's own output can cause this). A compromised webview could
  type commands that capture it on that server.

### T17. Network scanning
- **Attack path:** The scanner is used, or abused through a compromised webview, to
  probe networks other than the user's own, or to run continuously.
- **Impact:** Unwanted traffic towards third-party networks; the user is mistaken for an
  attacker.
- **Mitigation:**
  - Scans run only when the user presses Scan; nothing runs in the background.
  - The UI picks a network by id. The backend recomputes the attached subnets and
    accepts only RFC 1918, RFC 6598 (100.64.0.0/10) and link-local ranges, capped at
    1024 addresses (/22). Larger subnets are narrowed to the /24 around this computer.
  - Each address gets one TCP connection attempt to one port, and the SSH
    identification line is read. Nothing is sent and no authentication is attempted.
  - One scan at a time, and it can be stopped.
  - Only a summary line (counts, no addresses) is logged.
- **Residual risk:** Network monitoring may still flag a sweep of the local subnet.
  Names come from reverse DNS/mDNS and can be spoofed by devices on the LAN, so the
  host-key check, not the name, is what identifies a server.

### T18. Malicious remote desktop server
- **Attack path:** A connected computer (or a program on it running a fake VNC/RDP
  server on its loopback) sends crafted protocol data, pixels, cursors or clipboard
  text, asks for credentials, or tries to steer the client to weaker security.
- **Impact:** Memory corruption in the client, credential phishing, clipboard
  poisoning, or a downgraded session.
- **Mitigation:**
  - RDP is parsed and decoded in Rust (IronRDP). The webview receives only bounded
    rectangles of RGBA pixels, cursors up to 256×256 and text clipboard data up to
    1 MB. VNC security handshakes (VNC password, Apple Remote Desktop) are done in Rust
    with bounded reads; the rest is parsed by noVNC in the sandboxed webview.
  - Only TLS and NLA are offered for RDP; the legacy RC4 RDP security is refused,
    including when a server selects it. Unsupported VNC security types are refused,
    never improvised. The negotiation runs inside SSH, so it can't be downgraded on
    the network.
  - Password prompts use Simple Connect's own text, never the server's. Saved or
    reused passwords are tried once; after a failure the user is asked.
  - No audio, drive, printer or smart-card channels are offered. The clipboard is
    text only, and remote clipboard text reaches the local clipboard only by explicit
    action unless the user turns on automatic sharing (off by default).
- **Residual risk:** A server can still show misleading pixels, including fake
  dialogs. With automatic clipboard sharing on, a server can place text on the local
  clipboard. Bugs in IronRDP or noVNC are part of the attack surface.

### T19. Screen sharing and remote desktop services exposed
- **Attack path:** Starting a desktop server, or turning on Remote Desktop, exposes
  the desktop to the network, to other local users of that computer, or keeps it
  shared after the user is done.
- **Impact:** Someone else sees or controls the desktop.
- **Mitigation:**
  - All traffic goes through `ssh -W` over the verified SSH connection, to the remote
    loopback or to a Unix socket. Nothing listens on a local port.
  - Servers Simple Connect starts (x0vncserver, wayvnc, Xvnc) listen only on a
    0600 Unix socket in a 0700 directory in the user's home, with no TCP port, so only
    that account can connect. Screen shares are tied to the SSH channel and stop when
    it closes; virtual desktops end when the user signs out of them.
  - Launch scripts are fixed text; the only values passed are validated numbers and
    names, and the socket path they report is checked before use.
  - Setup steps run only after a confirmation showing the exact commands, in a
    visible terminal, with sudo asking as usual. Turning on Windows Remote Desktop
    leaves the firewall closed. The documentation recommends keeping RDP ports
    firewalled where a server (GNOME) listens on all interfaces.
- **Residual risk:** Services the user turns on themselves (GNOME Remote Desktop,
  Windows Remote Desktop, macOS Screen Sharing) listen according to their own
  settings; Simple Connect can't restrict them. A virtual desktop keeps running, with
  lingering enabled, until the user signs out of it.

### T20. Remote desktop credentials
- **Attack path:** Desktop passwords are stored insecurely, sent to the wrong
  computer, or the SSH password is reused where it shouldn't be.
- **Impact:** Credential disclosure or account compromise.
- **Mitigation:**
  - Desktop passwords live in the same credential store as SSH passwords, apart
    per kind (VNC password, account password), are saved only after they worked,
    are deleted with the profile, and never cross IPC to the webview.
  - The SSH password is reused only for an account of the same name, only when reuse
    is enabled, and only towards the remote computer's own loopback through the same
    verified SSH connection, which already received it.
  - RDP certificates aren't checked against a CA (the identity comes from SSH), but
    the TLS handshake proves possession of the certificate's key and CredSSP binds the
    credentials to it. TLS keys are never logged (`SSLKEYLOGFILE` is ignored).
  - Kerberos is not used, so no credentials are sent to a KDC.
- **Residual risk:** The RDP password is held in memory as a plain string by IronRDP
  for the duration of sign-in. Same-user malware is out of scope.

## Design consequences

* Fail closed: every verification path treats an error, timeout or unexpected input as
  "deny".
* Do not implement cryptography: the SSH protocol is handled by OpenSSH; the vault uses
  RustCrypto `argon2` + `chacha20poly1305`; randomness comes from the OS CSPRNG.
* Keep the frontend dumb: it renders state and forwards user decisions; it never holds
  secrets.
