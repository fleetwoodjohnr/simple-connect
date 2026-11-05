# Building and packaging

Install the prerequisites from [DEVELOPMENT.md](DEVELOPMENT.md), then:

```sh
npm install
npm run tauri build                          # release build + .deb, .rpm and AppImage
npm run tauri build -- --bundles deb rpm     # only some formats
```

Packages are written to `target/release/bundle/{deb,rpm,appimage}/`.

| Format | Runtime requirement declared |
|---|---|
| `.deb` | `openssh-client` |
| `.rpm` | `openssh-clients` |
| AppImage | uses the host's `ssh`; WebKitGTK is bundled |

The application binary is also the SSH helper (askpass / KnownHostsCommand), so no
separate helper executable is shipped.

Release builds use LTO, a single codegen unit, `panic = "abort"` and stripped symbols
(see the workspace `Cargo.toml`).

## Signed updates

The in-app updater only installs packages whose minisign signature matches the release
public key compiled into the application. The endpoint is the public GitHub Releases
`latest.json`; no account or update server is required.

Automatic checks run after settings load at startup and once every 24 hours while the
application is open. Disable them in Settings → About, where **Check now** remains
available. Updates download only after **Install and restart** is selected. Close
connection tabs, save unsaved files, and finish or cancel pending transfers before
installing. Downloads are verified before installation; offline checks and failed
installations leave the application usable.

Updates preserve the installed format: NSIS on Windows, application bundles on macOS,
and AppImage, DEB, or RPM on Linux. DEB/RPM installation may require administrator
approval. Windows installers restart the app; macOS/Linux relaunch after installation.
Update signing is separate from OS publisher signing: macOS builds use ad-hoc signatures
and Windows installers currently show an unknown-publisher prompt.

For local signed builds, provide `TAURI_SIGNING_PRIVATE_KEY` (the private key file path
or contents) and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, then run `npm run tauri build`.
Never commit the private key or regenerate it for each release. See the release guide
below for CI secrets, backup requirements, and publication checks.

## Release checklist

```sh
cargo audit                                  # cargo install cargo-audit
npm audit --omit=dev
cargo clippy --workspace --all-targets
cargo test --workspace && npm test
cargo test -p simple-connect-core --tests -- --ignored
tests/e2e/run.sh
```

## Flatpak

Not provided yet. A Flatpak needs the host's `ssh` (`flatpak-spawn --host`) or a bundled
OpenSSH, plus portal access for the Secret Service and logind; this is planned once the
core features are stable.

## Other platforms

Windows ships a pinned OpenSSH client and uses independent SSH processes because
Win32-OpenSSH does not support ControlMaster. Additional channels can require additional
MFA prompts. Its prompt helper uses restricted named pipes and saved credentials use
Windows Credential Manager. macOS uses Keychain and short private runtime socket paths.
The encrypted vault remains available when the native credential store cannot be used.

## v0.1.0 cross-platform releases

Platform configuration is merged automatically by the Tauri CLI: Linux produces DEB,
RPM and AppImage, Windows produces per-user NSIS installers, and macOS produces DMG
and application archives. Both x86_64 and aarch64 builds run on native GitHub runners.
Windows preparation runs `scripts/windows-openssh.ps1 -Architecture x86_64` (or
`aarch64`) under PowerShell. It verifies pinned upstream archive checksums and bundles
only client executables, libraries, and notices. Never install the upstream SSH server
service as part of application packaging.

Updater signing is enabled. The public key is committed in tauri.conf.json. The matching
private key is in the ignored `.release-keys/` directory on the release machine. An
independent backup is stored at `/home/jrf/.local/share/simple-connect-release/` on that
machine, with owner-only directory and file permissions; also keep an offline backup.
Do not delete or rotate this key casually: installed
clients trust it. GitHub Actions uses `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` secrets. Never expose them to pull-request jobs.

Run the Release workflow manually for an unpublished six-target rehearsal. Tag a
validated commit `vMAJOR.MINOR.PATCH` after synchronizing the npm, Cargo workspace,
and Tauri versions. The tag run checks signatures and all ten updater target entries,
then uploads a draft release and publishes only after all files are present. Artifacts
and signatures must not be renamed or modified after manifest generation. If publishing
is interrupted, inspect the draft before retrying; the workflow never overwrites a
published release. Withdraw a faulty release from latest, then publish a higher patch
version with the same key. Automatic downgrades are disabled.

`node --test scripts/release-manifest.node.mjs` tests signature rejection and manifest
coverage. `node scripts/check-version.mjs` checks release versions. A final validation
must install packages on each native platform and prove an older isolated test build
updates to the candidate; never publish that test version to the public feed.
