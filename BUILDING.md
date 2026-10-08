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

The in-app updater (Tauri updater plugin) only installs updates whose minisign
signature matches the public key compiled into the app. The repository ships a
placeholder key, so **all updates are rejected until you configure your own**:

1. Generate a key pair once, and keep the private key offline (never commit it):

   ```sh
   npm run tauri signer generate -- -w ~/.tauri/simple-connect.key
   ```

2. Put the printed public key in `src-tauri/tauri.conf.json` → `plugins.updater.pubkey`,
   and set `plugins.updater.endpoints` to the HTTPS URL of your `latest.json`
   (for GitHub releases: `https://github.com/<owner>/<repo>/releases/latest/download/latest.json`).

3. Enable updater artifacts in `tauri.conf.json` → `bundle.createUpdaterArtifacts: true`,
   then build with the key available only in the build environment:

   ```sh
   TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/simple-connect.key)" \
   TAURI_SIGNING_PRIVATE_KEY_PASSWORD=… npm run tauri build
   ```

4. Publish the AppImage, its `.sig` file and a `latest.json` describing them.

HTTP endpoints are refused by the updater. Distribution packages (deb/rpm) are normally
updated by the system package manager rather than the in-app updater.

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

The SSH engine, storage and UI are cross-platform. Windows needs a named-pipe helper
transport, the Windows Credential Manager store and one `ssh` per view (Win32-OpenSSH has
no ControlMaster); macOS needs the Keychain store and a short runtime-socket path.
These seams are marked `ponytail:` in the code.
