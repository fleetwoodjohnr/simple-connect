Simple Connect 0.1.0 provides an SSH terminal, SFTP file browser, tunnels, network discovery, and remote desktop connections.

Downloads cover x64 and ARM64 Windows, macOS, and Linux:
- Windows: run the architecture-matched setup.exe. OpenSSH is included; no SSH server or system service is installed.
- macOS: open the architecture-matched DMG and copy Simple Connect to Applications. These builds are ad-hoc signed, without Apple notarization. Allow the application in Privacy & Security when prompted.
- Linux: install the DEB/RPM matching your distribution or use the AppImage. OpenSSH 8.5+ must be installed. Ubuntu 22.04+, Debian 12+, or compatible glibc 2.35+ systems with GTK/WebKitGTK 4.1 are required.

Updates are checked automatically at startup and daily while running. Settings → About provides manual checks and an opt-out. Download and installation require selecting Install and restart after closing sessions and finishing/canceling transfers and unsaved edits. Linux packages may request administrator authorization. Every update is verified against the Simple Connect release-signing key.

Windows builds initially have no Authenticode publisher certificate and may show SmartScreen/unknown-publisher prompts. The bundled Microsoft OpenSSH 10.4.0.0p1-Preview client is an upstream preview; authentication is independent for each terminal, transfer, or tunnel and MFA may prompt more than once. macOS requires version 13+, Windows x64 requires Windows 10 22H2+/11, and ARM64 requires Windows 11.

Profiles, saved credentials, host keys, and settings survive upgrades. No account or telemetry is used. Update checks contact GitHub; turn them off to disable those requests.
