# v0.1.0 release execution

Accepted scope: desktop Windows/macOS/Linux, x64 and ARM64; bundled Windows OpenSSH; automatic checks and explicit install/restart; no commercial OS-signing certificates.

- [x] Platform helper transports, credential stores, private data paths, discovery and lock notifications.
- [x] Independent Windows SSH connections and forwarding; Unix multiplexing retained.
- [x] Central signed updater with opt-out, progress, and work-preservation guards.
- [x] Signing key backed up locally and configured in repository Actions secrets.
- [x] Six native build jobs, installer smoke checks, release completeness/signature validation, container integration gate.
- [ ] All native jobs green, installed update rehearsal passed.
- [ ] Annotated v0.1.0 tag and complete public release published.

Publication must remain blocked on failing native packaging, signature verification, or missing targets. Never replace the existing signing key to work around a failed build.
