#!/bin/bash
# End-to-end smoke test: drives the real app through tauri-driver/WebKitWebDriver
# against a disposable sshd container. The app's data is isolated in $OUT.
#
#   npm run tauri build -- --debug --no-bundle
#   tests/e2e/run.sh [output-dir]
#
# Needs: podman, tauri-driver (cargo install tauri-driver), WebKitWebDriver, a desktop session.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-$ROOT/target/e2e}
APP=${APP:-$ROOT/target/debug/simple-connect}
PORT=${SSHD_PORT:-2299}
rm -rf "$OUT" && mkdir -p "$OUT/home/.ssh"

# The desktop image is the sshd image plus desktops (Xvnc, xrdp) for Remote Desktop.
IMAGE=simple-connect-desktop
podman build -q -t $IMAGE -f "$ROOT/tests/desktop/Containerfile" "$ROOT/tests" >/dev/null
podman rm -f sc-e2e >/dev/null 2>&1
podman run -d --rm --name sc-e2e -p 127.0.0.1:$PORT:22 $IMAGE >/dev/null
TD=""
trap 'podman rm -f sc-e2e >/dev/null 2>&1; [ -n "$TD" ] && kill -- -$TD 2>/dev/null' EXIT

export REAL_HOME=$HOME
export HOME=$OUT/home XDG_CONFIG_HOME=$OUT/home/.config XDG_DATA_HOME=$OUT/home/.local/share XDG_STATE_HOME=$OUT/home/.local/state
setsid "${TAURI_DRIVER:-tauri-driver}" --port 4444 --native-driver "$(command -v WebKitWebDriver)" >"$OUT/driver.log" 2>&1 &
TD=$!
sleep 2
APP=$APP SSHD_PORT=$PORT OUT=$OUT IMAGE=$IMAGE python3 -I "$ROOT/tests/e2e/smoke.py"
