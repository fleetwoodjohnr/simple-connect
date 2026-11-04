//! Remote desktop through the session's SSH connection.
//!
//! Every byte travels through the ControlMaster as an `ssh -W` stdio forward,
//! either to the server's own loopback (`127.0.0.1:<port>`, for RDP and existing
//! VNC servers) or to a Unix socket in a 0700 directory that the launch scripts
//! below create (x0vncserver, wayvnc, Xvnc). Nothing listens on a local port, and
//! nothing the app starts listens on a remote TCP port.
//!
//! Remote commands are fixed scripts. The only values passed to them are
//! validated numbers and names (see [`OpenRequest::validate`]).

pub mod probe;
pub mod rdp;
pub mod rfb;

use serde::{Deserialize, Serialize};

use crate::ssh::shell::quote;

/// How the desktop is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Method {
    /// Share the user's running X11 desktop with TigerVNC's x0vncserver, only while connected.
    X11,
    /// Share a running wlroots Wayland desktop with wayvnc, only while connected.
    Wayland,
    /// A private Xvnc desktop that keeps running until the user signs out of it.
    Virtual,
    /// An existing VNC server on the remote loopback.
    Vnc,
    /// An existing RDP server on the remote loopback.
    Rdp,
}

impl Method {
    pub fn is_rdp(self) -> bool {
        self == Method::Rdp
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Method::X11 => "x11",
            Method::Wayland => "wayland",
            Method::Virtual => "virtual",
            Method::Vnc => "vnc",
            Method::Rdp => "rdp",
        }
    }

    pub fn parse(s: &str) -> Option<Method> {
        [Method::X11, Method::Wayland, Method::Virtual, Method::Vnc, Method::Rdp].into_iter().find(|m| m.as_str() == s)
    }
}

/// Image quality versus bandwidth. RDP maps it to performance flags; VNC
/// quality is applied by the viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Quality {
    #[default]
    Auto,
    High,
    Balanced,
    Low,
}

/// What the UI asks to open. Untrusted until [`OpenRequest::validate`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenRequest {
    pub method: Method,
    /// Vnc / Rdp: the port on the remote loopback.
    pub port: Option<u16>,
    /// X11: the display number.
    pub display: Option<u16>,
    /// Wayland: the compositor socket name, e.g. `wayland-1`.
    pub wayland: Option<String>,
    /// Virtual: an `/usr/share/xsessions` entry (basename without `.desktop`).
    pub session: Option<String>,
    pub width: u32,
    pub height: u32,
    /// Sign-in name for RDP and macOS Screen Sharing (defaults to the SSH user).
    pub user: Option<String>,
    #[serde(default)]
    pub quality: Quality,
}

/// A validated request.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub method: Method,
    pub launch: Launch,
    /// Known up front for Vnc/Rdp; launched methods report their socket.
    pub target: Option<Target>,
    pub width: u16,
    pub height: u16,
    pub user: Option<String>,
    pub quality: Quality,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Launch {
    None,
    X11 { display: u16 },
    Wayland { socket: String },
    Virtual { session: Option<String> },
}

/// Where the forward goes. Always the remote computer itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `127.0.0.1:<port>` on the remote side.
    Tcp(u16),
    /// A socket created by a launch script (validated by [`Target::unix`]).
    Unix(String),
}

impl Target {
    /// Accepts only sockets in the launch scripts' private directory.
    pub fn unix(path: &str) -> Option<Target> {
        const DIR: &str = "/.cache/simple-connect/rd/";
        let (home, name) = path.split_once(DIR)?;
        let ok_home = home.starts_with('/')
            && home.len() > 1
            && home.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            && !home.split('/').any(|c| c == "..");
        let stem = name.strip_suffix(".sock")?;
        let ok_name = !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        // sun_path is 108 bytes on Linux, 104 on macOS.
        (ok_home && ok_name && path.len() <= 100).then(|| Target::Unix(path.to_owned()))
    }

    /// The `ssh -W` argument.
    pub fn forward_arg(&self) -> String {
        match self {
            Target::Tcp(port) => format!("127.0.0.1:{port}"),
            Target::Unix(path) => path.clone(),
        }
    }
}

/// A failure the UI can act on: `code` selects the remedy offered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopError {
    /// missing | nosession | display | forwarding | refused | unreachable | auth |
    /// cancelled | unsupported | protocol | disconnected | server | invalid
    pub code: &'static str,
    pub message: String,
    pub details: Option<String>,
}

impl DesktopError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        DesktopError { code, message: message.into(), details: None }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        let d = sanitize(&details.into(), 2000);
        self.details = (!d.is_empty()).then_some(d);
        self
    }
}

impl std::fmt::Display for DesktopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Server text shown to the user: no control characters, bounded length.
pub fn sanitize(s: &str, max: usize) -> String {
    s.chars().map(|c| if c.is_control() && c != '\n' { ' ' } else { c }).take(max).collect::<String>().trim().to_owned()
}

/// `[DOMAIN\]user` or `user@domain`, as Windows and macOS accept them.
pub(crate) fn sign_in_name(s: &str) -> Option<String> {
    let s = s.trim();
    let ok = !s.is_empty()
        && s.len() <= 104
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_alphanumeric() || " ._@\\-$".contains(c))
        && s.matches('\\').count() <= 1;
    ok.then(|| s.to_owned())
}

/// An `/usr/share/xsessions` basename, or a Wayland socket name.
pub(crate) fn plain_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && !s.starts_with(['.', '-']) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl OpenRequest {
    pub fn validate(&self) -> Result<Plan, DesktopError> {
        let bad = |m: &str| DesktopError::new("invalid", m.to_owned());
        let width = u16::try_from(self.width.clamp(640, 8192)).unwrap_or(1024);
        let height = u16::try_from(self.height.clamp(480, 8192)).unwrap_or(768);
        let user = match self.user.as_deref().filter(|u| !u.trim().is_empty()) {
            Some(u) => Some(sign_in_name(u).ok_or_else(|| bad("That sign-in name isn't valid."))?),
            None => None,
        };
        let port = || self.port.filter(|p| *p != 0).ok_or_else(|| bad("Choose a port from 1 to 65535."));
        let (launch, target) = match self.method {
            Method::Vnc | Method::Rdp => (Launch::None, Some(Target::Tcp(port()?))),
            Method::X11 => {
                let display = self.display.filter(|d| *d < 1000).ok_or_else(|| bad("Choose an X display."))?;
                (Launch::X11 { display }, None)
            }
            Method::Wayland => {
                let socket = self.wayland.clone().filter(|w| plain_name(w)).ok_or_else(|| bad("Choose a Wayland session."))?;
                (Launch::Wayland { socket }, None)
            }
            Method::Virtual => {
                let session = self.session.clone().filter(|s| !s.is_empty());
                if session.as_deref().is_some_and(|s| !plain_name(s)) {
                    return Err(bad("Choose a desktop session from the list."));
                }
                (Launch::Virtual { session }, None)
            }
        };
        Ok(Plan { method: self.method, launch, target, width, height, user, quality: self.quality })
    }
}

// ---- launch scripts -----------------------------------------------------------
//
// Each prints exactly one status line: `READY <socket>`, `MISSING <program>`,
// `NOSESSION` or `ERROR <text>`. Shares then wait on stdin: when Simple Connect
// disconnects, `read` returns and the server is stopped.

const PRELUDE: &str = r#"umask 077
d="$HOME/.cache/simple-connect/rd"
mkdir -p "$d" && chmod 700 "$d" || { echo "ERROR could not create $d"; exit 0; }
# serve SOCKET PID LOG [READY-TEXT]: waits for the socket (and the server's
# "ready" log line), reports it, then runs until our ssh closes stdin.
ready() { [ -S "$1" ] && { [ -z "$3" ] || grep -q "$3" "$2" 2>/dev/null; }; }
serve() { i=0; while ! ready "$1" "$3" "${4:-}"; do i=$((i+1))
    if [ "$i" -gt 200 ] || ! kill -0 "$2" 2>/dev/null; then echo "ERROR $(tail -n 3 "$3" 2>/dev/null | tr '\n' ' ')"; kill "$2" 2>/dev/null; rm -f "$1" "$3"; exit 0; fi
    sleep 0.1; done
  echo "READY $1"; read _ || true; kill "$2" 2>/dev/null; rm -f "$1" "$3"; }
"#;

/// `$1` display number, `$2` socket name. The X cookie is taken from the
/// environment of one of the user's programs on that display (what GDM, LightDM
/// and startx set). (x11vnc can't be used: it rejects Unix socket clients.)
const SHARE_X11: &str = r#"X=$(command -v x0vncserver || command -v x0tigervncserver) || { echo "MISSING x0vncserver"; exit 0; }
auth=""
for e in /proc/[0-9]*/environ; do
  [ -O "$e" ] || continue
  env=$(tr '\0' '\n' < "$e" 2>/dev/null) || continue
  printf '%s\n' "$env" | grep -qE "^DISPLAY=:$1(\.[0-9]+)?\$" || continue
  a=$(printf '%s\n' "$env" | sed -n 's/^XAUTHORITY=//p' | head -n 1)
  if [ -n "$a" ] && [ -r "$a" ]; then auth="$a"; break; fi
done
[ -n "$auth" ] || auth="${XAUTHORITY:-$HOME/.Xauthority}"
s="$d/$2.sock"; l="$d/$2.log"; rm -f "$s"
XAUTHORITY="$auth" "$X" -display ":$1" -rfbunixpath "$s" -rfbunixmode 0600 -rfbport -1 -SecurityTypes None -AlwaysShared >"$l" 2>&1 </dev/null &
serve "$s" $! "$l"
"#;

/// `$1` Wayland socket name, `$2` socket name.
const SHARE_WAYLAND: &str = r#"command -v wayvnc >/dev/null 2>&1 || { echo "MISSING wayvnc"; exit 0; }
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" WAYLAND_DISPLAY="$1"
[ -S "$XDG_RUNTIME_DIR/$1" ] || { echo "ERROR There is no Wayland session $1 for this user."; exit 0; }
s="$d/$2.sock"; l="$d/$2.log"; rm -f "$s" "$d/$2.ctl"
wayvnc -u -S "$d/$2.ctl" "$s" >"$l" 2>&1 </dev/null &
serve "$s" $! "$l"
rm -f "$d/$2.ctl"
"#;

/// `$1` xsessions basename or `-`, `$2` geometry. Reattaches to a running
/// virtual desktop; otherwise starts Xvnc (socket only) and the session in a
/// new process group that outlives this connection.
const VIRTUAL: &str = r#"s="$d/virtual.sock"; pf="$d/virtual.pid"; l="$d/virtual.log"
if [ -S "$s" ] && [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null; then echo "READY $s"; exit 0; fi
rm -f "$s" "$pf"
X=$(command -v Xvnc || command -v Xtigervnc) || { echo "MISSING Xvnc"; exit 0; }
x=""
[ "$1" != "-" ] && [ -r "/usr/share/xsessions/$1.desktop" ] && x="/usr/share/xsessions/$1.desktop"
if [ -z "$x" ]; then for n in xfce mate lxqt LXDE cinnamon openbox icewm fluxbox; do
  [ -r "/usr/share/xsessions/$n.desktop" ] && { x="/usr/share/xsessions/$n.desktop"; break; }; done; fi
[ -n "$x" ] || { echo "NOSESSION"; exit 0; }
cmd=$(sed -n 's/^Exec=//p' "$x" | head -n 1)
[ -n "$cmd" ] || { echo "NOSESSION"; exit 0; }
n=10; while [ -e "/tmp/.X11-unix/X$n" ] || [ -e "/tmp/.X$n-lock" ]; do n=$((n+1)); [ "$n" -gt 99 ] && { echo "ERROR No free X display number."; exit 0; }; done
setsid sh -c '
  "$8" ":$1" -rfbunixpath "$2" -rfbunixmode 0600 -rfbport -1 -localhost -SecurityTypes None -AlwaysShared -geometry "$3" -depth 24 -desktop "$4" >"$5" 2>&1 &
  x=$!
  i=0; while [ ! -e "/tmp/.X11-unix/X$1" ] && [ "$i" -lt 100 ]; do i=$((i+1)); sleep 0.1; done
  if command -v dbus-run-session >/dev/null 2>&1; then DISPLAY=":$1" SIMPLE_CONNECT_VIRTUAL=1 dbus-run-session -- sh -c "$6"; else DISPLAY=":$1" SIMPLE_CONNECT_VIRTUAL=1 sh -c "$6"; fi
  kill "$x" 2>/dev/null; rm -f "$2" "$7"
' sc "$n" "$s" "$2" "$(hostname)" "$l" "$cmd" "$pf" "$X" </dev/null >/dev/null 2>&1 &
echo $! > "$pf"
i=0; while [ ! -S "$s" ]; do i=$((i+1)); if [ "$i" -gt 150 ]; then echo "ERROR $(tail -n 3 "$l" 2>/dev/null | tr '\n' ' ')"; exit 0; fi; sleep 0.1; done
echo "READY $s"
"#;

/// Ends the virtual desktop: its whole process group.
pub const END_VIRTUAL: &str = r#"d="$HOME/.cache/simple-connect/rd"; pf="$d/virtual.pid"
if [ -f "$pf" ]; then p=$(cat "$pf"); case "$p" in ''|*[!0-9]*) ;; *) kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null ;; esac; fi
rm -f "$pf" "$d/virtual.sock" "$d/virtual.log"
"#;

/// The remote command that starts the server for `launch`, or `None` if the
/// server is already running. `name` is the share's socket name.
pub fn launch_command(launch: &Launch, width: u16, height: u16, name: &str) -> Option<String> {
    let (script, args): (&str, Vec<String>) = match launch {
        Launch::None => return None,
        Launch::X11 { display } => (SHARE_X11, vec![display.to_string(), name.to_owned()]),
        Launch::Wayland { socket } => (SHARE_WAYLAND, vec![socket.clone(), name.to_owned()]),
        Launch::Virtual { session } => (VIRTUAL, vec![session.clone().unwrap_or_else(|| "-".into()), format!("{width}x{height}")]),
    };
    let body = format!("{PRELUDE}{script}");
    let args: Vec<String> = args.iter().map(|a| quote(a)).collect();
    Some(format!("sh -c {} sc {}", quote(&body), args.join(" ")))
}

/// Interprets a launch script's status line.
pub fn parse_status(line: &str) -> Result<Target, DesktopError> {
    let line = line.trim();
    if let Some(path) = line.strip_prefix("READY ") {
        return Target::unix(path.trim()).ok_or_else(|| {
            DesktopError::new("server", "The remote desktop server reported an unexpected socket path.").with_details(path)
        });
    }
    if let Some(prog) = line.strip_prefix("MISSING ") {
        let prog = sanitize(prog, 40);
        return Err(DesktopError::new("missing", format!("{prog} isn't installed on the remote computer. Use Set up to install it.")));
    }
    if line == "NOSESSION" {
        return Err(DesktopError::new(
            "nosession",
            "No desktop environment that can run in a virtual desktop is installed (for example XFCE, MATE or LXQt). Use Set up to install one.",
        ));
    }
    let text = line.strip_prefix("ERROR").unwrap_or(line).trim();
    if text.contains("XOpenDisplay") || text.contains("Authorization required") {
        return Err(DesktopError::new(
            "display",
            "The desktop couldn't be opened. It may belong to another user, or no one is signed in on the computer's screen.",
        )
        .with_details(text));
    }
    Err(DesktopError::new("server", "The remote desktop server couldn't be started.").with_details(text))
}

/// Explains a failed `ssh -W` from the master's log.
pub fn forward_failure(master_log: &[String]) -> DesktopError {
    let line = master_log.iter().rev().take(40).find(|l| l.contains("open failed:"));
    match line {
        Some(l) if l.contains("administratively prohibited") => DesktopError::new(
            "forwarding",
            "This SSH server doesn't allow forwarding, which remote desktop needs. Its administrator can enable AllowTcpForwarding and AllowStreamLocalForwarding for your account.",
        )
        .with_details(l.as_str()),
        Some(l) if l.contains("Connection refused") => DesktopError::new(
            "refused",
            "Nothing is listening on that port on the remote computer. The remote desktop service may be turned off.",
        )
        .with_details(l.as_str()),
        Some(l) => DesktopError::new(
            "unreachable",
            "The remote desktop server couldn't be reached. It may have stopped, or the SSH server doesn't allow forwarding to it.",
        )
        .with_details(l.as_str()),
        None => DesktopError::new("unreachable", "The remote desktop server couldn't be reached through SSH."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: Method) -> OpenRequest {
        OpenRequest {
            method,
            port: None,
            display: None,
            wayland: None,
            session: None,
            width: 1280,
            height: 800,
            user: None,
            quality: Quality::Auto,
        }
    }

    #[test]
    fn validates_requests() {
        let mut r = req(Method::Rdp);
        assert!(r.validate().is_err(), "port required");
        r.port = Some(3389);
        assert_eq!(r.validate().unwrap().target, Some(Target::Tcp(3389)));

        let mut r = req(Method::X11);
        r.display = Some(0);
        assert_eq!(r.validate().unwrap().launch, Launch::X11 { display: 0 });

        let mut r = req(Method::Wayland);
        for bad in ["../x", "-x", "a b", "a;b", ""] {
            r.wayland = Some(bad.into());
            assert!(r.validate().is_err(), "{bad}");
        }
        r.wayland = Some("wayland-1".into());
        assert!(r.validate().is_ok());

        let mut r = req(Method::Virtual);
        r.session = Some("xfce; rm -rf ~".into());
        assert!(r.validate().is_err());
        r.session = Some("xfce".into());
        r.width = 100_000;
        r.height = 1;
        let p = r.validate().unwrap();
        assert_eq!((p.width, p.height), (8192, 480));

        let mut r = req(Method::Rdp);
        r.port = Some(3389);
        for ok in ["alice", "CORP\\alice", "alice@corp.example", "First Last"] {
            r.user = Some(ok.into());
            assert_eq!(r.validate().unwrap().user.as_deref(), Some(ok));
        }
        for bad in ["-oProxy", "a\nb", "a;b", "a\\b\\c", "$(id)"] {
            r.user = Some(bad.into());
            assert!(r.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn unix_targets_stay_in_the_private_directory() {
        assert!(Target::unix("/home/pw/.cache/simple-connect/rd/virtual.sock").is_some());
        assert!(Target::unix("/home/pw/.cache/simple-connect/rd/share-0a1b.sock").is_some());
        for bad in [
            "/home/pw/.cache/simple-connect/rd/../x.sock",
            "/home/pw/../../etc/.cache/simple-connect/rd/x.sock",
            "/run/x.sock",
            "relative/.cache/simple-connect/rd/x.sock",
            "/home/pw/.cache/simple-connect/rd/X.sock",
            "/home/pw/.cache/simple-connect/rd/x.sock:22",
            "/home/a b/.cache/simple-connect/rd/x.sock",
            "/.cache/simple-connect/rd/x.sock",
        ] {
            assert!(Target::unix(bad).is_none(), "{bad}");
        }
        let long = format!("/home/{}/.cache/simple-connect/rd/x.sock", "a".repeat(80));
        assert!(Target::unix(&long).is_none());
        assert_eq!(Target::Tcp(5900).forward_arg(), "127.0.0.1:5900");
    }

    #[test]
    fn status_lines() {
        assert_eq!(
            parse_status("READY /home/pw/.cache/simple-connect/rd/virtual.sock\n").unwrap(),
            Target::Unix("/home/pw/.cache/simple-connect/rd/virtual.sock".into())
        );
        assert_eq!(parse_status("READY /etc/passwd").unwrap_err().code, "server");
        assert_eq!(parse_status("MISSING x0vncserver").unwrap_err().code, "missing");
        assert_eq!(parse_status("NOSESSION").unwrap_err().code, "nosession");
        assert_eq!(parse_status("ERROR XOpenDisplay(\":0\") failed.").unwrap_err().code, "display");
        let e = parse_status("ERROR boom\u{1b}[31m").unwrap_err();
        assert_eq!((e.code, e.details.as_deref()), ("server", Some("boom [31m")));
    }

    #[test]
    fn explains_forward_failures() {
        let log = |l: &str| vec!["debug1: x".to_owned(), l.to_owned()];
        assert_eq!(forward_failure(&log("channel 2: open failed: administratively prohibited: open failed")).code, "forwarding");
        assert_eq!(forward_failure(&log("channel 2: open failed: connect failed: Connection refused")).code, "refused");
        assert_eq!(forward_failure(&log("channel 2: open failed: connect failed: open failed")).code, "unreachable");
        assert_eq!(forward_failure(&[]).code, "unreachable");
    }

    #[test]
    fn launch_commands_quote_their_arguments() {
        let cmd = launch_command(&Launch::Virtual { session: Some("xfce".into()) }, 1280, 800, "x").unwrap();
        assert!(cmd.starts_with("sh -c '") && cmd.ends_with(" sc 'xfce' '1280x800'"), "{cmd}");
        assert!(launch_command(&Launch::None, 1, 1, "x").is_none());
    }

    /// The scripts must at least parse under a strict POSIX shell.
    #[cfg(unix)]
    #[test]
    fn scripts_are_valid_sh() {
        for script in [SHARE_X11, SHARE_WAYLAND, VIRTUAL, END_VIRTUAL] {
            let body = format!("{PRELUDE}{script}");
            let out = std::process::Command::new("/bin/sh").arg("-n").arg("-c").arg(&body).output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        }
    }
}
