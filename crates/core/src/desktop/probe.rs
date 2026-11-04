//! Finds out how a remote computer's desktop can be reached, and what could be
//! installed if nothing can. The remote commands are fixed text; their output
//! is untrusted and only parsed into the [`Probe`] the UI shows.

use std::collections::BTreeSet;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Method, sanitize};
use crate::ssh::shell::quote;

/// POSIX systems (Linux, macOS, BSD). Unprivileged; reads only the user's own
/// processes and public files.
pub const POSIX_SCRIPT: &str = r#"echo "os=$(uname -s 2>/dev/null)"
if [ -r /etc/os-release ]; then . /etc/os-release; echo "distro=${ID:-} ${ID_LIKE:-}"; echo "name=${PRETTY_NAME:-}"; fi
[ -e /etc/nv_tegra_release ] && echo "jetson=1"
command -v sw_vers >/dev/null 2>&1 && echo "name=macOS $(sw_vers -productVersion 2>/dev/null)"
echo "user=$(id -un 2>/dev/null)"
for t in x0vncserver x0tigervncserver wayvnc Xvnc Xtigervnc xrdp grdctl krdpserver dnf apt-get; do command -v "$t" >/dev/null 2>&1 && echo "tool=$t"; done
for c in /proc/[0-9]*/comm; do [ -O "$c" ] && cat "$c" 2>/dev/null; done | sort -u | grep -xE 'gnome-shell|kwin_wayland|kwin_x11|sway|Hyprland|labwc|wayfire|river|cage|niri|Xorg|Xvfb|Xvnc|Xwayland|xfce4-session|mate-session|lxqt-session|cinnamon|krdpserver|gnome-remote-de' | sed 's/^/proc=/'
for e in /proc/[0-9]*/environ; do [ -O "$e" ] || continue; tr '\0' '\n' < "$e" 2>/dev/null | grep -E '^(DISPLAY|WAYLAND_DISPLAY|XDG_SESSION_TYPE|XDG_CURRENT_DESKTOP|SIMPLE_CONNECT_VIRTUAL)=' | sort | tr '\n' ' '; echo; done 2>/dev/null | grep . | sort -u | head -n 40 | sed 's/^/env=/'
r="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"; for w in "$r"/wayland-*; do case "$w" in *.lock) ;; *) [ -S "$w" ] && echo "wayland=${w##*/}";; esac; done
for f in /usr/share/xsessions/*.desktop; do [ -r "$f" ] || continue; b=${f##*/}; echo "xsession=${b%.desktop}|$(sed -n 's/^Name=//p' "$f" | head -n 1)"; done
v="$HOME/.cache/simple-connect/rd"; [ -S "$v/virtual.sock" ] && [ -f "$v/virtual.pid" ] && kill -0 "$(cat "$v/virtual.pid")" 2>/dev/null && echo "virtual=1"
if command -v grdctl >/dev/null 2>&1; then t=""; command -v timeout >/dev/null 2>&1 && t="timeout 5"; $t grdctl status 2>/dev/null | tr -d '\t' | sed -n '/^RDP:/,/^VNC:/p' | head -n 12 | sed 's/^/grd=/'; fi
"#;

/// Windows (cmd.exe or PowerShell as the OpenSSH default shell): one command each.
pub const WINDOWS_RDP_QUERY: &str = r#"reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections"#;
pub const WINDOWS_EDITION_QUERY: &str = r#"reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionID"#;

/// Ports checked on the remote loopback.
pub const RDP_PORTS: &[u16] = &[3389, 3390];
pub const VNC_PORTS: &[u16] = &[5900, 5901, 5902, 5903];

/// What a port answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    Vnc,
    /// RDP with TLS or NLA.
    Rdp,
    /// RDP that only offers the legacy RC4 "RDP security", which is refused.
    RdpLegacyOnly,
}

/// Reads the RFB banner a VNC server sends first.
pub async fn check_vnc<S: AsyncRead + Unpin>(io: &mut S) -> bool {
    let mut b = [0u8; 4];
    io.read_exact(&mut b).await.is_ok() && &b == b"RFB "
}

/// Sends an X.224 Connection Request asking for TLS or NLA and reads the reply.
pub async fn check_rdp<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S) -> Option<PortKind> {
    const REQUEST: [u8; 19] = [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];
    io.write_all(&REQUEST).await.ok()?;
    io.flush().await.ok()?;
    let mut head = [0u8; 4];
    io.read_exact(&mut head).await.ok()?;
    if head[0] != 3 || head[1] != 0 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    if !(11..=64).contains(&len) {
        return None;
    }
    let mut rest = vec![0u8; len - 4];
    io.read_exact(&mut rest).await.ok()?;
    // TPKT(4) + X.224 CC(7), then RDP_NEG_RSP (2, with the selected protocol;
    // 0 = legacy RDP security) or RDP_NEG_FAILURE (3).
    let selected = rest.get(11..15).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    Some(match rest.get(7) {
        Some(2) if selected.is_some_and(|p| p != 0) => PortKind::Rdp,
        Some(3) => {
            let code = rest.get(11).copied().unwrap_or(0);
            // 2 = SSL_NOT_ALLOWED_BY_SERVER: the server only does legacy RDP security.
            if code == 2 { PortKind::RdpLegacyOnly } else { PortKind::Rdp }
        }
        _ => PortKind::RdpLegacyOnly,
    })
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Facts {
    pub os: String,
    pub distro: String,
    pub name: Option<String>,
    pub jetson: bool,
    pub user: Option<String>,
    pub tools: BTreeSet<String>,
    pub procs: BTreeSet<String>,
    /// X11 displays the user has programs on (excluding Xwayland and our virtual desktop).
    pub x_displays: Vec<(u16, Option<String>)>,
    /// Wayland sockets with the desktop name, when a program on it says.
    pub wayland: Vec<(String, Option<String>)>,
    pub xsessions: Vec<XSession>,
    pub virtual_running: bool,
    pub grd_rdp_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XSession {
    pub id: String,
    pub name: String,
}

fn display_number(v: &str) -> Option<u16> {
    let n = v.strip_prefix(':')?;
    n.split('.').next()?.parse().ok().filter(|n| *n < 1000)
}

pub fn parse_posix(out: &str) -> Facts {
    let mut f = Facts::default();
    for line in out.lines().take(400) {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim();
        let text = |max| sanitize(v, max);
        match k {
            "os" => f.os = text(32),
            "distro" => f.distro = text(100).to_lowercase(),
            "name" if !v.is_empty() => f.name = Some(text(100)),
            "jetson" => f.jetson = true,
            "user" if super::plain_name(v) || v.chars().all(|c| c.is_alphanumeric() || "._-@\\ ".contains(c)) => {
                f.user = Some(text(64));
            }
            "tool" if super::plain_name(v) => drop(f.tools.insert(v.to_owned())),
            "proc" if !v.is_empty() => drop(f.procs.insert(text(32))),
            "env" => {
                let vars: Vec<(&str, &str)> = v.split_whitespace().filter_map(|kv| kv.split_once('=')).collect();
                let get = |key: &str| vars.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
                if get("SIMPLE_CONNECT_VIRTUAL").is_some() {
                    continue;
                }
                let desktop = get("XDG_CURRENT_DESKTOP").map(|d| sanitize(d, 40));
                if let Some(w) = get("WAYLAND_DISPLAY").filter(|w| super::plain_name(w)) {
                    if !f.wayland.iter().any(|(s, d)| s == w && d.is_some()) {
                        f.wayland.retain(|(s, _)| s != w);
                        f.wayland.push((w.to_owned(), desktop));
                    }
                } else if get("XDG_SESSION_TYPE") != Some("wayland")
                    && let Some(n) = get("DISPLAY").and_then(display_number)
                    && !f.x_displays.iter().any(|(d, _)| *d == n)
                {
                    f.x_displays.push((n, desktop));
                }
            }
            "wayland" if super::plain_name(v) && !f.wayland.iter().any(|(s, _)| s == v) => f.wayland.push((v.to_owned(), None)),
            "xsession" => {
                let (id, name) = v.split_once('|').unwrap_or((v, v));
                if super::plain_name(id) && f.xsessions.len() < 32 {
                    let name = if name.trim().is_empty() { id } else { name };
                    f.xsessions.push(XSession { id: id.to_owned(), name: sanitize(name, 60) });
                }
            }
            "virtual" => f.virtual_running = true,
            "grd" if v.eq_ignore_ascii_case("Status: enabled") => f.grd_rdp_enabled = true,
            _ => {}
        }
    }
    f.x_displays.sort();
    f
}

/// `fDenyTSConnections REG_DWORD 0x0` → RDP enabled; `EditionID REG_SZ Core` → Home.
pub fn parse_windows_reg(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == name).then(|| it.nth(1).map(|v| sanitize(v, 40)))?
    })
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WindowsFacts {
    pub rdp_enabled: Option<bool>,
    pub edition: Option<String>,
}

/// One way to open the desktop, as the UI offers it. The UI sends the
/// method/port/display/wayland/session fields back in an `OpenRequest`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Offer {
    pub method: Method,
    pub port: Option<u16>,
    pub display: Option<u16>,
    pub wayland: Option<String>,
    pub title: String,
    pub detail: String,
    pub recommended: bool,
    /// The server asks for a password (RDP, Screen Sharing, VNC servers).
    pub sign_in: bool,
    /// A virtual desktop is already running and will be reattached.
    pub running: bool,
}

/// Something that can be installed or enabled, with the exact commands.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Setup {
    pub recipe: &'static str,
    pub title: &'static str,
    pub detail: &'static str,
    pub commands: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    /// linux | macos | windows | other
    pub os: &'static str,
    pub os_name: Option<String>,
    pub user: Option<String>,
    pub jetson: bool,
    pub offers: Vec<Offer>,
    pub setups: Vec<Setup>,
    pub notes: Vec<String>,
    /// Desktop environments a virtual desktop can run.
    pub sessions: Vec<XSession>,
}

pub struct Recipe {
    pub id: &'static str,
    pub title: &'static str,
    pub detail: &'static str,
    pub commands: &'static [&'static str],
    /// Run as given by the Windows default shell instead of `sh`.
    pub windows: bool,
}

const LINGER: &str = r#"if command -v loginctl >/dev/null 2>&1; then sudo loginctl enable-linger "$USER"; fi"#;
const SHARE_DETAIL: &str = "Installs wayvnc so you can see and control the desktop on this computer's screen. Nothing is shared until you connect, only through SSH, and sharing stops when you disconnect.";
const TIGERVNC_DETAIL: &str = "Installs TigerVNC, so you can share the desktop on this computer's screen and open separate virtual desktops that keep running after you disconnect. Nothing listens on the network: connections only come through SSH. Lingering is turned on so virtual desktops survive while you're not signed in.";

pub const RECIPES: &[Recipe] = &[
    Recipe { id: "wayvnc-dnf", title: "Install wayvnc", detail: SHARE_DETAIL, commands: &["sudo dnf install -y wayvnc"], windows: false },
    Recipe {
        id: "wayvnc-apt",
        title: "Install wayvnc",
        detail: SHARE_DETAIL,
        commands: &["sudo apt-get update", "sudo apt-get install -y wayvnc"],
        windows: false,
    },
    Recipe {
        id: "tigervnc-dnf",
        title: "Install TigerVNC",
        detail: TIGERVNC_DETAIL,
        commands: &["sudo dnf install -y tigervnc-server", LINGER],
        windows: false,
    },
    Recipe {
        id: "tigervnc-xfce-dnf",
        title: "Install TigerVNC and the XFCE desktop",
        detail: TIGERVNC_DETAIL,
        commands: &["sudo dnf install -y tigervnc-server xfce4-session xfwm4 xfce4-panel xfdesktop xfce4-terminal Thunar", LINGER],
        windows: false,
    },
    Recipe {
        id: "tigervnc-apt",
        title: "Install TigerVNC",
        detail: TIGERVNC_DETAIL,
        commands: &["sudo apt-get update", "sudo apt-get install -y tigervnc-standalone-server tigervnc-scraping-server", LINGER],
        windows: false,
    },
    Recipe {
        id: "tigervnc-xfce-apt",
        title: "Install TigerVNC and the XFCE desktop",
        detail: TIGERVNC_DETAIL,
        commands: &[
            "sudo apt-get update",
            "sudo apt-get install -y tigervnc-standalone-server tigervnc-scraping-server xfce4 xfce4-terminal dbus-x11",
            LINGER,
        ],
        windows: false,
    },
    Recipe {
        id: "windows-rdp",
        title: "Turn on Remote Desktop",
        detail: "Allows Remote Desktop connections. Run it from an administrator account. The Windows firewall stays closed, so Remote Desktop is only reachable through SSH.",
        commands: &[r#"reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f"#],
        windows: true,
    },
];

pub fn recipe(id: &str) -> Option<&'static Recipe> {
    RECIPES.iter().find(|r| r.id == id)
}

/// The command a setup terminal runs: the recipe, traced, then a normal shell
/// so the user can read the output and continue.
pub fn recipe_command(r: &Recipe) -> String {
    if r.windows {
        return r.commands.join(" & ");
    }
    let script = format!("set -ex\n{}", r.commands.join("\n"));
    format!(
        "printf '%s\\n\\n' {}; sh -c {} && printf '\\n%s\\n' {} || printf '\\n%s\\n' {}; exec \"${{SHELL:-/bin/sh}}\" -l",
        quote(&format!("# Simple Connect: {}", r.title)),
        quote(&script),
        quote("Finished. Go back to Remote Desktop and choose Check again."),
        quote("Setup didn't finish. The output above says why."),
    )
}

fn setup(id: &str) -> Option<Setup> {
    recipe(id).map(|r| Setup { recipe: r.id, title: r.title, detail: r.detail, commands: r.commands.to_vec() })
}

const WLROOTS: &[&str] = &["sway", "hyprland", "labwc", "wayfire", "river", "cage", "niri"];

#[derive(Clone, Copy, PartialEq)]
enum Shell {
    Gnome,
    Kde,
    Wlroots,
    Unknown,
}

fn wayland_shell(desktop: Option<&str>, procs: &BTreeSet<String>) -> Shell {
    let d = desktop.unwrap_or_default().to_lowercase();
    if d.contains("gnome") || (d.is_empty() && procs.contains("gnome-shell")) {
        Shell::Gnome
    } else if d.contains("kde") || (d.is_empty() && procs.contains("kwin_wayland")) {
        Shell::Kde
    } else if WLROOTS.iter().any(|w| d.contains(w) || (d.is_empty() && procs.iter().any(|p| p.eq_ignore_ascii_case(w)))) {
        Shell::Wlroots
    } else {
        Shell::Unknown
    }
}

/// Turns what was found into ranked offers, setups and notes.
pub fn build(facts: &Facts, ports: &[(u16, PortKind)], windows: Option<&WindowsFacts>) -> Probe {
    let os = if windows.is_some() {
        "windows"
    } else {
        match facts.os.as_str() {
            "Linux" => "linux",
            "Darwin" => "macos",
            _ => "other",
        }
    };
    let mut offers: Vec<Offer> = Vec::new();
    let mut setups: Vec<Setup> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let has = |t: &str| facts.tools.contains(t);
    let pm = if has("dnf") {
        Some("dnf")
    } else if has("apt-get") {
        Some("apt")
    } else {
        None
    };
    let add_setup = |setups: &mut Vec<Setup>, base: &str| {
        if let Some(pm) = pm
            && let Some(s) = setup(&format!("{base}-{pm}"))
            && !setups.iter().any(|x| x.recipe == s.recipe)
        {
            setups.push(s);
        }
    };
    let offer = |method, title: String, detail: &str| Offer {
        method,
        port: None,
        display: None,
        wayland: None,
        title,
        detail: detail.into(),
        recommended: false,
        sign_in: false,
        running: false,
    };

    let tigervnc = if facts.xsessions.is_empty() { "tigervnc-xfce" } else { "tigervnc" };
    // 1. The desktop on the computer's own screen.
    for (n, desktop) in &facts.x_displays {
        if has("x0vncserver") || has("x0tigervncserver") {
            let name = desktop.as_deref().map(|d| format!(" ({d})")).unwrap_or_default();
            offers.push(Offer {
                display: Some(*n),
                ..offer(
                    Method::X11,
                    format!("Share the screen :{n}{name}"),
                    "The desktop on this computer's monitor, through TigerVNC. Sharing stops when you disconnect.",
                )
            });
        } else {
            add_setup(&mut setups, tigervnc);
        }
    }
    let mut gnome_or_kde_wayland = None;
    for (socket, desktop) in &facts.wayland {
        match wayland_shell(desktop.as_deref(), &facts.procs) {
            Shell::Gnome => gnome_or_kde_wayland = Some(Shell::Gnome),
            Shell::Kde => gnome_or_kde_wayland = Some(Shell::Kde),
            shell if has("wayvnc") => {
                let known = shell == Shell::Wlroots;
                offers.push(Offer {
                    wayland: Some(socket.clone()),
                    ..offer(
                        Method::Wayland,
                        format!("Share the Wayland desktop ({})", desktop.as_deref().unwrap_or(socket)),
                        if known {
                            "The desktop on this computer's monitor, through wayvnc. Sharing stops when you disconnect."
                        } else {
                            "Through wayvnc. This works with wlroots-based desktops such as Sway, labwc and Wayfire."
                        },
                    )
                });
            }
            Shell::Wlroots => add_setup(&mut setups, "wayvnc"),
            Shell::Unknown => {}
        }
    }

    // 2. Servers that are already running.
    let gnome = gnome_or_kde_wayland == Some(Shell::Gnome) || facts.procs.contains("gnome-shell");
    for (port, kind) in ports {
        match kind {
            PortKind::Rdp => {
                let (title, detail) = if os == "windows" {
                    ("Windows Remote Desktop".to_owned(), "Sign in with your Windows account.")
                } else if facts.procs.contains("gnome-remote-de") || facts.grd_rdp_enabled {
                    ("GNOME Remote Desktop".to_owned(), "Sign in with the user name and password set in GNOME's Remote Desktop settings.")
                } else if facts.procs.contains("krdpserver") {
                    ("KDE Remote Desktop".to_owned(), "Sign in with the user name and password set in KDE's Remote Desktop settings.")
                } else if has("xrdp") {
                    ("xrdp session".to_owned(), "A desktop session from xrdp. Sign in with your account on this computer.")
                } else {
                    (format!("Remote Desktop (RDP) on port {port}"), "Sign in with the account the server expects.")
                };
                offers.push(Offer { port: Some(*port), sign_in: true, ..offer(Method::Rdp, title, detail) });
            }
            PortKind::RdpLegacyOnly => notes.push(format!(
                "The Remote Desktop server on port {port} only offers outdated encryption, so Simple Connect won't use it. Turn on TLS or Network Level Authentication on that server."
            )),
            PortKind::Vnc => {
                let (title, detail) = if os == "macos" {
                    ("macOS Screen Sharing".to_owned(), "Sign in with your Mac user name and password.")
                } else {
                    (format!("VNC server on port {port}"), "An existing VNC server. It may ask for its VNC password.")
                };
                offers.push(Offer { port: Some(*port), sign_in: true, ..offer(Method::Vnc, title, detail) });
            }
        }
    }

    // 3. A virtual desktop.
    if os == "linux" {
        let xvnc = has("Xvnc") || has("Xtigervnc");
        if xvnc && (!facts.xsessions.is_empty() || facts.virtual_running) {
            offers.push(Offer {
                running: facts.virtual_running,
                ..offer(
                    Method::Virtual,
                    if facts.virtual_running { "Your virtual desktop".into() } else { "New virtual desktop".into() },
                    if facts.virtual_running {
                        "Your separate desktop is still running. Reconnect to pick up where you left off."
                    } else {
                        "A separate desktop that keeps running after you disconnect. It doesn't need anyone signed in on the computer."
                    },
                )
            });
        } else {
            add_setup(&mut setups, tigervnc);
        }
        let x0 = has("x0vncserver") || has("x0tigervncserver");
        let missing = (!facts.x_displays.is_empty() && !x0) || !xvnc;
        if pm.is_none() && missing {
            notes.push(
                "Install TigerVNC (x0vncserver to share the screen, Xvnc for virtual desktops) with this system's package manager, then choose Check again."
                    .into(),
            );
        }
    }

    let screen_offered = offers.iter().any(|o| matches!(o.method, Method::X11 | Method::Wayland | Method::Rdp));
    if gnome && !screen_offered && os == "linux" {
        notes.push("To share this computer's GNOME desktop: on the computer, open Settings › System › Remote Desktop, turn on Desktop Sharing and Remote Control, and set a user name and password. Simple Connect connects through SSH, so you don't need to open port 3389 in the firewall.".into());
    }
    if gnome_or_kde_wayland == Some(Shell::Kde) && !screen_offered {
        notes.push("To share this computer's KDE Plasma desktop: on the computer, open System Settings › Remote Desktop, turn it on and add a user. Simple Connect connects through SSH, so you don't need to open the port in the firewall.".into());
    }
    if facts.jetson && offers.is_empty() {
        notes.push("A Jetson without a monitor has no desktop to share. Use a virtual desktop instead.".into());
    }
    if os == "macos" && offers.is_empty() {
        notes.push("To use this Mac's screen: on the Mac, open System Settings › General › Sharing and turn on Screen Sharing. macOS doesn't allow turning it on over SSH.".into());
    }
    if let Some(w) = windows
        && !offers.iter().any(|o| o.method == Method::Rdp)
    {
        let home = w.edition.as_deref().is_some_and(|e| e.starts_with("Core"));
        if home {
            notes.push("Windows Home editions can't accept Remote Desktop connections. Install a VNC server such as TightVNC or TigerVNC on the PC, set it to accept connections from this computer only (localhost), and choose Check again.".into());
        } else if let Some(s) = setup("windows-rdp") {
            setups.push(s);
            if w.rdp_enabled == Some(true) {
                notes.push("Remote Desktop is turned on, but it isn't answering on port 3389.".into());
            }
        }
    }
    if os == "other" && offers.is_empty() {
        notes.push("Simple Connect couldn't detect a desktop on this computer.".into());
    }

    // A screen that's in use beats a running server, which beats a new desktop.
    if let Some(first) = offers.first_mut() {
        first.recommended = true;
    }
    Probe {
        os,
        os_name: facts.name.clone().or_else(|| windows.and_then(|w| w.edition.clone()).map(|e| format!("Windows ({e})"))),
        user: facts.user.clone(),
        jetson: facts.jetson,
        offers,
        setups,
        notes,
        sessions: facts.xsessions.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEDORA_GNOME_WAYLAND: &str = "os=Linux\ndistro=fedora \nname=Fedora Linux 44 (Workstation Edition)\nuser=jrf\ntool=dnf\ntool=grdctl\n\
proc=Xwayland\nproc=gnome-shell\n\
env=DISPLAY=:0 WAYLAND_DISPLAY=wayland-0 XDG_CURRENT_DESKTOP=GNOME XDG_SESSION_TYPE=wayland \n\
env=XDG_SESSION_TYPE=tty \nwayland=wayland-0\nxsession=gnome-xorg|GNOME on Xorg\n";

    const UBUNTU_X11: &str = "os=Linux\ndistro=ubuntu debian\nname=Ubuntu 24.04 LTS\nuser=pat\ntool=apt-get\ntool=x0tigervncserver\nproc=Xorg\n\
env=DISPLAY=:0 XDG_CURRENT_DESKTOP=ubuntu:GNOME XDG_SESSION_TYPE=x11 \nxsession=ubuntu|Ubuntu\n";

    const JETSON_HEADLESS: &str = "os=Linux\ndistro=ubuntu debian\nname=Ubuntu 22.04.4 LTS\njetson=1\nuser=nvidia\ntool=apt-get\n";

    const DEBIAN_VIRTUAL: &str = "os=Linux\ndistro=debian\nname=Debian GNU/Linux 13\nuser=ops\ntool=apt-get\ntool=Xvnc\n\
env=DISPLAY=:10 SIMPLE_CONNECT_VIRTUAL=1 \nxsession=xfce|Xfce Session\nxsession=bad name|x\nvirtual=1\n";

    const SWAY: &str = "os=Linux\ndistro=alpine\nuser=pw\ntool=wayvnc\nproc=sway\nwayland=wayland-1\n";

    #[test]
    fn fedora_gnome_wayland() {
        let f = parse_posix(FEDORA_GNOME_WAYLAND);
        assert!(f.x_displays.is_empty(), "Xwayland is not offered for sharing");
        assert_eq!(f.wayland, [("wayland-0".to_owned(), Some("GNOME".to_owned()))]);
        let p = build(&f, &[], None);
        assert_eq!(p.os, "linux");
        assert!(p.offers.is_empty());
        assert!(p.notes.iter().any(|n| n.contains("GNOME")), "{:?}", p.notes);
        assert_eq!(p.setups.iter().map(|s| s.recipe).collect::<Vec<_>>(), ["tigervnc-dnf"], "an X session exists, so no XFCE");

        let p = build(&f, &[(3389, PortKind::Rdp)], None);
        assert_eq!(p.offers[0].method, Method::Rdp);
        assert!(p.offers[0].recommended && p.offers[0].sign_in);
        assert!(!p.notes.iter().any(|n| n.contains("GNOME")));
    }

    #[test]
    fn ubuntu_x11() {
        let f = parse_posix(UBUNTU_X11);
        assert_eq!(f.x_displays, [(0, Some("ubuntu:GNOME".into()))]);
        let p = build(&f, &[], None);
        assert_eq!((p.offers[0].method, p.offers[0].display), (Method::X11, Some(0)));
        assert_eq!(p.setups.iter().map(|s| s.recipe).collect::<Vec<_>>(), ["tigervnc-apt"]);
    }

    #[test]
    fn headless_jetson() {
        let p = build(&parse_posix(JETSON_HEADLESS), &[], None);
        assert!(p.jetson && p.offers.is_empty());
        assert_eq!(p.setups.iter().map(|s| s.recipe).collect::<Vec<_>>(), ["tigervnc-xfce-apt"]);
        assert!(p.notes.iter().any(|n| n.contains("Jetson")));
    }

    #[test]
    fn running_virtual_desktop_is_not_offered_as_a_screen() {
        let f = parse_posix(DEBIAN_VIRTUAL);
        assert!(f.x_displays.is_empty());
        assert_eq!(f.xsessions, [XSession { id: "xfce".into(), name: "Xfce Session".into() }]);
        let p = build(&f, &[], None);
        assert_eq!(p.offers.len(), 1);
        assert!(p.offers[0].running && p.offers[0].method == Method::Virtual);
    }

    #[test]
    fn wlroots_and_legacy_rdp() {
        let p = build(&parse_posix(SWAY), &[(3389, PortKind::RdpLegacyOnly)], None);
        assert_eq!(p.offers[0].wayland.as_deref(), Some("wayland-1"));
        assert!(p.notes.iter().any(|n| n.contains("outdated encryption")));
    }

    #[test]
    fn macos_and_windows() {
        let mac = parse_posix("os=Darwin\nname=macOS 15.1\nuser=kim\n");
        let p = build(&mac, &[(5900, PortKind::Vnc)], None);
        assert_eq!((p.os, p.offers[0].title.as_str()), ("macos", "macOS Screen Sharing"));
        assert!(build(&mac, &[], None).notes[0].contains("Screen Sharing"));

        let ts = "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\...\\Terminal Server\r\n    fDenyTSConnections    REG_DWORD    0x1\r\n";
        assert_eq!(parse_windows_reg(ts, "fDenyTSConnections").as_deref(), Some("0x1"));
        let ed = "    EditionID    REG_SZ    Professional\r\n";
        let w = WindowsFacts { rdp_enabled: Some(false), edition: parse_windows_reg(ed, "EditionID") };
        let p = build(&Facts::default(), &[], Some(&w));
        assert_eq!(p.os, "windows");
        assert_eq!(p.setups[0].recipe, "windows-rdp");
        let home = WindowsFacts { rdp_enabled: None, edition: Some("Core".into()) };
        assert!(build(&Facts::default(), &[], Some(&home)).notes[0].contains("Home"));
        assert_eq!(build(&Facts::default(), &[(3389, PortKind::Rdp)], Some(&w)).offers[0].title, "Windows Remote Desktop");
    }

    #[test]
    fn hostile_output_is_contained() {
        let f = parse_posix("user=$(id)\ntool=../x\nxsession=../../etc|x\nenv=DISPLAY=evil:1 \nwayland=-x\nname=\u{1b}[2Jhi\n");
        assert_eq!(f.user, None);
        assert!(f.tools.is_empty() && f.xsessions.is_empty() && f.x_displays.is_empty() && f.wayland.is_empty());
        assert_eq!(f.name.as_deref(), Some("[2Jhi"));
    }

    #[test]
    fn recipes_are_complete() {
        for r in RECIPES {
            assert!(!r.commands.is_empty());
            let cmd = recipe_command(r);
            assert!(r.windows || cmd.ends_with("exec \"${SHELL:-/bin/sh}\" -l"), "{cmd}");
        }
        assert!(recipe("rm -rf").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn probe_script_is_valid_sh() {
        let out = std::process::Command::new("/bin/sh").arg("-n").arg("-c").arg(POSIX_SCRIPT).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    #[tokio::test]
    async fn port_checks() {
        let (mut a, mut b) = tokio::io::duplex(256);
        b.write_all(b"RFB 003.008\n").await.unwrap();
        assert!(check_vnc(&mut a).await);

        // xrdp's answer: RDP_NEG_RSP selecting TLS.
        let (mut a, mut b) = tokio::io::duplex(256);
        b.write_all(&[3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0x1f, 8, 0, 1, 0, 0, 0]).await.unwrap();
        assert_eq!(check_rdp(&mut a).await, Some(PortKind::Rdp));
        // xrdp with security_layer=rdp: a response selecting legacy RDP security.
        let (mut a, mut b) = tokio::io::duplex(256);
        b.write_all(&[3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 1, 8, 0, 0, 0, 0, 0]).await.unwrap();
        assert_eq!(check_rdp(&mut a).await, Some(PortKind::RdpLegacyOnly));
        // RDP_NEG_FAILURE SSL_NOT_ALLOWED_BY_SERVER.
        let (mut a, mut b) = tokio::io::duplex(256);
        b.write_all(&[3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 3, 0, 8, 0, 2, 0, 0, 0]).await.unwrap();
        assert_eq!(check_rdp(&mut a).await, Some(PortKind::RdpLegacyOnly));
        let (mut a, mut b) = tokio::io::duplex(256);
        b.write_all(b"SSH-2.0-x\r\n").await.unwrap();
        assert_eq!(check_rdp(&mut a).await, None);
    }
}
