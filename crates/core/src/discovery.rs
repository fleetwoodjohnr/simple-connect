//! Finds devices on the networks this computer is directly attached to.
//!
//! Runs only when the user starts a scan. It never leaves the local network:
//! the caller names one of [`local_networks`] by id and the subnet is recomputed
//! here, so a compromised UI can't point it elsewhere. Only private (RFC 1918),
//! shared (RFC 6598, 100.64.0.0/10) and link-local IPv4 ranges qualify, and at
//! most 1024 addresses are probed.
//!
//! Each address gets one TCP connection attempt to the SSH port. If it connects,
//! the server's identification line is read; nothing is sent and no
//! authentication is attempted. Afterwards the kernel's neighbour (ARP) table,
//! which those attempts filled, supplies MAC addresses and also reveals hosts that
//! silently drop TCP. Names come from reverse lookups (DNS and mDNS through NSS).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const MAX_HOSTS: u32 = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(600);
const BANNER_TIMEOUT: Duration = Duration::from_millis(800);
const NAME_TIMEOUT: Duration = Duration::from_millis(1500);
const PARALLEL: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalNetwork {
    /// Stable identifier the UI passes back to start a scan.
    pub id: String,
    pub interface: String,
    pub address: String,
    /// The attached subnet, e.g. `192.168.1.0/24`.
    pub cidr: String,
    /// What is scanned: the subnet, or the /24 around this computer if larger than /22.
    pub scan_cidr: String,
    pub hosts: u32,
    /// Carries the default route (the network you're "on").
    pub preferred: bool,
}

fn in_range(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

/// Private, shared (CGNAT) and link-local IPv4 space: never the public internet.
pub fn is_local_range(ip: Ipv4Addr) -> bool {
    in_range(ip, [10, 0, 0, 0], 8)
        || in_range(ip, [172, 16, 0, 0], 12)
        || in_range(ip, [192, 168, 0, 0], 16)
        || in_range(ip, [100, 64, 0, 0], 10)
        || in_range(ip, [169, 254, 0, 0], 16)
}

/// The network to scan for an interface address: its subnet, narrowed to the
/// enclosing /24 when larger than /22. Returns (network address, prefix).
pub fn scan_range(ip: Ipv4Addr, prefix: u8) -> Option<(Ipv4Addr, u8)> {
    if prefix > 30 || !is_local_range(ip) {
        return None;
    }
    let prefix = if prefix < 22 { 24 } else { prefix };
    let mask = u32::MAX << (32 - u32::from(prefix));
    Some((Ipv4Addr::from(u32::from(ip) & mask), prefix))
}

/// Usable host addresses of `network/prefix`, excluding `own`.
pub fn targets(network: Ipv4Addr, prefix: u8, own: Ipv4Addr) -> Vec<Ipv4Addr> {
    let base = u32::from(network);
    let size = 1u32 << (32 - u32::from(prefix));
    (1..size.saturating_sub(1)).map(|i| Ipv4Addr::from(base + i)).filter(|ip| *ip != own).take(MAX_HOSTS as usize).collect()
}

/// Interface carrying the default route, from `/proc/net/route`.
pub fn default_route_interface(route_table: &str) -> Option<String> {
    route_table.lines().skip(1).find_map(|l| {
        let mut f = l.split_whitespace();
        let (iface, dest) = (f.next()?, f.next()?);
        (dest == "00000000").then(|| iface.to_owned())
    })
}

/// Networks that can be scanned right now.
pub fn local_networks() -> Vec<LocalNetwork> {
    #[cfg(target_os = "linux")]
    let default_iface = std::fs::read_to_string("/proc/net/route").ok().and_then(|t| default_route_interface(&t));
    #[cfg(target_os = "macos")]
    let default_iface = system_table("/sbin/route", &["-n", "get", "default"])
        .and_then(|s| s.lines().find_map(|line| line.trim().strip_prefix("interface:").map(|name| name.trim().to_owned())));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let default_iface: Option<String> = None;
    #[cfg(windows)]
    let default_index = windows_default_interface();
    #[cfg(not(windows))]
    let default_index: Option<u32> = None;
    let mut out: Vec<LocalNetwork> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback() && i.is_oper_up())
        .filter_map(|i| {
            let if_addrs::IfAddr::V4(v4) = &i.addr else { return None };
            let (network, prefix) = scan_range(v4.ip, v4.prefixlen)?;
            let attached = Ipv4Addr::from(u32::from(v4.ip) & (u32::MAX << (32 - u32::from(v4.prefixlen.max(1)))));
            let hosts = targets(network, prefix, v4.ip).len() as u32;
            Some(LocalNetwork {
                id: format!("{}/{}/{}", i.name, v4.ip, v4.prefixlen),
                preferred: default_iface.as_deref() == Some(i.name.as_str()) || (default_index.is_some() && default_index == i.index),
                interface: i.name,
                address: v4.ip.to_string(),
                cidr: format!("{attached}/{}", v4.prefixlen),
                scan_cidr: format!("{network}/{prefix}"),
                hosts,
            })
        })
        .filter(|n| n.hosts > 0)
        .collect();
    out.sort_by_key(|n| !n.preferred);
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SshStatus {
    /// Something accepted the connection; `software` is set if it identified as SSH.
    Open { software: Option<String>, os: Option<String> },
    /// The host answered but nothing listens on the port.
    Closed,
    /// The host is present (neighbour table) but didn't answer on the port.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub ssh: SshStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ScanEvent {
    Progress {
        done: u32,
        total: u32,
    },
    /// A device was found or learned more (same `ip` replaces the earlier entry).
    Device {
        device: Device,
    },
    Done {
        found: u32,
        cancelled: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("That network is no longer available. Refresh the list and try again.")]
    NotLocal,
}

/// `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13` → ("OpenSSH 9.6p1", Some("Ubuntu")).
/// The text is untrusted: only a short printable prefix is kept.
pub fn parse_banner(raw: &[u8]) -> Option<(String, Option<String>)> {
    let line = String::from_utf8_lossy(raw);
    let line = line.lines().find(|l| l.starts_with("SSH-"))?;
    let clean: String = line.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(120).collect();
    let rest = clean.splitn(3, '-').nth(2)?; // after "SSH-2.0-"
    let (software, comment) = rest.split_once(' ').unwrap_or((rest, ""));
    let pretty = software.replacen("OpenSSH_for_Windows_", "OpenSSH ", 1).replacen("OpenSSH_", "OpenSSH ", 1).replace('_', " ");
    let hay = format!("{software} {comment}").to_ascii_lowercase();
    let os = [
        ("raspbian", "Raspberry Pi OS"),
        ("ubuntu", "Ubuntu"),
        ("debian", "Debian"),
        ("for_windows", "Windows"),
        ("freebsd", "FreeBSD"),
        ("netbsd", "NetBSD"),
        ("dropbear", "Embedded (Dropbear)"),
        ("rosssh", "MikroTik"),
        ("cisco", "Cisco"),
    ]
    .iter()
    .find(|(needle, _)| hay.contains(needle))
    .map(|(_, os)| (*os).to_owned());
    Some((pretty, os))
}

/// One connection attempt: identifies an SSH server by its banner, never logs in.
pub async fn probe(ip: Ipv4Addr, port: u16) -> Option<SshStatus> {
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((ip, port))).await {
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 255];
            let n = tokio::time::timeout(BANNER_TIMEOUT, stream.read(&mut buf)).await.ok().and_then(Result::ok).unwrap_or(0);
            let parsed = parse_banner(&buf[..n]);
            Some(SshStatus::Open { software: parsed.as_ref().map(|p| p.0.clone()), os: parsed.and_then(|p| p.1) })
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(SshStatus::Closed),
        _ => None,
    }
}

/// Complete entries of the kernel neighbour table: IP → MAC.
pub fn parse_arp(table: &str) -> BTreeMap<Ipv4Addr, String> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (ip, flags, mac) = (f.first()?.parse::<Ipv4Addr>().ok()?, f.get(2)?, f.get(3)?);
            let complete = u32::from_str_radix(flags.trim_start_matches("0x"), 16).ok()? & 0x2 != 0;
            let mac = crate::validate::mac(mac).ok()?;
            (complete && mac != "00:00:00:00:00:00").then_some((ip, mac))
        })
        .collect()
}

fn neighbours() -> BTreeMap<Ipv4Addr, String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/net/arp").map(|t| parse_arp(&t)).unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        system_table("/usr/sbin/arp", &["-an"]).map(|s| parse_native_arp(&s, true)).unwrap_or_default()
    }
    #[cfg(windows)]
    {
        system_table(&windows_system_program("arp.exe"), &["-a"]).map(|s| parse_native_arp(&s, false)).unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    BTreeMap::new()
}

/// Parse numeric ARP output without relying on localized column headings.
#[cfg(any(target_os = "macos", windows, test))]
fn parse_native_arp(table: &str, macos: bool) -> BTreeMap<Ipv4Addr, String> {
    table
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let (address, raw_mac) =
                if macos { (fields.get(1)?.trim_matches(['(', ')']), *fields.get(3)?) } else { (*fields.first()?, *fields.get(1)?) };
            let address = address.parse::<Ipv4Addr>().ok()?;
            let octets: Option<Vec<u8>> = raw_mac
                .split([':', '-'])
                .map(|v| (!v.is_empty() && v.len() <= 2).then(|| u8::from_str_radix(v, 16).ok()).flatten())
                .collect();
            let octets = octets?;
            if octets.len() != 6 || octets.iter().all(|b| *b == 0) || octets[0] & 1 != 0 {
                return None;
            }
            Some((address, octets.iter().map(|v| format!("{v:02x}")).collect::<Vec<_>>().join(":")))
        })
        .collect()
}

/// OS utilities are queried with fixed arguments, capped output, and a deadline.
/// Failure only removes optional route/MAC metadata; SSH scanning remains usable.
#[cfg(any(target_os = "macos", windows))]
fn system_table(program: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut cmd = Command::new(program);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().ok()?;
    let stdout = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    const MAX_OUTPUT: u64 = 1024 * 1024;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(MAX_OUTPUT + 1).read_to_end(&mut bytes);
        let _ = tx.send((result, bytes));
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Err(_) => break None,
            _ if Instant::now() >= deadline => break None,
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let output = rx.recv_timeout(Duration::from_secs(1)).ok();
    // Never block joining a reader if a utility unexpectedly inherited its pipe.
    if reader.is_finished() {
        let _ = reader.join();
    }
    let (result, bytes) = output?;
    if !status?.success() || result.is_err() || bytes.len() > MAX_OUTPUT as usize {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(windows)]
fn windows_system_program(program: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32").join(program)
}

#[cfg(windows)]
fn windows_default_interface() -> Option<u32> {
    let shell = windows_system_program("WindowsPowerShell/v1.0/powershell.exe");
    let script = "$ErrorActionPreference='Stop'; Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1 -ExpandProperty InterfaceIndex";
    system_table(shell, &["-NoProfile", "-NonInteractive", "-Command", script])?.trim().parse().ok()
}

async fn reverse_name(ip: Ipv4Addr) -> Option<String> {
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    let name = tokio::time::timeout(NAME_TIMEOUT, lookup).await.ok()?.ok()??;
    let name = name.trim_end_matches('.');
    let ok = !name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
    (ok && name != ip.to_string()).then(|| name.to_owned())
}

/// Scans one of [`local_networks`] (by id) for hosts and SSH servers on `port`.
pub async fn scan(network_id: &str, port: u16, cancel: &AtomicBool, mut emit: impl FnMut(ScanEvent)) -> Result<u32, ScanError> {
    let net = local_networks().into_iter().find(|n| n.id == network_id).ok_or(ScanError::NotLocal)?;
    let own: Ipv4Addr = net.address.parse().map_err(|_| ScanError::NotLocal)?;
    let (network, prefix) = net
        .scan_cidr
        .split_once('/')
        .and_then(|(a, p)| Some((a.parse::<Ipv4Addr>().ok()?, p.parse::<u8>().ok()?)))
        .ok_or(ScanError::NotLocal)?;
    let list = targets(network, prefix, own);
    let total = list.len() as u32;

    let mut found: BTreeMap<Ipv4Addr, Device> = BTreeMap::new();
    let mut probes =
        futures_util::stream::iter(list.iter().copied()).map(|ip| async move { (ip, probe(ip, port).await) }).buffer_unordered(PARALLEL);
    let mut done = 0;
    emit(ScanEvent::Progress { done, total });
    while let Some((ip, status)) = probes.next().await {
        done += 1;
        if let Some(ssh) = status {
            let device = Device { ip: ip.to_string(), hostname: None, mac: None, ssh };
            emit(ScanEvent::Device { device: device.clone() });
            found.insert(ip, device);
        }
        if done % 16 == 0 || done == total {
            emit(ScanEvent::Progress { done, total });
        }
        if cancel.load(Ordering::Relaxed) {
            emit(ScanEvent::Done { found: found.len() as u32, cancelled: true });
            return Ok(found.len() as u32);
        }
    }
    drop(probes);

    // Hosts that answered ARP but dropped the TCP attempt, plus MACs for everyone.
    let in_scan = |ip: &Ipv4Addr| u32::from(*ip) >> (32 - u32::from(prefix)) == u32::from(network) >> (32 - u32::from(prefix));
    for (ip, mac) in neighbours().into_iter().filter(|(ip, _)| in_scan(ip) && *ip != own) {
        found.entry(ip).or_insert_with(|| Device { ip: ip.to_string(), hostname: None, mac: None, ssh: SshStatus::Unknown }).mac =
            Some(mac);
    }

    let mut named = futures_util::stream::iter(found.keys().copied().collect::<Vec<_>>())
        .map(|ip| async move { (ip, reverse_name(ip).await) })
        .buffer_unordered(32);
    while let Some((ip, name)) = named.next().await {
        if let Some(d) = found.get_mut(&ip) {
            d.hostname = name;
            emit(ScanEvent::Device { device: d.clone() });
        }
        if cancel.load(Ordering::Relaxed) {
            break;
        }
    }
    let n = found.len() as u32;
    tracing::info!(hosts = total, found = n, "network scan finished");
    emit(ScanEvent::Done { found: n, cancelled: cancel.load(Ordering::Relaxed) });
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn only_local_ranges() {
        for ok in ["10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.5", "100.110.198.200", "169.254.3.4"] {
            assert!(is_local_range(ip(ok)), "{ok}");
        }
        for bad in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "1.1.1.1", "193.168.1.1", "127.0.0.1"] {
            assert!(!is_local_range(ip(bad)), "{bad}");
        }
    }

    #[test]
    fn ranges_are_capped_and_narrowed() {
        assert_eq!(scan_range(ip("100.110.198.200"), 26), Some((ip("100.110.198.192"), 26)));
        assert_eq!(scan_range(ip("192.168.1.42"), 24), Some((ip("192.168.1.0"), 24)));
        assert_eq!(scan_range(ip("10.0.5.9"), 22), Some((ip("10.0.4.0"), 22)));
        assert_eq!(scan_range(ip("10.0.5.9"), 16), Some((ip("10.0.5.0"), 24)), "big subnets shrink to the local /24");
        assert_eq!(scan_range(ip("8.8.8.8"), 24), None, "public networks are never scanned");
        assert_eq!(scan_range(ip("10.0.0.1"), 32), None);

        let t = targets(ip("192.168.1.0"), 24, ip("192.168.1.42"));
        assert_eq!(t.len(), 253, "no network, broadcast or own address");
        assert!(!t.contains(&ip("192.168.1.0")) && !t.contains(&ip("192.168.1.255")) && !t.contains(&ip("192.168.1.42")));
        assert_eq!(targets(ip("10.0.4.0"), 22, ip("10.0.5.9")).len(), 1021);
        assert!(targets(ip("10.0.0.0"), 16, ip("10.0.0.1")).len() <= MAX_HOSTS as usize);
    }

    #[test]
    fn parses_system_tables() {
        let route = "Iface\tDestination\tGateway\tFlags\n\
                     wlp3s0\t00000000\tC1C66E64\t0003\n\
                     wlp3s0\tC0C66E64\t00000000\t0001\n";
        assert_eq!(default_route_interface(route).as_deref(), Some("wlp3s0"));
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   100.110.198.193  0x1         0x2         18:FD:74:69:74:29     *        wlp3s0\n\
                   100.110.198.199  0x1         0x0         00:00:00:00:00:00     *        wlp3s0\n\
                   bogus line\n";
        let t = parse_arp(arp);
        assert_eq!(t.len(), 1);
        assert_eq!(t[&ip("100.110.198.193")], "18:fd:74:69:74:29");
    }

    #[test]
    fn parses_macos_and_windows_neighbours_without_localized_headers() {
        let mac = "? (192.168.1.2) at a:b:c:d:e:f on en0 ifscope [ethernet]\n? (192.168.1.3) at (incomplete) on en0\n? (224.0.0.1) at 1:0:5e:0:0:1 on en0\n";
        let parsed = parse_native_arp(mac, true);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[&ip("192.168.1.2")], "0a:0b:0c:0d:0e:0f");
        let windows = "Interface: 192.168.1.42 --- 0x5\n  Internetadresse Physische Adresse Typ\n  192.168.1.2 18-FD-74-69-74-29 dynamisch\n  192.168.1.3 00-00-00-00-00-00 ungültig\n  255.255.255.255 ff-ff-ff-ff-ff-ff statisch\n";
        let parsed = parse_native_arp(windows, false);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[&ip("192.168.1.2")], "18:fd:74:69:74:29");
    }

    #[test]
    fn lists_only_local_networks() {
        // Reads interfaces only; nothing is probed.
        for n in local_networks() {
            println!("{n:?}");
            assert!(is_local_range(n.address.parse().unwrap()));
            assert!(n.hosts > 0 && n.hosts <= MAX_HOSTS);
        }
    }

    #[test]
    fn parses_banners() {
        assert_eq!(parse_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"), Some(("OpenSSH 9.6p1".into(), Some("Ubuntu".into()))));
        assert_eq!(parse_banner(b"SSH-2.0-OpenSSH_9.2p1 Raspbian-2+deb12u3\r\n").unwrap().1.as_deref(), Some("Raspberry Pi OS"));
        assert_eq!(parse_banner(b"SSH-2.0-OpenSSH_for_Windows_9.5\r\n"), Some(("OpenSSH 9.5".into(), Some("Windows".into()))));
        assert_eq!(parse_banner(b"SSH-2.0-dropbear_2022.83\r\n").unwrap().1.as_deref(), Some("Embedded (Dropbear)"));
        assert_eq!(parse_banner(b"SSH-2.0-OpenSSH_10.0\r\n"), Some(("OpenSSH 10.0".into(), None)));
        assert_eq!(parse_banner(b"HTTP/1.1 400 Bad Request\r\n"), None);
        let hostile = parse_banner(b"SSH-2.0-Evil\x1b[31m\x07name<script>\r\n").unwrap().0;
        assert!(!hostile.contains('\u{1b}') && !hostile.contains('\u{7}'));
    }
}
