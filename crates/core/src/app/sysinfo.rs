//! Basic, unprivileged remote system information, gathered only on request.
//! The command is a fixed string: no user input reaches the remote shell.

use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;

use super::{AppError, Manager};

const SCRIPT: &str = r#"echo "hostname=$(hostname 2>/dev/null || uname -n)"
echo "kernel=$(uname -sr 2>/dev/null)"
echo "arch=$(uname -m 2>/dev/null)"
if [ -r /etc/os-release ]; then . /etc/os-release; echo "os=$PRETTY_NAME"; elif command -v sw_vers >/dev/null 2>&1; then echo "os=macOS $(sw_vers -productVersion)"; fi
[ -r /proc/uptime ] && echo "uptime=$(cut -d' ' -f1 /proc/uptime)"
echo "cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null)"
[ -r /proc/meminfo ] && awk '/^MemTotal:/{print "memTotalKb="$2} /^MemAvailable:/{print "memAvailableKb="$2}' /proc/meminfo
df -Pk / 2>/dev/null | awk 'NR==2{print "diskTotalKb="$2; print "diskUsedKb="$3}'
echo "addresses=$(hostname -I 2>/dev/null)""#;

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SysInfo {
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub arch: Option<String>,
    pub uptime_secs: Option<u64>,
    pub cpus: Option<u32>,
    pub mem_total_kb: Option<u64>,
    pub mem_available_kb: Option<u64>,
    pub disk_total_kb: Option<u64>,
    pub disk_used_kb: Option<u64>,
    pub addresses: Vec<String>,
}

pub fn parse(output: &str) -> SysInfo {
    let mut i = SysInfo::default();
    for line in output.lines().take(64) {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        let text = || Some(v.chars().filter(|c| !c.is_control()).take(200).collect::<String>());
        match k {
            "hostname" => i.hostname = text(),
            "kernel" => i.kernel = text(),
            "arch" => i.arch = text(),
            "os" => i.os = text(),
            "uptime" => i.uptime_secs = v.split('.').next().and_then(|s| s.parse().ok()),
            "cpus" => i.cpus = v.parse().ok(),
            "memTotalKb" => i.mem_total_kb = v.parse().ok(),
            "memAvailableKb" => i.mem_available_kb = v.parse().ok(),
            "diskTotalKb" => i.disk_total_kb = v.parse().ok(),
            "diskUsedKb" => i.disk_used_kb = v.parse().ok(),
            "addresses" => i.addresses = v.split_whitespace().take(16).map(str::to_owned).collect(),
            _ => {}
        }
    }
    i
}

pub async fn gather(m: &Manager, session: &str) -> Result<SysInfo, AppError> {
    let s = m.session(session)?;
    let master = s.master().ok_or(AppError::NotConnected)?;
    let mut args = master.client_args(&s.req.dest);
    args.extend(["-T".into(), "--".into(), s.req.dest.host.as_str().into(), SCRIPT.into()]);
    let child =
        tokio::process::Command::new(&m.engine.ossh.ssh).args(args).stdin(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).output();
    let out = tokio::time::timeout(Duration::from_secs(10), child)
        .await
        .map_err(|_| AppError::Invalid("The server took too long to respond.".into()))??;
    Ok(parse(&String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(16 * 1024)])))
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_linux_output() {
        let i = super::parse(
            "hostname=nas\nos=Debian GNU/Linux 12\nuptime=3600.5 1.0\ncpus=4\nmemTotalKb=8000\naddresses=10.0.0.2 fd00::2\nbogus\n",
        );
        assert_eq!(i.hostname.as_deref(), Some("nas"));
        assert_eq!(i.uptime_secs, Some(3600));
        assert_eq!(i.addresses, ["10.0.0.2", "fd00::2"]);
    }
}
