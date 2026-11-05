//! Port forwarding through the session's ControlMaster (`ssh -O forward|cancel`).
//! Tunnels are re-established after a reconnect.

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{AppError, Manager, Session, UiEvent};
use crate::validate::Host;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelKind {
    /// -L: a local port reaches a host on the server's side.
    Local,
    /// -R: a port on the server reaches a host on this side.
    Remote,
    /// -D: a local SOCKS proxy.
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelSpec {
    pub kind: TunnelKind,
    /// IP literal or `localhost`. Defaults to loopback.
    pub bind_address: String,
    pub bind_port: u16,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    /// Binding to a non-loopback address exposes the tunnel to the network and
    /// must be requested explicitly.
    #[serde(default)]
    pub allow_external: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tunnel {
    pub id: String,
    pub spec: TunnelSpec,
    pub active: bool,
    pub error: Option<String>,
}

fn bracket(h: &str) -> String {
    if h.contains(':') { format!("[{h}]") } else { h.to_owned() }
}

impl TunnelSpec {
    /// Validates and returns the `ssh` flag and its argument, e.g. `("-L", "127.0.0.1:5433:db:5432")`.
    pub fn to_arg(&self) -> Result<(&'static str, String), String> {
        let bind = self.bind_address.trim();
        let loopback = match bind {
            "localhost" => true,
            b => b.parse::<IpAddr>().map_err(|_| "The listen address must be an IP address or localhost.".to_owned())?.is_loopback(),
        };
        if !loopback && !self.allow_external {
            return Err("Listening on a non-local address exposes the tunnel to other computers. Confirm to allow it.".into());
        }
        if self.bind_port == 0 {
            return Err("Choose a listen port from 1 to 65535.".into());
        }
        let listen = format!("{}:{}", bracket(bind), self.bind_port);
        if self.kind == TunnelKind::Dynamic {
            return Ok(("-D", listen));
        }
        let host = Host::parse(self.target_host.as_deref().unwrap_or_default()).map_err(|e| e.to_string())?;
        let port = self.target_port.filter(|p| *p != 0).ok_or("Choose a destination port from 1 to 65535.")?;
        let flag = if self.kind == TunnelKind::Local { "-L" } else { "-R" };
        Ok((flag, format!("{listen}:{}:{port}", bracket(host.as_str()))))
    }
}

#[derive(Default)]
pub struct Registry {
    tunnels: Mutex<HashMap<String, Vec<Tunnel>>>,
}

async fn control(m: &Manager, s: &Session, op: &str, flag: &str, arg: &str) -> Result<(), String> {
    let master = s.master().ok_or("Not connected.")?;
    if cfg!(any(windows, feature = "independent-ssh")) {
        return master.forward(&m.engine.ossh, &s.req.dest, op, flag, arg).await;
    }
    let mut args = master.client_args(&s.req.dest);
    // The generated config clears forwardings by default; this request is explicit.
    args.extend(["-o".into(), "ClearAllForwardings=no".into(), "-O".into(), op.into(), flag.into(), arg.into()]);
    args.extend(["--".into(), s.req.dest.host.as_str().into()]);
    let out = tokio::process::Command::new(&m.engine.ossh.ssh).args(args).stdin(Stdio::null()).output().await.map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(if err.contains("forwarding failed") || err.contains("Address already in use") {
        "The port couldn't be opened. It may be in use, or forwarding may be disabled on the server.".into()
    } else {
        err.trim().to_owned()
    })
}

impl Registry {
    pub fn list(&self, session: &str) -> Vec<Tunnel> {
        self.tunnels.lock().ok().and_then(|t| t.get(session).cloned()).unwrap_or_default()
    }

    fn emit(&self, m: &Manager, session: &str) {
        m.emit(UiEvent::Tunnels { session: session.into(), tunnels: self.list(session) });
    }

    pub async fn add(&self, m: &Arc<Manager>, session: &str, spec: TunnelSpec) -> Result<Tunnel, AppError> {
        let (flag, arg) = spec.to_arg().map_err(AppError::Invalid)?;
        let s = m.session(session)?;
        control(m, &s, "forward", flag, &arg).await.map_err(AppError::Invalid)?;
        let t = Tunnel { id: uuid::Uuid::new_v4().to_string(), spec, active: true, error: None };
        if let Ok(mut map) = self.tunnels.lock() {
            map.entry(session.into()).or_default().push(t.clone());
        }
        self.emit(m, session);
        if cfg!(any(windows, feature = "independent-ssh")) {
            self.watch_forward(m, session, &t);
        }
        Ok(t)
    }

    pub async fn remove(&self, m: &Arc<Manager>, session: &str, id: &str) -> Result<(), AppError> {
        let t = self.list(session).into_iter().find(|t| t.id == id).ok_or(AppError::NoSession)?;
        if t.active
            && let (Ok(s), Ok((flag, arg))) = (m.session(session), t.spec.to_arg())
        {
            let _ = control(m, &s, "cancel", flag, &arg).await;
        }
        if let Ok(mut map) = self.tunnels.lock()
            && let Some(v) = map.get_mut(session)
        {
            v.retain(|t| t.id != id);
        }
        self.emit(m, session);
        Ok(())
    }

    /// Re-opens a session's tunnels on a fresh connection.
    pub async fn restore(&self, m: &Arc<Manager>, s: &Session) {
        let list = self.list(&s.id);
        if list.is_empty() {
            return;
        }
        let mut updated = Vec::new();
        for mut t in list {
            let res = match t.spec.to_arg() {
                Ok((flag, arg)) => control(m, s, "forward", flag, &arg).await,
                Err(e) => Err(e),
            };
            t.active = res.is_ok();
            t.error = res.err();
            if cfg!(any(windows, feature = "independent-ssh")) && t.active {
                self.watch_forward(m, &s.id, &t);
            }
            updated.push(t);
        }
        if let Ok(mut map) = self.tunnels.lock() {
            map.insert(s.id.clone(), updated);
        }
        self.emit(m, &s.id);
    }

    fn watch_forward(&self, m: &Arc<Manager>, session: &str, tunnel: &Tunnel) {
        let manager = Arc::downgrade(m);
        let session = session.to_owned();
        let id = tunnel.id.clone();
        let spec = tunnel.spec.clone();
        let original = m.session(&session).ok().and_then(|s| s.master());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(m) = manager.upgrade() else { return };
                let Ok(s) = m.session(&session) else { return };
                let Some(master) = s.master() else { return };
                if !original.as_ref().is_some_and(|old| Arc::ptr_eq(old, &master)) {
                    return;
                }
                let Ok((flag, arg)) = spec.to_arg() else { return };
                if master.forward_is_alive(flag, &arg).await {
                    continue;
                }
                if let Ok(mut map) = m.tunnels.tunnels.lock()
                    && let Some(t) = map.get_mut(&session).and_then(|list| list.iter_mut().find(|t| t.id == id))
                {
                    t.active = false;
                    t.error = Some("The forwarding connection ended.".into());
                }
                m.tunnels.emit(&m, &session);
                return;
            }
        });
    }

    pub fn mark_inactive(&self, m: &Manager, session: &str) {
        if let Ok(mut map) = self.tunnels.lock()
            && let Some(v) = map.get_mut(session)
        {
            v.iter_mut().for_each(|t| t.active = false);
        }
        self.emit(m, session);
    }

    pub fn forget_session(&self, session: &str) {
        if let Ok(mut map) = self.tunnels.lock() {
            map.remove(session);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: TunnelKind, bind: &str, host: Option<&str>) -> TunnelSpec {
        TunnelSpec {
            kind,
            bind_address: bind.into(),
            bind_port: 5433,
            target_host: host.map(Into::into),
            target_port: Some(5432),
            allow_external: false,
        }
    }

    #[test]
    fn builds_forward_arguments() {
        assert_eq!(spec(TunnelKind::Local, "127.0.0.1", Some("db")).to_arg().unwrap(), ("-L", "127.0.0.1:5433:db:5432".into()));
        assert_eq!(spec(TunnelKind::Remote, "::1", Some("fd00::5")).to_arg().unwrap(), ("-R", "[::1]:5433:[fd00::5]:5432".into()));
        assert_eq!(spec(TunnelKind::Dynamic, "localhost", None).to_arg().unwrap(), ("-D", "localhost:5433".into()));
    }

    #[test]
    fn rejects_unsafe_specs() {
        assert!(spec(TunnelKind::Local, "0.0.0.0", Some("db")).to_arg().is_err(), "LAN exposure needs consent");
        let mut ok = spec(TunnelKind::Local, "0.0.0.0", Some("db"));
        ok.allow_external = true;
        assert!(ok.to_arg().is_ok());
        assert!(spec(TunnelKind::Local, "127.0.0.1", Some("db -oProxyCommand=x")).to_arg().is_err());
        assert!(spec(TunnelKind::Local, "evil.example.com", Some("db")).to_arg().is_err(), "bind must be an IP");
        assert!(spec(TunnelKind::Local, "127.0.0.1", None).to_arg().is_err());
    }
}
