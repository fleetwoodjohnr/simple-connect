import { useEffect, useMemo, useState } from "react";
import { Channel } from "@tauri-apps/api/core";
import { Popover } from "radix-ui";
import { Radar, Search } from "lucide-react";
import { api, errorMessage } from "../services/ipc";
import { useUi } from "../stores/ui";
import { findProfile, profileToDraft, useConnections } from "../stores/connections";
import { useSessions } from "../stores/sessions";
import type { Device, LocalNetwork, Profile, ScanEvent } from "../types/ipc";
import { Dialog } from "../components/ui/Dialog";
import { Button } from "../components/ui/Button";
import { inputClass } from "../components/ui/Field";
import { ProfileIcon } from "./appearance";

const ipValue = (ip: string) => ip.split(".").reduce((n, part) => n * 256 + Number(part), 0);

/** `atlas.local` → `atlas`: local suffixes add nothing for a person. systemd names
 *  the default gateway `_gateway`. */
export const friendlyHost = (h: string | null) =>
  h === "_gateway" ? "Router (gateway)" : (h?.replace(/\.(local|lan|home|localdomain|home\.arpa)$/i, "") ?? null);

function stored(key: string, fallback: string) {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}
function remember(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* preference lasts for this session */
  }
}

function sshText(d: Device, port: number) {
  if (d.ssh.state === "open") return [d.ssh.software ?? "SSH", d.ssh.os].filter(Boolean).join(" · ");
  if (d.ssh.state === "closed") return `No SSH on port ${port}`;
  return `No answer on port ${port}`;
}

function ConnectAs({ device, port, onConnect }: { device: Device; port: number; onConnect: (user: string) => void }) {
  const [user, setUser] = useState(() => stored("scanUser", ""));
  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <Button variant="primary" className="h-7">
          Connect
        </Button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="end" sideOffset={6} className="animate-pop z-[60] w-64 rounded-panel bg-raised p-3 shadow-pop">
          <form
            className="flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (!user.trim()) return;
              remember("scanUser", user.trim());
              onConnect(user.trim());
            }}
          >
            <label className="flex flex-col gap-1 text-muted">
              User name on {device.ip}
              <input autoFocus className={`${inputClass} font-mono`} value={user} onChange={(e) => setUser(e.target.value)} spellCheck={false} />
            </label>
            <Button type="submit" variant="primary" disabled={!user.trim()}>
              Connect{port !== 22 ? ` on port ${port}` : ""}
            </Button>
          </form>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

/**
 * Finds devices on the local network. Nothing runs until the user presses Scan,
 * and only networks this computer is attached to are offered (the backend checks).
 */
export function NetworkScanner() {
  const { scannerOpen, setScannerOpen, setEditing } = useUi();
  const { profiles, save } = useConnections();
  const connect = useSessions((s) => s.connect);
  const [networks, setNetworks] = useState<LocalNetwork[]>([]);
  const [networkId, setNetworkId] = useState("");
  const [port, setPort] = useState(() => Number(stored("scanPort", "22")) || 22);
  const [devices, setDevices] = useState<Map<string, Device>>(new Map());
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [state, setState] = useState<"idle" | "scanning" | "done">("idle");
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    if (!scannerOpen) return;
    void api.listNetworks().then((n) => {
      setNetworks(n);
      setNetworkId((id) => (n.some((x) => x.id === id) ? id : (n[0]?.id ?? "")));
    });
  }, [scannerOpen]);

  const network = networks.find((n) => n.id === networkId);

  const scan = async () => {
    remember("scanPort", String(port));
    setDevices(new Map());
    setError(null);
    setState("scanning");
    const channel = new Channel<ScanEvent>();
    channel.onmessage = (e) => {
      if (e.type === "progress") setProgress({ done: e.done, total: e.total });
      else if (e.type === "device") setDevices((prev) => new Map(prev).set(e.device.ip, { ...prev.get(e.device.ip), ...e.device }));
      else setState("done");
    };
    try {
      await api.scanNetwork(networkId, port, channel);
    } catch (e) {
      setError(errorMessage(e, "The scan couldn't start."));
    } finally {
      setState((s) => (s === "scanning" ? "done" : s));
    }
  };

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return [...devices.values()]
      .map((d) => ({ d, saved: findProfile(profiles, { mac: d.mac, host: d.ip }) }))
      .filter(({ d, saved }) => !q || [d.ip, d.hostname ?? "", d.mac ?? "", saved?.name ?? "", ...(saved?.tags ?? [])].some((s) => s.toLowerCase().includes(q)))
      .sort((a, b) => Number(b.d.ssh.state === "open") - Number(a.d.ssh.state === "open") || ipValue(a.d.ip) - ipValue(b.d.ip));
  }, [devices, profiles, filter]);

  const close = () => {
    if (state === "scanning") void api.cancelScan();
    setScannerOpen(false);
  };

  const open = (saved: Profile) => {
    close();
    void connect({ kind: "profile", profile: saved });
  };

  const quickConnect = async (d: Device, user: string) => {
    const input = `${user}@${d.ip}${port !== 22 ? ` -p ${port}` : ""}`;
    try {
      const dest = await api.parseQuickConnect(input);
      close();
      void connect({ kind: "quick", input, dest, mac: d.mac });
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const pct = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <Dialog
      open={scannerOpen}
      onOpenChange={(o) => !o && close()}
      title={
        <span className="flex items-center gap-2">
          <Radar size={17} className="text-accent" /> Devices on your network
        </span>
      }
      width="w-[min(900px,95vw)] h-[min(720px,90vh)]"
    >
      <div className="flex h-full flex-col gap-3">
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex min-w-64 flex-1 flex-col gap-1 text-muted">
            Network
            <select className={inputClass} value={networkId} onChange={(e) => setNetworkId(e.target.value)} disabled={state === "scanning"}>
              {networks.length === 0 && <option value="">No local network found</option>}
              {networks.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.interface} · {n.scanCidr} ({n.hosts} addresses){n.preferred ? " · current" : ""}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-muted">
            SSH port
            <input
              className={`${inputClass} w-24 font-mono`}
              inputMode="numeric"
              value={port}
              disabled={state === "scanning"}
              onChange={(e) => setPort(Math.min(65535, Number(e.target.value.replace(/\D/g, "")) || 0))}
            />
          </label>
          {state === "scanning" ? (
            <Button onClick={() => void api.cancelScan()}>Stop</Button>
          ) : (
            <Button variant="primary" disabled={!network || !port} onClick={() => void scan()}>
              <Radar size={14} /> {state === "done" ? "Scan again" : "Scan"}
            </Button>
          )}
        </div>

        {network && network.scanCidr !== network.cidr && (
          <p className="text-xs text-faint">
            {network.cidr} is large, so only {network.scanCidr} (around this computer) is scanned.
          </p>
        )}
        {state === "scanning" && (
          <div role="progressbar" aria-label="Scan progress" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} className="h-1 overflow-hidden rounded-full bg-line">
            <div className="h-full bg-accent transition-[width]" style={{ width: `${pct}%` }} />
          </div>
        )}
        {error && <p className="text-bad">{error}</p>}

        {devices.size > 0 && (
          <label className="flex h-8 items-center gap-2 rounded-control border border-line bg-ink px-2 text-muted focus-within:border-accent">
            <Search size={14} aria-hidden />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by name, address, MAC or tag"
              aria-label="Filter devices"
              className="min-w-0 flex-1 bg-transparent text-text outline-none placeholder:text-faint"
            />
          </label>
        )}

        {state === "done" && devices.size > 0 && (
          <p className="text-muted" role="status">
            {devices.size} {devices.size === 1 ? "device" : "devices"} found,{" "}
            {(() => {
              const n = [...devices.values()].filter((d) => d.ssh.state === "open").length;
              return n === 0 ? `none with SSH on port ${port}.` : `${n} with SSH.`;
            })()}
          </p>
        )}
        <div className="min-h-0 flex-1 overflow-y-auto">
          {state === "idle" && devices.size === 0 && (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-center text-muted">
              <Radar size={28} className="text-faint" aria-hidden />
              <p className="max-w-md">
                Find computers, servers and boards on {network ? network.scanCidr : "your network"} that accept SSH connections.
              </p>
            </div>
          )}
          {state === "done" && rows.length === 0 && (
            <p className="py-10 text-center text-muted">{filter ? "No devices match the filter." : "No devices answered. Devices that block connections can't be found."}</p>
          )}
          <ul className="flex flex-col gap-1">
            {rows.map(({ d, saved }) => {
              // Recognised by MAC at a new IP (DHCP): offer to update the saved address.
              const moved = !!saved?.mac && saved.mac === d.mac && saved.host !== d.ip && /^\d+\.\d+\.\d+\.\d+$/.test(saved.host);
              const name = saved?.name ?? friendlyHost(d.hostname) ?? "Unknown device";
              return (
                <li key={d.ip} className="flex items-center gap-3 rounded-control px-3 py-2 hover:bg-hover">
                  <span className={`size-2 shrink-0 rounded-full ${d.ssh.state === "open" ? "bg-ok" : "bg-faint"}`} aria-hidden />
                  {saved && <ProfileIcon icon={saved.icon} color={saved.color} />}
                  <div className="min-w-0 flex-1">
                    <p className="flex items-baseline gap-2">
                      <span className={`truncate ${saved ? "font-medium" : name === "Unknown device" ? "text-muted" : ""}`}>{name}</span>
                      {saved && d.hostname && friendlyHost(d.hostname) !== saved.name && <span className="truncate text-xs text-faint">{friendlyHost(d.hostname)}</span>}
                    </p>
                    <p className="flex flex-wrap gap-x-3 text-xs text-muted">
                      <span className="font-mono text-text">{d.ip}</span>
                      {d.mac && <span className="font-mono text-faint">{d.mac}</span>}
                      <span>{sshText(d, port)}</span>
                    </p>
                  </div>
                  {moved && (
                    <Button className="h-7" onClick={() => void save({ ...profileToDraft(saved), host: d.ip }, saved.id)} title={`Saved as ${saved.host}`}>
                      Update address
                    </Button>
                  )}
                  {saved ? (
                    <>
                      <Button variant="ghost" className="h-7" onClick={() => setEditing({ profile: saved })}>
                        Edit
                      </Button>
                      <Button variant="primary" className="h-7" disabled={moved} title={moved ? "Update the address first" : undefined} onClick={() => open(saved)}>
                        Connect
                      </Button>
                    </>
                  ) : (
                    <>
                      <Button
                        variant="ghost"
                        className="h-7"
                        onClick={() =>
                          setEditing({
                            initial: { name: friendlyHost(d.hostname) ?? d.ip, host: d.ip, port: port !== 22 ? port : null, mac: d.mac, username: stored("scanUser", "") || null },
                          })
                        }
                      >
                        Save…
                      </Button>
                      {d.ssh.state !== "closed" && <ConnectAs device={d} port={port} onConnect={(user) => void quickConnect(d, user)} />}
                    </>
                  )}
                </li>
              );
            })}
          </ul>
        </div>

        <p className="text-xs text-faint">
          Only runs when you press Scan, and only on {network?.scanCidr ?? "your local network"}. Each address gets one connection attempt on port {port}; no sign-in is tried and nothing is sent.
        </p>
      </div>
    </Dialog>
  );
}
