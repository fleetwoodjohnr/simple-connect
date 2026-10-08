import { useState } from "react";
import { ArrowRight, Plus, Trash2 } from "lucide-react";
import { api, errorMessage } from "../services/ipc";
import type { SessionTab } from "../stores/sessions";
import type { TunnelKind, TunnelSpec } from "../types/ipc";
import { Button } from "../components/ui/Button";
import { inputClass } from "../components/ui/Field";
import { IconButton } from "../components/ui/IconButton";

const KINDS: { value: TunnelKind; label: string; hint: string }[] = [
  { value: "local", label: "Local", hint: "A port on this computer reaches a service the server can see." },
  { value: "remote", label: "Remote", hint: "A port on the server reaches a service this computer can see." },
  { value: "dynamic", label: "SOCKS proxy", hint: "A local SOCKS5 proxy that sends traffic through the server." },
];

function describe(s: TunnelSpec) {
  const listen = `${s.bindAddress}:${s.bindPort}`;
  return s.kind === "dynamic" ? { from: `SOCKS ${listen}`, to: "via server" } : { from: s.kind === "remote" ? `server ${listen}` : listen, to: `${s.targetHost}:${s.targetPort}` };
}

export function TunnelManager({ tab }: { tab: SessionTab }) {
  const [spec, setSpec] = useState<TunnelSpec>({ kind: "local", bindAddress: "127.0.0.1", bindPort: 0, targetHost: "localhost", targetPort: null, allowExternal: false });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const num = (v: string) => (v === "" ? 0 : Math.min(65535, Number(v.replace(/\D/g, ""))));
  const external = !["127.0.0.1", "::1", "localhost"].includes(spec.bindAddress.trim());

  const add = async () => {
    setBusy(true);
    try {
      await api.addTunnel(tab.id, { ...spec, targetHost: spec.kind === "dynamic" ? null : spec.targetHost, targetPort: spec.kind === "dynamic" ? null : spec.targetPort });
      setError(null);
    } catch (e) {
      setError(errorMessage(e, "The tunnel couldn't be opened."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-6 p-6">
      <section className="flex flex-col gap-2">
        <h2 className="text-base font-semibold">Tunnels</h2>
        {tab.tunnels.length === 0 && <p className="text-muted">No tunnels on this connection.</p>}
        <ul className="flex flex-col gap-1.5">
          {tab.tunnels.map((t) => {
            const d = describe(t.spec);
            return (
              <li key={t.id} className="flex items-center gap-3 rounded-control border border-line bg-panel px-3 py-2">
                <span className={`size-2 rounded-full ${t.active ? "bg-ok" : "bg-faint"}`} aria-hidden />
                <span className="w-24 text-xs text-muted">{KINDS.find((k) => k.value === t.spec.kind)?.label}</span>
                <span className="font-mono">{d.from}</span>
                <ArrowRight size={14} className="text-faint" aria-hidden />
                <span className="font-mono">{d.to}</span>
                <span className="ml-auto text-xs text-muted">{t.active ? "Active" : (t.error ?? "Inactive")}</span>
                <IconButton label="Close tunnel" onClick={() => void api.removeTunnel(tab.id, t.id)}>
                  <Trash2 size={14} />
                </IconButton>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="flex flex-col gap-3 rounded-panel border border-line bg-panel p-4">
        <h3 className="font-semibold">New tunnel</h3>
        <div role="radiogroup" aria-label="Tunnel type" className="flex gap-1.5">
          {KINDS.map((k) => (
            <button
              key={k.value}
              type="button"
              role="radio"
              aria-checked={spec.kind === k.value}
              onClick={() => setSpec({ ...spec, kind: k.value })}
              className="rounded-control border border-line px-3 py-1.5 text-muted aria-checked:border-accent aria-checked:bg-accent-soft aria-checked:text-text"
            >
              {k.label}
            </button>
          ))}
        </div>
        <p className="text-xs text-faint">{KINDS.find((k) => k.value === spec.kind)?.hint}</p>
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-muted">
            Listen on
            <input className={`${inputClass} w-36 font-mono`} value={spec.bindAddress} onChange={(e) => setSpec({ ...spec, bindAddress: e.target.value })} />
          </label>
          <label className="flex flex-col gap-1 text-muted">
            Port
            <input className={`${inputClass} w-24 font-mono`} inputMode="numeric" value={spec.bindPort || ""} placeholder="5433" onChange={(e) => setSpec({ ...spec, bindPort: num(e.target.value) })} />
          </label>
          {spec.kind !== "dynamic" && (
            <>
              <ArrowRight size={16} className="mb-2 text-faint" aria-hidden />
              <label className="flex flex-col gap-1 text-muted">
                Destination host
                <input className={`${inputClass} w-48 font-mono`} value={spec.targetHost ?? ""} placeholder="db.internal" onChange={(e) => setSpec({ ...spec, targetHost: e.target.value })} />
              </label>
              <label className="flex flex-col gap-1 text-muted">
                Port
                <input className={`${inputClass} w-24 font-mono`} inputMode="numeric" value={spec.targetPort ?? ""} placeholder="5432" onChange={(e) => setSpec({ ...spec, targetPort: num(e.target.value) || null })} />
              </label>
            </>
          )}
        </div>
        {external && (
          <label className="flex items-start gap-2 rounded-control bg-warn-soft p-2.5 text-warn">
            <input type="checkbox" checked={spec.allowExternal} onChange={(e) => setSpec({ ...spec, allowExternal: e.target.checked })} className="mt-0.5" />
            Listening on {spec.bindAddress || "this address"} lets other computers on the network use this tunnel. Allow it.
          </label>
        )}
        {error && <p className="text-bad">{error}</p>}
        <div>
          <Button variant="primary" disabled={busy || tab.status.state !== "connected"} onClick={() => void add()}>
            <Plus size={15} /> Open tunnel
          </Button>
        </div>
      </section>
    </div>
  );
}
