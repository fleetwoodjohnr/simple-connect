import { useState, type ReactNode } from "react";
import { ChevronRight, Lock, RefreshCw } from "lucide-react";
import { Collapsible } from "radix-ui";
import { api, errorMessage } from "../services/ipc";
import { describeStatus, quickToDraft, type SessionTab } from "../stores/sessions";
import { useUi } from "../stores/ui";
import { useConnections } from "../stores/connections";
import type { SysInfo } from "../types/ipc";
import { Button } from "../components/ui/Button";
import { StatusDot } from "../components/StatusDot";
import { RoutePreview } from "../connections/RoutePreview";
import { FingerprintGlyph } from "./FingerprintGlyph";
import { authName, cipherName, hostKeyName, isLegacy, kexName } from "./names";
import { formatBytes } from "../file-manager/format";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[11rem_1fr] gap-3 py-1.5">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words" data-selectable>
        {children}
      </dd>
    </div>
  );
}

const fmtUptime = (s: number) => {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return d ? `${d} d ${h} h` : `${h} h ${Math.floor((s % 3600) / 60)} min`;
};

export function SessionInfo({ tab }: { tab: SessionTab }) {
  const profile = useConnections((s) => s.profiles.find((p) => p.id === tab.profileId));
  const setEditing = useUi((s) => s.setEditing);
  const [sys, setSys] = useState<SysInfo | null>(null);
  const [sysError, setSysError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const info = tab.info;
  const legacy = [info?.cipher, info?.kex, info?.hostKeyAlgorithm, info?.mac].some(isLegacy);

  const loadSys = async () => {
    setLoading(true);
    try {
      setSys(await api.systemInfo(tab.id));
      setSysError(null);
    } catch (e) {
      setSysError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-6 p-6">
      <header className="flex items-center gap-3">
        <StatusDot status={tab.status} className="size-2.5" />
        <div>
          <h2 className="text-base font-semibold">{tab.label}</h2>
          <p className="text-muted" role="status">
            {describeStatus(tab.status)}
          </p>
        </div>
        <span className="ml-auto flex gap-2">
          {!profile && tab.quick && (
            <Button onClick={() => setEditing({ initial: quickToDraft(tab), linkSession: tab.id })}>Save as connection…</Button>
          )}
          {tab.status.state !== "connected" && (
            <Button onClick={() => void api.reconnect(tab.id)}>
              <RefreshCw size={14} /> Reconnect
            </Button>
          )}
        </span>
      </header>

      {profile && profile.jump.length > 0 && <RoutePreview jump={profile.jump} target={{ user: profile.username, host: profile.host, port: profile.port }} />}

      {tab.failure && tab.status.state !== "connected" && (
        <section role="alert" className="rounded-panel border border-bad/40 bg-bad-soft p-4">
          <p className="text-text">{tab.failure.message}</p>
          {tab.failure.details && (
            <Collapsible.Root className="mt-2">
              <Collapsible.Trigger className="group flex items-center gap-1 text-muted hover:text-text">
                <ChevronRight size={13} className="transition-transform group-data-[state=open]:rotate-90" /> Technical details
              </Collapsible.Trigger>
              <Collapsible.Content>
                <pre className="mt-2 max-h-56 overflow-auto rounded-control bg-ink p-3 font-mono text-xs text-muted" data-selectable>
                  {tab.failure.details}
                </pre>
              </Collapsible.Content>
            </Collapsible.Root>
          )}
        </section>
      )}

      {info?.cipher && (
        <section className="rounded-panel border border-line bg-panel p-4">
          <div className="flex items-center gap-3">
            <Lock size={16} className={legacy ? "text-warn" : "text-ok"} aria-hidden />
            <p>
              {legacy ? "Connected with legacy algorithms" : "Connected securely"} · {hostKeyName(info.hostKeyAlgorithm)} · {cipherName(info.cipher)}
            </p>
          </div>
          <Collapsible.Root className="mt-3">
            <Collapsible.Trigger className="group flex items-center gap-1 text-muted hover:text-text">
              <ChevronRight size={13} className="transition-transform group-data-[state=open]:rotate-90" /> Connection security
            </Collapsible.Trigger>
            <Collapsible.Content>
              <dl className="mt-2 divide-y divide-line">
                <Row label="Encryption">
                  {cipherName(info.cipher)} <span className="font-mono text-xs text-faint">{info.cipher}</span>
                </Row>
                {info.mac && (
                  <Row label="Integrity">
                    <span className="font-mono text-xs">{info.mac}</span>
                  </Row>
                )}
                <Row label="Key exchange">
                  {kexName(info.kex)} <span className="font-mono text-xs text-faint">{info.kex}</span>
                </Row>
                <Row label="Host key">
                  {hostKeyName(info.hostKeyAlgorithm)} <span className="font-mono text-xs text-faint">{info.hostKeyAlgorithm}</span>
                </Row>
                {info.hostKeyFingerprint && (
                  <Row label="Host fingerprint">
                    <span className="flex items-center gap-3">
                      <FingerprintGlyph fingerprint={info.hostKeyFingerprint} size={36} />
                      <span className="font-mono text-xs">{info.hostKeyFingerprint}</span>
                    </span>
                  </Row>
                )}
                <Row label="Authentication">{authName(info.authMethod)}</Row>
                {info.serverSoftware && <Row label="Server software">{info.serverSoftware}</Row>}
                {info.remoteAddress && (
                  <Row label="Address">
                    <span className="font-mono">{info.remoteAddress}</span>
                  </Row>
                )}
              </dl>
            </Collapsible.Content>
          </Collapsible.Root>
        </section>
      )}

      <section className="rounded-panel border border-line bg-panel p-4">
        <div className="flex items-center">
          <h3 className="font-semibold">System</h3>
          <Button variant="ghost" className="ml-auto" disabled={loading || tab.status.state !== "connected"} onClick={() => void loadSys()}>
            {sys ? "Refresh" : "Show system information"}
          </Button>
        </div>
        {!sys && !sysError && <p className="mt-1 text-muted">Reads the host name, OS, uptime, CPU, memory and disk. No administrator rights are used.</p>}
        {sysError && <p className="mt-2 text-bad">{sysError}</p>}
        {sys && (
          <dl className="mt-2 divide-y divide-line">
            {sys.hostname && <Row label="Host name">{sys.hostname}</Row>}
            {sys.os && <Row label="Operating system">{sys.os}</Row>}
            {sys.kernel && <Row label="Kernel">{sys.kernel}</Row>}
            {sys.arch && <Row label="Architecture">{sys.arch}</Row>}
            {sys.uptimeSecs !== null && <Row label="Uptime">{fmtUptime(sys.uptimeSecs)}</Row>}
            {sys.cpus !== null && <Row label="CPUs">{sys.cpus}</Row>}
            {sys.memTotalKb !== null && (
              <Row label="Memory">
                {sys.memAvailableKb !== null && `${formatBytes(sys.memAvailableKb * 1024)} free of `}
                {formatBytes(sys.memTotalKb * 1024)}
              </Row>
            )}
            {sys.diskTotalKb !== null && (
              <Row label="Disk (/)">
                {formatBytes((sys.diskUsedKb ?? 0) * 1024)} used of {formatBytes(sys.diskTotalKb * 1024)}
              </Row>
            )}
            {sys.addresses.length > 0 && <Row label="IP addresses">{sys.addresses.join(", ")}</Row>}
          </dl>
        )}
      </section>

      <section>
        <h3 className="mb-2 font-semibold">Activity</h3>
        <ol className="flex flex-col gap-1 text-muted">
          {[...tab.log].reverse().map((l, i) => (
            <li key={i} className="flex gap-3">
              <time className="w-20 shrink-0 tabular-nums text-faint">{new Date(l.at).toLocaleTimeString()}</time>
              <span>{l.text}</span>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
