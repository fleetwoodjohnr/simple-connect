import { useCallback, useEffect, useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { ChevronRight, Info, Layers, LoaderCircle, Monitor, RefreshCw, ScreenShare, Server, Wrench } from "lucide-react";
import { Collapsible } from "radix-ui";
import { api, errorMessage } from "../services/ipc";
import { isConnected, useSessions, type SessionTab } from "../stores/sessions";
import { useConnections } from "../stores/connections";
import { useSettings } from "../stores/settings";
import type { DesktopError, DesktopMethod, DesktopOffer, DesktopOpenRequest, DesktopProbe, DesktopQuality, DesktopSetup, DesktopState } from "../types/ipc";
import { Button } from "../components/ui/Button";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { inputClass } from "../components/ui/Field";
import { VncViewer } from "./VncViewer";
import { RdpViewer } from "./RdpViewer";
import { Toolbar } from "./Toolbar";
import type { SpecialKey, ViewerHandle } from "./keys";
import { autoQuality } from "./quality";

const ICONS: Record<DesktopMethod, typeof Monitor> = { x11: ScreenShare, wayland: ScreenShare, virtual: Layers, vnc: Monitor, rdp: Server };

const STEPS: Record<string, string> = {
  starting: "Starting the remote desktop server…",
  connecting: "Connecting…",
  signingIn: "Signing in…",
};

const MAX_CLIPBOARD = 1024 * 1024;

function requestFor(offer: DesktopOffer, el: HTMLElement | null, session: string | null, user: string | null, quality: DesktopQuality): DesktopOpenRequest {
  return {
    method: offer.method,
    port: offer.port,
    display: offer.display,
    wayland: offer.wayland,
    session: offer.method === "virtual" ? session : null,
    width: Math.round(el?.clientWidth || 1280),
    height: Math.round(el?.clientHeight || 800),
    user,
    quality,
  };
}

function ErrorPanel({ error, onRetry, onVirtual }: { error: DesktopError; onRetry: () => void; onVirtual?: () => void }) {
  const title =
    error.code === "auth" ? "Sign-in failed" : error.code === "cancelled" ? "Sign-in cancelled" : error.code === "ended" ? "The remote desktop ended" : "The remote desktop couldn't be opened";
  return (
    <section role="alert" className={`rounded-panel border p-4 ${error.code === "ended" || error.code === "cancelled" ? "border-line bg-raised" : "border-bad/40 bg-bad-soft"}`}>
      <h3 className="font-semibold">{title}</h3>
      <p className="mt-1 text-text" data-selectable>
        {error.message}
      </p>
      {error.details && (
        <Collapsible.Root className="mt-2">
          <Collapsible.Trigger className="group flex items-center gap-1 text-xs text-muted hover:text-text">
            <ChevronRight size={12} className="transition-transform group-data-[state=open]:rotate-90" /> Technical details
          </Collapsible.Trigger>
          <Collapsible.Content>
            <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap rounded-control bg-ink p-2 font-mono text-xs text-muted" data-selectable>
              {error.details}
            </pre>
          </Collapsible.Content>
        </Collapsible.Root>
      )}
      <div className="mt-3 flex gap-2">
        {!["missing", "nosession", "unsupported"].includes(error.code) && <Button onClick={onRetry}>Try again</Button>}
        {onVirtual && error.code === "display" && <Button onClick={onVirtual}>Use a virtual desktop</Button>}
      </div>
    </section>
  );
}

/**
 * The Remote Desktop view of a session: finds out how the computer can show its
 * desktop, sets it up with the user's permission, and shows it. It stays
 * mounted while other views are shown, so the desktop keeps running.
 */
export function RemoteDesktop({ tab, visible }: { tab: SessionTab; visible: boolean }) {
  const connected = isConnected(tab);
  const profile = useConnections((s) => s.profiles.find((p) => p.id === tab.profileId));
  const settings = useSettings((s) => s.settings.remoteDesktop);
  const saveSettings = useSettings((s) => s.save);
  const { addTerminal, setView } = useSessions();

  const [probe, setProbe] = useState<DesktopProbe | null>(null);
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [choice, setChoice] = useState(0);
  const [xsession, setXsession] = useState<string | null>(null);
  const [active, setActive] = useState<{ request: DesktopOpenRequest; offer: DesktopOffer } | null>(null);
  const [gen, setGen] = useState(0);
  const [state, setState] = useState<DesktopState | null>(null);
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState<{ error: DesktopError; retry: { request: DesktopOpenRequest; offer: DesktopOffer } } | null>(null);
  const [setup, setSetup] = useState<DesktopSetup | null>(null);
  const [endConfirm, setEndConfirm] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [remoteClip, setRemoteClip] = useState<string | null>(null);
  const [rate, setRate] = useState(0);
  const area = useRef<HTMLDivElement>(null);
  const viewer = useRef<ViewerHandle>(null);
  const lastSent = useRef<string | null>(null);

  const runProbe = useCallback(async () => {
    setProbing(true);
    setProbeError(null);
    try {
      const p = await api.desktopProbe(tab.id);
      setProbe(p);
      const preferred = p.offers.findIndex((o) => o.method === profile?.rdMethod);
      setChoice(preferred >= 0 ? preferred : 0);
      setXsession((cur) => cur ?? p.sessions[0]?.id ?? null);
    } catch (e) {
      setProbeError(errorMessage(e, "The remote computer couldn't be checked."));
    } finally {
      setProbing(false);
    }
  }, [tab.id, profile?.rdMethod]);

  useEffect(() => {
    if (visible && connected && !probe && !probing && !probeError) void runProbe();
  }, [visible, connected, probe, probing, probeError, runProbe]);

  const open = (offer: DesktopOffer, request?: DesktopOpenRequest) => {
    setError(null);
    setRemoteClip(null);
    setState({ state: "connecting", step: "connecting" });
    setActive({ offer, request: request ?? requestFor(offer, area.current, xsession, profile?.rdUser ?? null, settings.quality) });
    setGen((g) => g + 1);
  };

  const onState = useCallback(
    (s: DesktopState) => {
      setState(s);
      if (s.state !== "closed") return;
      if (s.error?.code === "disconnected") {
        setWaiting(true); // reopened when the SSH connection is back
        return;
      }
      setActive((cur) => {
        if (cur && s.error) setError({ error: s.error, retry: cur });
        return null;
      });
      if (fullscreen) void getCurrentWindow().setFullscreen(false);
      setFullscreen(false);
      setProbe(null); // what's available may have changed
    },
    [fullscreen],
  );

  useEffect(() => {
    if (waiting && connected && active) {
      setWaiting(false);
      setState({ state: "connecting", step: "connecting" });
      setGen((g) => g + 1);
    }
  }, [waiting, connected, active]);

  const disconnect = () => {
    setActive(null);
    setState(null);
    setWaiting(false);
    if (fullscreen) void toggleFullscreen();
    setProbe(null);
  };

  const toggleFullscreen = useCallback(async () => {
    const next = !fullscreen;
    await getCurrentWindow()
      .setFullscreen(next)
      .catch(() => undefined);
    setFullscreen(next);
    setTimeout(() => viewer.current?.focus(), 50);
  }, [fullscreen]);

  // Ctrl+Alt+Enter toggles full screen while the desktop is shown.
  useEffect(() => {
    if (!visible || !active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Enter" && e.ctrlKey && e.altKey && !e.shiftKey && !e.metaKey) {
        e.preventDefault();
        e.stopPropagation();
        void toggleFullscreen();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [visible, active, toggleFullscreen]);

  // Files dropped on the desktop are uploaded to the remote upload folder.
  useEffect(() => {
    if (!active) return;
    const off = getCurrentWebview().onDragDropEvent(async (e) => {
      if (e.payload.type !== "drop") return;
      const scale = window.devicePixelRatio || 1;
      const el = document.elementFromPoint(e.payload.position.x / scale, e.payload.position.y / scale);
      if (el?.closest("[data-desktop-drop]")?.getAttribute("data-desktop-drop") !== tab.id) return;
      const home = await api.remoteHome(tab.id).catch(() => null);
      if (!home) return;
      const sub = useSettings.getState().settings.remoteDesktop.uploadDir;
      const target = sub ? `${home.replace(/\/$/, "")}/${sub}` : home;
      const dir = await api.listRemote(tab.id, target).then(
        () => target,
        () => home,
      );
      void api.enqueueUpload(tab.id, e.payload.paths, dir).catch(() => undefined);
    });
    return () => void off.then((f) => f());
  }, [active, tab.id]);

  const onClipboard = useCallback((text: string) => {
    if (text.length > MAX_CLIPBOARD) return;
    if (useSettings.getState().settings.remoteDesktop.clipboardSync) void api.copyText(text).catch(() => undefined);
    else setRemoteClip(text);
  }, []);

  const sendClipboard = async () => {
    const text = await api.pasteText().catch(() => "");
    if (text && text.length <= MAX_CLIPBOARD) {
      viewer.current?.paste(text);
      lastSent.current = text;
    }
    viewer.current?.focus();
  };

  // With automatic sharing, the local clipboard follows the user into the desktop.
  const onFocusDesktop = () => {
    if (!settings.clipboardSync) return;
    void api.pasteText().then(
      (text) => {
        if (text && text !== lastSent.current && text.length <= MAX_CLIPBOARD) {
          lastSent.current = text;
          viewer.current?.paste(text);
        }
      },
      () => undefined,
    );
  };

  const latencyMs = state?.state === "connected" ? state.latencyMs : undefined;
  const effectiveQuality = settings.quality === "auto" ? autoQuality(latencyMs) : settings.quality;
  const patch = (p: Partial<typeof settings>) => void saveSettings({ remoteDesktop: { ...settings, ...p } });
  const virtualOffer = probe?.offers.find((o) => o.method === "virtual");
  const selected = probe?.offers[choice];

  if (!connected && !active) {
    return (
      <div className="grid h-full place-items-center p-6 text-center text-muted">
        <p>Remote Desktop is available while you're connected.</p>
      </div>
    );
  }

  if (active) {
    const viewerProps = {
      session: tab.id,
      request: active.request,
      scale: settings.scale,
      quality: effectiveQuality,
      onState,
      onClipboard,
      onStats: setRate,
    };
    const stepText = state?.state === "connecting" ? STEPS[state.step] : null;
    return (
      <div className={fullscreen ? "fixed inset-0 z-40 flex flex-col bg-black" : "flex h-full flex-col"}>
        <div className={fullscreen ? "group absolute inset-x-0 top-0 z-10 h-2 hover:h-auto focus-within:h-auto" : ""}>
          <div className={fullscreen ? "-translate-y-full transition-transform group-hover:translate-y-0 group-focus-within:translate-y-0" : ""}>
            <Toolbar
              title={active.offer.title}
              protocol={state?.state === "connected" ? state.protocol : undefined}
              latencyMs={latencyMs}
              bytesPerSec={rate}
              scale={settings.scale}
              canResizeRemote={active.offer.method === "virtual" || active.offer.method === "rdp"}
              onScale={(scale) => patch({ scale })}
              quality={settings.quality}
              effectiveQuality={effectiveQuality}
              onQuality={(quality) => patch({ quality })}
              clipboardSync={settings.clipboardSync}
              onClipboardSync={(clipboardSync) => patch({ clipboardSync })}
              remoteClipboard={remoteClip !== null}
              onSendClipboard={() => void sendClipboard()}
              onCopyRemote={() => remoteClip !== null && void api.copyText(remoteClip)}
              onKeys={(keys: SpecialKey[]) => {
                viewer.current?.sendKeys(keys);
                viewer.current?.focus();
              }}
              onFiles={() => {
                if (fullscreen) void toggleFullscreen();
                setView(tab.id, "files");
              }}
              fullscreen={fullscreen}
              onFullscreen={() => void toggleFullscreen()}
              onDisconnect={disconnect}
              onEndVirtual={active.offer.method === "virtual" ? () => setEndConfirm(true) : undefined}
            />
          </div>
        </div>
        <div ref={area} className="relative min-h-0 flex-1 bg-black" data-desktop-drop={tab.id} data-terminal onFocusCapture={onFocusDesktop}>
          {!waiting &&
            (active.request.method === "rdp" ? (
              <RdpViewer key={gen} ref={viewer} {...viewerProps} />
            ) : (
              <VncViewer key={gen} ref={viewer} {...viewerProps} />
            ))}
          {(stepText || waiting) && (
            <div className="absolute inset-0 grid place-items-center bg-ink/80" role="status">
              <div className="flex flex-col items-center gap-3 text-muted">
                <LoaderCircle size={22} className="animate-spin text-accent" aria-hidden />
                <p>{waiting ? "The SSH connection was lost. The desktop reopens when it's back…" : stepText}</p>
                <Button variant="ghost" onClick={disconnect}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
        <ConfirmDialog
          open={endConfirm}
          onOpenChange={setEndConfirm}
          title="Sign out of the virtual desktop?"
          description="The virtual desktop and every program running in it will be closed. Unsaved work is lost."
          confirmLabel="Sign out"
          onConfirm={async () => {
            disconnect();
            await api.desktopEndVirtual(tab.id).catch(() => undefined);
          }}
        />
      </div>
    );
  }

  return (
    <div ref={area} className="h-full overflow-auto">
      <div className="mx-auto flex max-w-3xl flex-col gap-5 p-6">
        <header className="flex items-center gap-3">
          <div>
            <h2 className="text-base font-semibold">Remote Desktop</h2>
            <p className="text-muted">
              {probe?.osName ?? "See and control this computer's desktop."} {probe?.jetson && "· NVIDIA Jetson"}
            </p>
          </div>
          <Button className="ml-auto" onClick={() => void runProbe()} disabled={probing}>
            <RefreshCw size={14} className={probing ? "animate-spin" : ""} /> Check again
          </Button>
        </header>

        {error && <ErrorPanel error={error.error} onRetry={() => open(error.retry.offer, error.retry.request)} onVirtual={virtualOffer ? () => open(virtualOffer) : undefined} />}
        {probeError && (
          <p role="alert" className="rounded-panel border border-bad/40 bg-bad-soft p-4">
            {probeError}
          </p>
        )}
        {probing && !probe && (
          <p className="flex items-center gap-2 text-muted" role="status">
            <LoaderCircle size={15} className="animate-spin" /> Checking how this computer can share its desktop…
          </p>
        )}

        {probe && probe.offers.length > 0 && (
          <section className="flex flex-col gap-2">
            <div role="radiogroup" aria-label="How to open the desktop" className="flex flex-col gap-2">
              {probe.offers.map((o, i) => {
                const Icon = ICONS[o.method];
                const on = i === choice;
                return (
                  <button
                    key={`${o.method}-${o.port}-${o.display}-${o.wayland}`}
                    type="button"
                    role="radio"
                    aria-checked={on}
                    onClick={() => setChoice(i)}
                    onDoubleClick={() => open(o)}
                    className={`flex items-start gap-3 rounded-panel border p-3 text-left transition-colors ${on ? "border-accent bg-accent-soft" : "border-line bg-raised hover:border-line-strong"}`}
                  >
                    <Icon size={18} className={`mt-0.5 shrink-0 ${on ? "text-accent" : "text-muted"}`} aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2 font-medium">
                        {o.title}
                        {o.recommended && <span className="rounded-chip bg-accent-soft px-1.5 text-xs text-accent">Recommended</span>}
                        {o.running && <span className="rounded-chip bg-ok-soft px-1.5 text-xs text-ok">Running</span>}
                      </span>
                      <span className="mt-0.5 block text-muted">{o.detail}</span>
                    </span>
                  </button>
                );
              })}
            </div>
            {selected?.method === "virtual" && !selected.running && probe.sessions.length > 1 && (
              <label className="flex items-center gap-3">
                <span className="text-muted">Desktop environment</span>
                <select value={xsession ?? ""} onChange={(e) => setXsession(e.target.value)} className={`${inputClass} w-auto`}>
                  {probe.sessions.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <div className="flex items-center gap-3">
              <Button variant="primary" onClick={() => selected && open(selected)} disabled={!selected}>
                Connect
              </Button>
              <span className="text-xs text-faint">Everything travels through this SSH connection.</span>
            </div>
          </section>
        )}

        {probe && probe.setups.length > 0 && (
          <section className="flex flex-col gap-2">
            <h3 className="font-semibold">{probe.offers.length ? "More options" : "Set up remote desktop"}</h3>
            {probe.setups.map((s) => (
              <div key={s.recipe} className="flex items-start gap-3 rounded-panel border border-line bg-raised p-3">
                <Wrench size={16} className="mt-0.5 shrink-0 text-muted" aria-hidden />
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{s.title}</p>
                  <p className="mt-0.5 text-muted">{s.detail}</p>
                </div>
                <Button onClick={() => setSetup(s)}>Set up…</Button>
              </div>
            ))}
          </section>
        )}

        {probe?.notes.map((n) => (
          <p key={n} className="flex gap-2 rounded-panel border border-line p-3 text-muted">
            <Info size={15} className="mt-0.5 shrink-0" aria-hidden />
            <span>{n}</span>
          </p>
        ))}

        {probe && !probe.offers.length && !probe.setups.length && !probe.notes.length && (
          <p className="text-muted">Simple Connect couldn't find a way to show this computer's desktop.</p>
        )}
      </div>

      <ConfirmDialog
        open={setup !== null}
        onOpenChange={(o) => !o && setSetup(null)}
        title={setup?.title}
        variant="primary"
        confirmLabel="Run in a new terminal"
        description={
          setup && (
            <>
              {setup.detail} These commands will run on {tab.label}:
              <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap rounded-control bg-ink p-2 font-mono text-xs text-text" data-selectable>
                {setup.commands.join("\n")}
              </pre>
              <span className="mt-2 block">You'll see them run, and sudo may ask for your password.</span>
            </>
          )
        }
        onConfirm={() => {
          if (setup) addTerminal(tab.id, { id: setup.recipe, title: setup.title });
          setProbe(null);
        }}
      />
    </div>
  );
}
