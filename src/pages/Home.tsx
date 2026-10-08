import { useEffect, useState } from "react";
import { Radar, TerminalSquare } from "lucide-react";
import { useUi } from "../stores/ui";
import { api } from "../services/ipc";
import type { CmdError, QuickConnect } from "../types/ipc";
import { Button } from "../components/ui/Button";
import { profileDestination, RoutePreview } from "../connections/RoutePreview";
import { useConnections } from "../stores/connections";
import { useSessions } from "../stores/sessions";
import { ProfileIcon } from "../connections/appearance";
import { Kbd } from "../components/ui/Kbd";
import { SHORTCUTS } from "../shortcuts";

/** Parses quick-connect input in the backend (the single source of validation). */
export function useParsedDestination(input: string) {
  const [state, setState] = useState<{ parsed?: QuickConnect; error?: CmdError }>({});
  useEffect(() => {
    if (!input.trim()) return setState({});
    let live = true;
    const t = setTimeout(() => {
      api.parseQuickConnect(input).then(
        (parsed) => live && setState({ parsed }),
        (error: CmdError) => live && setState({ error }),
      );
    }, 120);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [input]);
  return state;
}

export function Home({ startupError }: { startupError: string | null }) {
  const [input, setInput] = useState("");
  const { parsed, error } = useParsedDestination(input);
  const { connect, connectError, dismissConnectError } = useSessions();
  const profiles = useConnections((s) => s.profiles);
  const setScannerOpen = useUi((s) => s.setScannerOpen);
  const recent = profiles
    .filter((p) => p.lastUsedAt)
    .sort((a, b) => (b.lastUsedAt ?? 0) - (a.lastUsedAt ?? 0))
    .slice(0, 6);
  const onConnect = (q: QuickConnect) => {
    void connect({ kind: "quick", input, dest: q });
    setInput("");
  };

  return (
    <div className="mx-auto flex w-full max-w-2xl flex-col gap-5 px-8 pb-10 pt-[14vh]">
      {startupError && (
        <div role="alert" className="rounded-panel border border-bad/40 bg-bad-soft p-4 text-text">
          <p className="font-medium">Connections are unavailable</p>
          <p className="mt-1 text-muted">{startupError}</p>
        </div>
      )}
      <h1 className="text-2xl font-semibold tracking-tight">Connect to a server</h1>
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (parsed) onConnect(parsed);
        }}
      >
        <div className="flex h-12 items-center gap-3 rounded-panel border border-line-strong bg-raised px-4 focus-within:border-accent">
          <TerminalSquare size={18} className="text-faint" aria-hidden />
          <input
            autoFocus
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            aria-label="Destination"
            aria-invalid={!!error}
            aria-describedby="qc-help"
            placeholder="user@192.168.1.100 or ssh user@example.com -p 2222"
            className="min-w-0 flex-1 bg-transparent font-mono text-sm outline-none placeholder:font-sans placeholder:text-faint"
          />
          <Button type="submit" variant="primary" disabled={!parsed || !!startupError}>
            Connect
          </Button>
        </div>
        <div id="qc-help" className="min-h-6" aria-live="polite">
          {parsed && <RoutePreview jump={parsed.jump} target={parsed} />}
          {error && <p className="text-bad">{error.message}</p>}
          {connectError && (
            <p role="alert" className="text-bad">
              {connectError}{" "}
              <button type="button" className="underline" onClick={dismissConnectError}>
                Dismiss
              </button>
            </p>
          )}
        </div>
      </form>

      <button
        type="button"
        onClick={() => setScannerOpen(true)}
        disabled={!!startupError}
        className="-mt-2 flex w-fit items-center gap-2 rounded-control px-2 py-1 text-accent hover:bg-accent-soft disabled:opacity-45"
      >
        <Radar size={15} aria-hidden /> Find devices on your network
      </button>

      {recent.length > 0 && (
        <section className="mt-4">
          <h2 className="mb-2 text-muted">Recent</h2>
          <ul className="grid grid-cols-2 gap-2">
            {recent.map((p) => (
              <li key={p.id}>
                <button
                  type="button"
                  onClick={() => void connect({ kind: "profile", profile: p })}
                  className="flex w-full items-center gap-3 rounded-panel border border-line bg-panel px-3 py-2.5 text-left transition-colors hover:border-line-strong hover:bg-hover"
                >
                  <ProfileIcon icon={p.icon} color={p.color} size={16} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate">{p.name}</span>
                    <span className="block truncate font-mono text-xs text-faint">{profileDestination(p)}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
      <p className="mt-6 flex items-center gap-2 text-xs text-faint">
        <Kbd keys={SHORTCUTS.palette.keys} /> opens commands and search from anywhere.
      </p>
    </div>
  );
}
