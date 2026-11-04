import { lazy, Suspense, useRef } from "react";
import { FolderTree, Info, Monitor, Network, SquareTerminal } from "lucide-react";
import { useSessions, type SessionTab, type SubView } from "../stores/sessions";
import { useConnections } from "../stores/connections";
import { TerminalPane } from "../terminal/TerminalPane";
import { FileManager } from "../file-manager/FileManager";
import { TunnelManager } from "../tunnels/TunnelManager";
import { SessionInfo } from "../security/SessionInfo";

// noVNC and the viewers load on first use.
const RemoteDesktop = lazy(() => import("../desktop/RemoteDesktop").then((m) => ({ default: m.RemoteDesktop })));
import { describeStatus } from "../stores/sessions";

const VIEWS: { id: SubView; label: string; icon: typeof Info }[] = [
  { id: "terminal", label: "Terminal", icon: SquareTerminal },
  { id: "files", label: "Files", icon: FolderTree },
  { id: "desktop", label: "Remote Desktop", icon: Monitor },
  { id: "tunnels", label: "Tunnels", icon: Network },
  { id: "info", label: "Connection", icon: Info },
];

/**
 * One connection. Subviews share the session's single SSH connection; they stay
 * mounted while hidden so terminals and file panes keep their state.
 */
export function SessionView({ tab, visible }: { tab: SessionTab; visible: boolean }) {
  const setView = useSessions((s) => s.setView);
  const startDir = useConnections((s) => s.profiles.find((p) => p.id === tab.profileId)?.startDir ?? null);
  const connected = tab.status.state === "connected";
  const everConnected = tab.everConnected;
  // Keep the file manager mounted once opened, so its folders survive view switches.
  const filesVisited = useRef(false);
  if (tab.view === "files") filesVisited.current = true;
  // Likewise the remote desktop keeps running while other views are shown.
  const desktopVisited = useRef(false);
  if (tab.view === "desktop") desktopVisited.current = true;

  return (
    <div className="flex h-full flex-col" hidden={!visible}>
      <nav aria-label={`${tab.label} views`} className="flex h-10 shrink-0 items-center gap-1 border-b border-line px-2">
        {VIEWS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            aria-current={tab.view === id ? "page" : undefined}
            onClick={() => setView(tab.id, id)}
            className="flex h-7 items-center gap-1.5 rounded-control px-2.5 text-muted hover:bg-hover hover:text-text aria-[current=page]:bg-raised aria-[current=page]:text-text"
          >
            <Icon size={14} aria-hidden />
            {label}
          </button>
        ))}
        {!connected && <span className="ml-auto pr-2 text-xs text-muted">{describeStatus(tab.status)}</span>}
      </nav>
      <div className="relative min-h-0 flex-1">
        {!everConnected ? (
          <div className="h-full overflow-auto">
            <SessionInfo tab={tab} />
          </div>
        ) : (
          <>
            <div className="absolute inset-0" hidden={tab.view !== "terminal"}>
              <TerminalPane tab={tab} visible={visible && tab.view === "terminal"} />
            </div>
            <div className="absolute inset-0" hidden={tab.view !== "files"}>
              {filesVisited.current &&
                (connected ? (
                  <FileManager session={tab.id} startDir={startDir} />
                ) : (
                  <div className="h-full overflow-auto">
                    <SessionInfo tab={tab} />
                  </div>
                ))}
            </div>
            <div className="absolute inset-0" hidden={tab.view !== "desktop"}>
              {desktopVisited.current && (
                <Suspense fallback={null}>
                  <RemoteDesktop tab={tab} visible={visible && tab.view === "desktop"} />
                </Suspense>
              )}
            </div>
            {tab.view === "tunnels" && (
              <div className="h-full overflow-auto">
                <TunnelManager tab={tab} />
              </div>
            )}
            {tab.view === "info" && (
              <div className="h-full overflow-auto">
                <SessionInfo tab={tab} />
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
