import { ArrowDownUp, Lock } from "lucide-react";
import { describeStatus, useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { StatusDot } from "../StatusDot";
import { cipherName, hostKeyName, isLegacy } from "../../security/names";

export function StatusBar() {
  const { toggleDrawer, drawerOpen } = useUi();
  const tab = useSessions((s) => s.tabs.find((t) => t.id === s.activeId));
  const running = useSessions((s) => s.jobs.filter((j) => j.state === "running").length);
  const info = tab?.info;
  const secure = tab?.status.state === "connected" && info?.cipher;
  const legacy = [info?.cipher, info?.kex, info?.hostKeyAlgorithm].some(isLegacy);

  return (
    <footer className="flex h-7 shrink-0 items-center gap-3 border-t border-line bg-panel px-3 text-xs text-muted">
      <span className="flex min-w-0 items-center gap-2" role="status">
        {tab ? (
          <>
            <StatusDot status={tab.status} />
            {secure ? (
              <span className="flex items-center gap-1.5 truncate">
                <Lock size={11} className={legacy ? "text-warn" : "text-ok"} aria-hidden />
                {legacy ? "Connected (legacy algorithms)" : "Connected securely"} · {hostKeyName(info?.hostKeyAlgorithm)} · {cipherName(info?.cipher)}
              </span>
            ) : (
              <span className="truncate">{describeStatus(tab.status)}</span>
            )}
          </>
        ) : (
          <>
            <span className="size-2 rounded-full bg-faint" aria-hidden />
            No connection selected
          </>
        )}
      </span>
      <button
        type="button"
        onClick={toggleDrawer}
        aria-expanded={drawerOpen}
        className="ml-auto flex items-center gap-1.5 rounded-chip px-1.5 py-0.5 hover:bg-hover hover:text-text"
      >
        <ArrowDownUp size={13} aria-hidden />
        Transfers{running ? ` (${running})` : ""}
      </button>
    </footer>
  );
}
