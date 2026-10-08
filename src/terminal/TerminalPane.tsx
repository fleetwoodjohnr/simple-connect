import { Maximize2, Plus, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { isConnected, useSessions, type SessionTab } from "../stores/sessions";
import { TerminalView } from "./TerminalView";
import { IconButton } from "../components/ui/IconButton";
import { SHORTCUTS } from "../shortcuts";

export async function toggleFullscreen() {
  const w = getCurrentWindow();
  await w.setFullscreen(!(await w.isFullscreen()));
}

/** The shells of one session, as small tabs over a shared area. */
export function TerminalPane({ tab, visible }: { tab: SessionTab; visible: boolean }) {
  const { addTerminal, removeTerminal, setActiveTerminal } = useSessions();
  const connected = isConnected(tab);
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-9 shrink-0 items-center gap-1 px-2">
        {tab.terminals.map((t) => (
          <div
            key={t.key}
            className={`group flex h-7 items-center gap-1 rounded-control pl-2.5 pr-1 ${tab.activeTerminal === t.key ? "bg-raised text-text" : "text-muted hover:bg-hover"}`}
          >
            <button type="button" onClick={() => setActiveTerminal(tab.id, t.key)} className="outline-none">
              {t.title}
            </button>
            {tab.terminals.length > 1 && (
              <button
                type="button"
                aria-label={`Close ${t.title}`}
                onClick={() => removeTerminal(tab.id, t.key)}
                className="grid size-5 place-items-center rounded-chip opacity-0 hover:bg-line group-hover:opacity-100"
              >
                <X size={12} />
              </button>
            )}
          </div>
        ))}
        <IconButton label="New terminal" shortcut={SHORTCUTS.newTerminal.keys} onClick={() => addTerminal(tab.id)} className="size-7">
          <Plus size={15} />
        </IconButton>
        {tab.cwd && <span className="ml-3 truncate font-mono text-xs text-faint" title="Remote working folder">{tab.cwd}</span>}
        <IconButton label="Full screen" onClick={() => void toggleFullscreen()} className="ml-auto size-7">
          <Maximize2 size={14} />
        </IconButton>
      </div>
      <div className="relative min-h-0 flex-1">
        {tab.terminals.map((t) => (
          <div key={t.key} className="absolute inset-0" hidden={tab.activeTerminal !== t.key}>
            <TerminalView session={tab.id} connected={connected} visible={visible && tab.activeTerminal === t.key} />
          </div>
        ))}
      </div>
    </div>
  );
}
