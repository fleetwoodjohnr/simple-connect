import { Lock, Search, Settings } from "lucide-react";
import { useUi } from "../../stores/ui";
import { IconButton } from "../ui/IconButton";
import { Kbd } from "../ui/Kbd";
import { SHORTCUTS } from "../../shortcuts";
import { api } from "../../services/ipc";

export function TopBar({ canLock }: { canLock: boolean }) {
  const { setPaletteOpen, setView } = useUi();
  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-b border-line bg-panel px-3">
      <span className="flex items-center gap-2 pr-2 font-semibold tracking-tight">
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
          <circle cx="6" cy="12" r="3" fill="var(--accent)" />
          <circle cx="18" cy="12" r="3" fill="none" stroke="var(--accent)" strokeWidth="2" />
          <path d="M9 12h6" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" />
        </svg>
        Simple Connect
      </span>
      <button
        type="button"
        onClick={() => setPaletteOpen(true)}
        className="flex h-8 w-full max-w-md items-center gap-2 rounded-control border border-line bg-ink px-2.5 text-muted transition-colors hover:border-line-strong"
      >
        <Search size={15} aria-hidden />
        <span className="flex-1 text-left">Search or connect to user@host</span>
        <Kbd keys={SHORTCUTS.palette.keys} />
      </button>
      <div className="ml-auto flex items-center gap-1">
        {canLock && (
          <IconButton label="Lock" shortcut={SHORTCUTS.lock.keys} onClick={() => void api.lockApp()}>
            <Lock size={16} aria-hidden />
          </IconButton>
        )}
        <IconButton label="Settings" shortcut={SHORTCUTS.settings.keys} onClick={() => setView("settings")}>
          <Settings size={17} aria-hidden />
        </IconButton>
      </div>
    </header>
  );
}
