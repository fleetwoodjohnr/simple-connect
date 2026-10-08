import { ContextMenu } from "radix-ui";
import { Home, X } from "lucide-react";
import { describeStatus, quickToDraft, useSessions } from "../../stores/sessions";
import { useConnections } from "../../stores/connections";
import { useUi } from "../../stores/ui";
import { StatusDot } from "../StatusDot";
import { api } from "../../services/ipc";
import { ContextItem, menuContent, menuSeparator } from "../ui/Menu";

export function TabStrip() {
  const { tabs, activeId, setActive, close, setView, connect } = useSessions();
  const profiles = useConnections((s) => s.profiles);
  const setEditing = useUi((s) => s.setEditing);

  return (
    <div role="tablist" aria-label="Open connections" className="flex h-10 shrink-0 items-end gap-1 overflow-x-auto border-b border-line bg-panel px-2">
      <button
        type="button"
        role="tab"
        aria-selected={activeId === null}
        aria-label="Home"
        onClick={() => setActive(null)}
        className="mb-1 grid size-8 shrink-0 place-items-center rounded-control text-muted hover:bg-hover aria-selected:bg-ink aria-selected:text-text"
      >
        <Home size={15} />
      </button>
      {tabs.map((t) => {
        const profile = profiles.find((p) => p.id === t.profileId);
        return (
          <ContextMenu.Root key={t.id}>
            <ContextMenu.Trigger asChild>
              <div
                role="tab"
                tabIndex={0}
                aria-selected={activeId === t.id}
                title={`${t.label} — ${describeStatus(t.status)}`}
                onClick={() => setActive(t.id)}
                onKeyDown={(e) => e.key === "Enter" && setActive(t.id)}
                onAuxClick={(e) => e.button === 1 && void close(t.id)}
                className="group flex h-8 max-w-56 shrink-0 cursor-default items-center gap-2 rounded-t-control px-3 text-muted outline-none hover:bg-hover focus-visible:ring-2 focus-visible:ring-accent aria-selected:bg-ink aria-selected:text-text"
              >
                <StatusDot status={t.status} />
                <span className="truncate">{t.label}</span>
                <span className="sr-only">, {describeStatus(t.status)}</span>
                <button
                  type="button"
                  aria-label={`Close ${t.label}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    void close(t.id);
                  }}
                  className="-mr-1 grid size-5 place-items-center rounded-chip opacity-0 hover:bg-line group-hover:opacity-100 group-aria-selected:opacity-100"
                >
                  <X size={12} />
                </button>
              </div>
            </ContextMenu.Trigger>
            <ContextMenu.Portal>
              <ContextMenu.Content className={menuContent}>
                <ContextItem onSelect={() => void api.reconnect(t.id)}>Reconnect</ContextItem>
                {profile && <ContextItem onSelect={() => void connect({ kind: "profile", profile })}>Duplicate session</ContextItem>}
                <ContextItem onSelect={() => (setActive(t.id), setView(t.id, "files"))}>Open file browser</ContextItem>
                <ContextItem onSelect={() => (setActive(t.id), setView(t.id, "tunnels"))}>Open tunnel manager</ContextItem>
                {profile && <ContextItem onSelect={() => setEditing({ profile })}>Edit connection</ContextItem>}
                {!profile && t.quick && (
                  <ContextItem onSelect={() => setEditing({ initial: quickToDraft(t), linkSession: t.id })}>Save as connection…</ContextItem>
                )}
                <ContextMenu.Separator className={menuSeparator} />
                <ContextItem danger onSelect={() => void close(t.id)}>
                  Disconnect
                </ContextItem>
              </ContextMenu.Content>
            </ContextMenu.Portal>
          </ContextMenu.Root>
        );
      })}
    </div>
  );
}
