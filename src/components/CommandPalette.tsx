import { useState, type ReactNode } from "react";
import { Command } from "cmdk";
import { open as openFile } from "@tauri-apps/plugin-dialog";
import { ArrowDownUp, FolderTree, KeyRound, Lock, Monitor, Moon, Network, Plug, Plus, Radar, Settings, Sun, Upload } from "lucide-react";
import { useUi } from "../stores/ui";
import { useConnections } from "../stores/connections";
import { useSessions } from "../stores/sessions";
import { useParsedDestination } from "../pages/Home";
import { formatDestination, profileDestination } from "../connections/RoutePreview";
import { ProfileIcon } from "../connections/appearance";
import { api } from "../services/ipc";

function Item({ icon, children, onSelect, value, hint }: { icon: ReactNode; children: ReactNode; onSelect: () => void; value?: string; hint?: string }) {
  return (
    <Command.Item
      value={value}
      onSelect={onSelect}
      className="flex h-9 cursor-default items-center gap-2.5 rounded-control px-2.5 text-text data-[selected=true]:bg-hover"
    >
      <span className="text-muted">{icon}</span>
      <span className="min-w-0 flex-1 truncate">{children}</span>
      {hint && <span className="truncate font-mono text-xs text-faint">{hint}</span>}
    </Command.Item>
  );
}

const group = "px-1 py-1 [&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-faint";

export function CommandPalette({ openSettings }: { openSettings: (page?: "General" | "SSH keys") => void }) {
  const { paletteOpen, setPaletteOpen, setTheme, toggleDrawer, setEditing, setScannerOpen } = useUi();
  const profiles = useConnections((s) => s.profiles);
  const { connect, tabs, activeId, setView } = useSessions();
  const active = tabs.find((t) => t.id === activeId);
  const [query, setQuery] = useState("");
  const { parsed } = useParsedDestination(query);

  const run = (fn: () => void) => () => {
    setPaletteOpen(false);
    setQuery("");
    fn();
  };

  return (
    <Command.Dialog
      open={paletteOpen}
      onOpenChange={setPaletteOpen}
      label="Command palette"
      overlayClassName="fixed inset-0 z-40 bg-black/40"
      contentClassName="animate-pop fixed left-1/2 top-[12vh] z-50 w-[min(600px,90vw)] -translate-x-1/2 overflow-hidden rounded-panel bg-raised shadow-pop"
    >
      <Command.Input
        value={query}
        onValueChange={setQuery}
        placeholder="Type a command, a connection, or user@host"
        className="h-12 w-full border-b border-line bg-transparent px-4 text-sm outline-none placeholder:text-faint"
      />
      <Command.List className="max-h-[55vh] overflow-y-auto p-1">
        <Command.Empty className="px-4 py-6 text-center text-muted">No matching commands.</Command.Empty>
        {parsed && (
          <Command.Group heading="Quick connect" className={group}>
            <Item value={`quick connect ${query}`} icon={<Plug size={15} />} onSelect={run(() => void connect({ kind: "quick", input: query, dest: parsed }))}>
              Connect to <span className="font-mono">{formatDestination(parsed)}</span>
            </Item>
          </Command.Group>
        )}
        {profiles.length > 0 && (
          <Command.Group heading="Connections" className={group}>
            {profiles.map((p) => (
              <Item
                key={p.id}
                value={`connect ${p.name} ${p.host} ${p.tags.join(" ")}`}
                icon={<ProfileIcon icon={p.icon} color={p.color} />}
                hint={profileDestination(p)}
                onSelect={run(() => void connect({ kind: "profile", profile: p }))}
              >
                Connect to {p.name}
              </Item>
            ))}
          </Command.Group>
        )}
        {active && (
          <Command.Group heading={active.label} className={group}>
            <Item icon={<FolderTree size={15} />} onSelect={run(() => setView(active.id, "files"))}>
              Open SFTP file browser
            </Item>
            <Item icon={<Network size={15} />} onSelect={run(() => setView(active.id, "tunnels"))}>
              Create tunnel
            </Item>
            <Item
              icon={<Upload size={15} />}
              onSelect={run(async () => {
                const picked = await openFile({ multiple: true, directory: false, title: "Upload to the server's home folder" });
                const files = Array.isArray(picked) ? picked : picked ? [picked] : [];
                if (files.length) await api.enqueueUpload(active.id, files, await api.remoteHome(active.id));
              })}
            >
              Upload file…
            </Item>
          </Command.Group>
        )}
        <Command.Group heading="Actions" className={group}>
          <Item icon={<Plus size={15} />} onSelect={run(() => setEditing({}))}>
            New connection
          </Item>
          <Item icon={<Radar size={15} />} onSelect={run(() => setScannerOpen(true))}>
            Scan local network
          </Item>
          <Item icon={<KeyRound size={15} />} onSelect={run(() => openSettings("SSH keys"))}>
            Generate SSH key
          </Item>
          <Item icon={<Lock size={15} />} onSelect={run(() => void api.lockApp())}>
            Lock application
          </Item>
          <Item icon={<Settings size={15} />} onSelect={run(() => openSettings())}>
            Open settings
          </Item>
          <Item icon={<ArrowDownUp size={15} />} onSelect={run(toggleDrawer)}>
            Show or hide transfers
          </Item>
        </Command.Group>
        <Command.Group heading="Appearance" className={group}>
          <Item icon={<Moon size={15} />} onSelect={run(() => setTheme("dark"))}>
            Use dark theme
          </Item>
          <Item icon={<Sun size={15} />} onSelect={run(() => setTheme("light"))}>
            Use light theme
          </Item>
          <Item icon={<Monitor size={15} />} onSelect={run(() => setTheme("system"))}>
            Match system theme
          </Item>
        </Command.Group>
      </Command.List>
    </Command.Dialog>
  );
}
