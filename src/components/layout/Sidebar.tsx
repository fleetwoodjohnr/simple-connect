import { useMemo, useState, type ReactNode } from "react";
import { ContextMenu, DropdownMenu } from "radix-ui";
import { ChevronRight, FileCode2, Folder, FolderPlus, Plus, Radar, Search, Star } from "lucide-react";
import { matchesFilter, profileToDraft, useConnections } from "../../stores/connections";
import { useUi } from "../../stores/ui";
import type { Group, Profile, SshConfigHost } from "../../types/ipc";
import type { ConnectTarget } from "../../types/session";
import { ProfileIcon } from "../../connections/appearance";
import { ContextItem, DropdownItem, menuContent, menuItem, menuSeparator } from "../ui/Menu";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { PromptDialog, type PromptRequest } from "../ui/PromptDialog";
import { IconButton } from "../ui/IconButton";
import { formatKeys, SHORTCUTS } from "../../shortcuts";

type Confirm = { title: string; description: ReactNode; confirmLabel: string; onConfirm: () => Promise<void> };

const rowClass =
  "flex h-8 w-full items-center gap-2 rounded-control px-2 text-left outline-none hover:bg-hover focus-visible:bg-hover focus-visible:outline-none";

function Row({ icon, label, detail, onOpen }: { icon: ReactNode; label: string; detail?: string; onOpen: () => void }) {
  return (
    <button
      type="button"
      className={rowClass}
      onDoubleClick={onOpen}
      onKeyDown={(e) => e.key === "Enter" && onOpen()}
      title={detail ? `${label} — ${detail}` : label}
    >
      {icon}
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {detail && <span className="max-w-[45%] truncate font-mono text-xs text-faint">{detail}</span>}
    </button>
  );
}

function SectionHeader({
  label,
  icon,
  open,
  onToggle,
  menu,
}: {
  label: string;
  icon: ReactNode;
  open: boolean;
  onToggle: () => void;
  menu?: ReactNode;
}) {
  const header = (
    <button type="button" aria-expanded={open} onClick={onToggle} className={`${rowClass} text-muted`}>
      <ChevronRight size={13} className={`shrink-0 transition-transform ${open ? "rotate-90" : ""}`} aria-hidden />
      {icon}
      <span className="flex-1 truncate font-medium">{label}</span>
    </button>
  );
  if (!menu) return header;
  return (
    <ContextMenu.Root>
      <ContextMenu.Trigger asChild>{header}</ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content className={menuContent}>{menu}</ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );
}

export function Sidebar({ onConnect }: { onConnect: (t: ConnectTarget) => void }) {
  const { profiles, groups, sshConfigHosts, setFavorite, move, remove, createGroup, renameGroup, deleteGroup } = useConnections();
  const setEditing = useUi((s) => s.setEditing);
  const setScannerOpen = useUi((s) => s.setScannerOpen);
  const [filter, setFilter] = useState("");
  const [closed, setClosed] = useState<Record<string, boolean>>({ "ssh-config": true });
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [prompt, setPrompt] = useState<PromptRequest | null>(null);
  const toggle = (key: string) => setClosed((c) => ({ ...c, [key]: !c[key] }));

  const newFolder = () =>
    setPrompt({ title: "New folder", label: "Folder name", submitLabel: "Create folder", onSubmit: async (name) => void (await createGroup(name)) });

  const profileRow = (p: Profile) => (
    <ContextMenu.Root key={p.id}>
      <ContextMenu.Trigger asChild>
        <div>
          <Row
            icon={<ProfileIcon icon={p.icon} color={p.color} />}
            label={p.name}
            detail={p.host}
            onOpen={() => onConnect({ kind: "profile", profile: p })}
          />
        </div>
      </ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content className={menuContent}>
          <ContextItem onSelect={() => onConnect({ kind: "profile", profile: p })}>Connect</ContextItem>
          <ContextItem onSelect={() => setEditing({ profile: p })}>Edit connection</ContextItem>
          <ContextItem onSelect={() => setEditing({ initial: { ...profileToDraft(p), name: `${p.name} copy` } })}>Duplicate</ContextItem>
          <ContextItem onSelect={() => void setFavorite(p.id, !p.favorite)}>
            {p.favorite ? "Remove from favorites" : "Add to favorites"}
          </ContextItem>
          {groups.length > 0 && (
            <ContextMenu.Sub>
              <ContextMenu.SubTrigger className={menuItem}>
                Move to folder
                <ChevronRight size={13} className="ml-auto" aria-hidden />
              </ContextMenu.SubTrigger>
              <ContextMenu.Portal>
                <ContextMenu.SubContent className={menuContent}>
                  <ContextItem onSelect={() => void move(p.id, null)}>No folder</ContextItem>
                  {groups.map((g) => (
                    <ContextItem key={g.id} onSelect={() => void move(p.id, g.id)}>
                      {g.name}
                    </ContextItem>
                  ))}
                </ContextMenu.SubContent>
              </ContextMenu.Portal>
            </ContextMenu.Sub>
          )}
          <ContextMenu.Separator className={menuSeparator} />
          <ContextItem
            danger
            onSelect={() =>
              setConfirm({
                title: `Delete “${p.name}”?`,
                description: "The saved connection and any password saved for it are removed. Trusted host keys are kept.",
                confirmLabel: "Delete connection",
                onConfirm: () => remove(p.id),
              })
            }
          >
            Delete connection
          </ContextItem>
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );

  const aliasRow = (h: SshConfigHost) => (
    <ContextMenu.Root key={`alias-${h.alias}`}>
      <ContextMenu.Trigger asChild>
        <div>
          <Row
            icon={<FileCode2 size={15} className="shrink-0 text-faint" aria-hidden />}
            label={h.alias}
            detail={h.hostName ?? undefined}
            onOpen={() => onConnect({ kind: "alias", host: h })}
          />
        </div>
      </ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content className={menuContent}>
          <ContextItem onSelect={() => onConnect({ kind: "alias", host: h })}>Connect</ContextItem>
          <ContextItem
            onSelect={() =>
              setEditing({
                initial: {
                  name: h.alias,
                  host: h.hostName ?? h.alias,
                  port: h.port,
                  username: h.user,
                  identityFile: h.identityFile,
                  jump: h.proxyJump,
                },
              })
            }
          >
            Save as connection
          </ContextItem>
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );

  const groupMenu = (g: Group) => (
    <>
      <ContextItem
        onSelect={() =>
          setPrompt({ title: "Rename folder", label: "Folder name", initial: g.name, submitLabel: "Rename", onSubmit: (name) => renameGroup(g.id, name) })
        }
      >
        Rename folder
      </ContextItem>
      <ContextItem
        danger
        onSelect={() =>
          setConfirm({
            title: `Delete folder “${g.name}”?`,
            description: "Connections in this folder are kept and moved out of it.",
            confirmLabel: "Delete folder",
            onConfirm: () => deleteGroup(g.id),
          })
        }
      >
        Delete folder
      </ContextItem>
    </>
  );

  const filtered = useMemo(() => profiles.filter((p) => matchesFilter(p, filter)), [profiles, filter]);
  const allTags = useMemo(() => {
    const seen = new Map<string, string>();
    profiles.flatMap((p) => p.tags).forEach((t) => seen.set(t.toLowerCase(), seen.get(t.toLowerCase()) ?? t));
    return [...seen.values()].sort((a, b) => a.localeCompare(b)).slice(0, 16);
  }, [profiles]);
  const favorites = profiles.filter((p) => p.favorite);
  const ungrouped = profiles.filter((p) => !p.groupId);
  const empty = profiles.length === 0 && sshConfigHosts.length === 0;

  return (
    <nav aria-label="Connections" className="flex w-64 shrink-0 flex-col border-r border-line bg-panel">
      <div className="flex h-10 items-center pl-3 pr-1.5">
        <span className="flex-1 font-medium text-muted">Connections</span>
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <IconButton label="Add">
              <Plus size={16} aria-hidden />
            </IconButton>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content align="end" className={menuContent}>
              <DropdownItem onSelect={() => setEditing({})}>
                <Plus size={14} aria-hidden /> New connection
                <span className="ml-auto text-xs text-faint">{formatKeys(SHORTCUTS.newConnection.keys)}</span>
              </DropdownItem>
              <DropdownItem onSelect={newFolder}>
                <FolderPlus size={14} aria-hidden /> New folder
              </DropdownItem>
              <DropdownItem onSelect={() => setScannerOpen(true)}>
                <Radar size={14} aria-hidden /> Find devices on network
              </DropdownItem>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
      <label className="mx-3 mb-2 flex h-8 items-center gap-2 rounded-control border border-line bg-ink px-2 text-muted focus-within:border-accent">
        <Search size={14} aria-hidden />
        <input
          id="connection-filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={(e) => e.key === "Escape" && setFilter("")}
          placeholder="Filter by name, address or #tag"
          aria-label="Filter connections"
          className="min-w-0 flex-1 bg-transparent text-text outline-none placeholder:text-faint"
        />
      </label>
      {allTags.length > 0 && (
        <div className="mx-3 mb-2 flex flex-wrap gap-1" aria-label="Filter by tag">
          {allTags.map((t) => {
            const active = filter.trim().toLowerCase() === `#${t.toLowerCase()}`;
            return (
              <button
                key={t}
                type="button"
                aria-pressed={active}
                onClick={() => setFilter(active ? "" : `#${t}`)}
                className="rounded-chip border border-line px-1.5 py-px text-xs text-muted hover:text-text aria-pressed:border-accent aria-pressed:bg-accent-soft aria-pressed:text-text"
              >
                {t}
              </button>
            );
          })}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto px-1.5 pb-3">
        {empty && (
          <div className="px-2 py-6 text-muted">
            <p>Save the servers you use often to connect in one step.</p>
            <button type="button" onClick={() => setEditing({})} className="mt-2 text-accent hover:underline">
              Add a connection
            </button>
          </div>
        )}

        {filter.trim() ? (
          <>
            {filtered.map(profileRow)}
            {sshConfigHosts.filter((h) => h.alias.toLowerCase().includes(filter.trim().toLowerCase())).map(aliasRow)}
            {filtered.length === 0 && <p className="px-2 py-4 text-muted">No connections match “{filter}”.</p>}
          </>
        ) : (
          <>
            {favorites.length > 0 && (
              <>
                <SectionHeader
                  label="Favorites"
                  icon={<Star size={14} aria-hidden />}
                  open={!closed.favorites}
                  onToggle={() => toggle("favorites")}
                />
                {!closed.favorites && <div className="pl-3">{favorites.map(profileRow)}</div>}
              </>
            )}
            {groups.map((g) => {
              const members = profiles.filter((p) => p.groupId === g.id);
              return (
                <div key={g.id}>
                  <SectionHeader
                    label={g.name}
                    icon={<Folder size={14} aria-hidden />}
                    open={!closed[g.id]}
                    onToggle={() => toggle(g.id)}
                    menu={groupMenu(g)}
                  />
                  {!closed[g.id] && (
                    <div className="pl-3">
                      {members.map(profileRow)}
                      {members.length === 0 && <p className="px-2 py-1 text-xs text-faint">Empty folder</p>}
                    </div>
                  )}
                </div>
              );
            })}
            {ungrouped.map(profileRow)}
            {sshConfigHosts.length > 0 && (
              <>
                <SectionHeader
                  label="From ~/.ssh/config"
                  icon={<FileCode2 size={14} aria-hidden />}
                  open={!closed["ssh-config"]}
                  onToggle={() => toggle("ssh-config")}
                />
                {!closed["ssh-config"] && <div className="pl-3">{sshConfigHosts.map(aliasRow)}</div>}
              </>
            )}
          </>
        )}
      </div>

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={confirm?.title}
        description={confirm?.description}
        confirmLabel={confirm?.confirmLabel ?? ""}
        onConfirm={() => confirm?.onConfirm()}
      />
      <PromptDialog request={prompt} onClose={() => setPrompt(null)} />
    </nav>
  );
}

