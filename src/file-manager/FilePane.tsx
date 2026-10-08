import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent, type KeyboardEvent } from "react";
import { ContextMenu } from "radix-ui";
import { AlertTriangle, ArrowUp, Eye, EyeOff, File, Folder, FolderPlus, Link2, RefreshCw, Search } from "lucide-react";
import type { Entry } from "../types/ipc";
import { errorMessage } from "../services/ipc";
import { displayName, formatBytes, formatMode, formatTime, joinPath, parentPath, sortEntries, type SortKey } from "./format";
import { IconButton } from "../components/ui/IconButton";
import { ContextItem, menuContent, menuSeparator } from "../components/ui/Menu";
import { inputClass } from "../components/ui/Field";

export interface FsAdapter {
  side: "local" | "remote";
  list: (path: string) => Promise<Entry[]>;
}

/** What one pane can do with its items; handled by the FileManager. */
export interface PaneActions {
  open: (path: string, entry: Entry) => void;
  transfer: (paths: string[]) => void;
  transferLabel: string;
  newFolder: (dir: string) => void;
  rename: (path: string, entry: Entry) => void;
  remove: (paths: string[]) => void;
  copyPath: (path: string) => void;
  duplicate?: (path: string, entry: Entry) => void;
  permissions?: (path: string, entry: Entry) => void;
  edit?: (path: string, entry: Entry) => void;
  /** Items dragged from the other pane (or the OS) were dropped here. */
  dropped: (data: DataTransfer) => void;
}

export const DRAG_TYPE = { local: "application/x-sc-local", remote: "application/x-sc-remote" } as const;

export function FilePane({
  title,
  adapter,
  path,
  setPath,
  actions,
  showHidden,
  setShowHidden,
  refreshKey,
}: {
  title: string;
  adapter: FsAdapter;
  path: string;
  setPath: (p: string) => void;
  actions: PaneActions;
  showHidden: boolean;
  setShowHidden: (v: boolean) => void;
  refreshKey: number;
}) {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [anchor, setAnchor] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; asc: boolean }>({ key: "name", asc: true });
  const [pathInput, setPathInput] = useState(path);
  const [dropping, setDropping] = useState(false);
  const rowRefs = useRef(new Map<string, HTMLTableRowElement>());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setEntries(await adapter.list(path));
      setError(null);
    } catch (e) {
      setError(errorMessage(e, "This folder couldn't be opened."));
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, [adapter, path]);

  useEffect(() => {
    setSelected(new Set());
    setPathInput(path);
    void load();
  }, [load, path, refreshKey]);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = entries.filter((e) => (showHidden || !e.name.startsWith(".")) && (!q || e.name.toLowerCase().includes(q)));
    return sortEntries(list, sort.key, sort.asc);
  }, [entries, filter, showHidden, sort]);

  const isDir = (e: Entry) => e.kind === "dir" || e.targetIsDir;
  const full = (name: string) => joinPath(path, name);
  const selectedPaths = () => [...selected].map(full);

  const activate = (e: Entry) => (isDir(e) ? setPath(full(e.name)) : actions.open(full(e.name), e));

  const click = (e: Entry, ev: React.MouseEvent) => {
    if (ev.shiftKey && anchor) {
      const names = visible.map((v) => v.name);
      const [a, b] = [names.indexOf(anchor), names.indexOf(e.name)].sort((x, y) => x - y);
      setSelected(new Set(names.slice(a, b + 1)));
    } else if (ev.ctrlKey || ev.metaKey) {
      const next = new Set(selected);
      if (next.has(e.name)) next.delete(e.name);
      else next.add(e.name);
      setSelected(next);
      setAnchor(e.name);
    } else {
      setSelected(new Set([e.name]));
      setAnchor(e.name);
    }
  };

  const keyDown = (ev: KeyboardEvent, e: Entry) => {
    const i = visible.findIndex((v) => v.name === e.name);
    const focus = (j: number) => {
      const target = visible[Math.max(0, Math.min(visible.length - 1, j))];
      if (!target) return;
      rowRefs.current.get(target.name)?.focus();
      if (!ev.shiftKey) setSelected(new Set([target.name]));
      setAnchor(target.name);
    };
    if (ev.key === "ArrowDown") focus(i + 1);
    else if (ev.key === "ArrowUp") focus(i - 1);
    else if (ev.key === "Enter") activate(e);
    else if (ev.key === "Backspace") setPath(parentPath(path));
    else if (ev.key === "Delete") actions.remove(selected.size ? selectedPaths() : [full(e.name)]);
    else if (ev.key === "F2") actions.rename(full(e.name), e);
    else if (ev.key === "a" && (ev.ctrlKey || ev.metaKey)) setSelected(new Set(visible.map((v) => v.name)));
    else return;
    ev.preventDefault();
  };

  const dragStart = (ev: DragEvent, e: Entry) => {
    const names = selected.has(e.name) ? [...selected] : [e.name];
    ev.dataTransfer.setData(DRAG_TYPE[adapter.side], JSON.stringify(names.map(full)));
    ev.dataTransfer.effectAllowed = "copy";
  };
  const other = DRAG_TYPE[adapter.side === "local" ? "remote" : "local"];
  const accepts = (ev: DragEvent) => ev.dataTransfer.types.includes(other);

  const header = (key: SortKey, label: string, cls: string) => (
    <th scope="col" className={`px-2 py-1.5 text-left font-medium ${cls}`} aria-sort={sort.key === key ? (sort.asc ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={() => setSort((s) => ({ key, asc: s.key === key ? !s.asc : true }))} className="hover:text-text">
        {label}
        {sort.key === key ? (sort.asc ? " ↑" : " ↓") : ""}
      </button>
    </th>
  );

  return (
    <section
      aria-label={title}
      className={`flex min-w-0 flex-1 flex-col rounded-panel border bg-panel ${dropping ? "border-accent" : "border-line"}`}
      onDragOver={(ev) => {
        if (accepts(ev)) {
          ev.preventDefault();
          setDropping(true);
        }
      }}
      onDragLeave={() => setDropping(false)}
      onDrop={(ev) => {
        setDropping(false);
        if (accepts(ev)) {
          ev.preventDefault();
          actions.dropped(ev.dataTransfer);
        }
      }}
      data-pane={adapter.side}
    >
      <div className="flex items-center gap-1 border-b border-line px-2 py-1.5">
        <span className="mr-1 font-medium">{title}</span>
        <IconButton label="Up one folder" onClick={() => setPath(parentPath(path))} className="size-7">
          <ArrowUp size={14} />
        </IconButton>
        <IconButton label="Refresh" onClick={() => void load()} className="size-7">
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
        </IconButton>
        <IconButton label="New folder" onClick={() => actions.newFolder(path)} className="size-7">
          <FolderPlus size={14} />
        </IconButton>
        <IconButton label={showHidden ? "Hide hidden files" : "Show hidden files"} onClick={() => setShowHidden(!showHidden)} className="size-7">
          {showHidden ? <EyeOff size={14} /> : <Eye size={14} />}
        </IconButton>
        <label className="ml-auto flex h-7 w-40 items-center gap-1.5 rounded-control border border-line bg-ink px-2 text-muted focus-within:border-accent">
          <Search size={12} aria-hidden />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter"
            aria-label={`Filter ${title}`}
            className="min-w-0 flex-1 bg-transparent text-text outline-none placeholder:text-faint"
          />
        </label>
      </div>
      <form
        className="border-b border-line px-2 py-1.5"
        onSubmit={(e) => {
          e.preventDefault();
          if (pathInput.trim()) setPath(pathInput.trim());
        }}
      >
        <input
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
          spellCheck={false}
          aria-label={`${title} path`}
          className={`${inputClass} h-7 font-mono text-xs`}
        />
      </form>

      <div className="min-h-0 flex-1 overflow-auto" onClick={(e) => e.target === e.currentTarget && setSelected(new Set())}>
        {error ? (
          <p className="p-4 text-bad">{error}</p>
        ) : (
          <table className="w-full table-fixed border-collapse">
            <thead className="sticky top-0 z-10 bg-panel text-xs text-muted">
              <tr>
                {header("name", "Name", "w-auto")}
                {header("size", "Size", "w-20 text-right")}
                {header("modified", "Modified", "w-40")}
                <th scope="col" className="w-28 px-2 py-1.5 text-left font-medium">
                  Permissions
                </th>
              </tr>
            </thead>
            <tbody>
              {visible.map((e) => {
                const { text, suspicious } = displayName(e.name);
                const p = full(e.name);
                return (
                  <ContextMenu.Root key={e.name}>
                    <ContextMenu.Trigger asChild>
                      <tr
                        ref={(el) => {
                          if (el) rowRefs.current.set(e.name, el);
                          else rowRefs.current.delete(e.name);
                        }}
                        tabIndex={0}
                        aria-selected={selected.has(e.name)}
                        draggable
                        onDragStart={(ev) => dragStart(ev, e)}
                        onClick={(ev) => click(e, ev)}
                        onDoubleClick={() => activate(e)}
                        onKeyDown={(ev) => keyDown(ev, e)}
                        onContextMenu={() => !selected.has(e.name) && setSelected(new Set([e.name]))}
                        className="h-7 cursor-default outline-none hover:bg-hover focus-visible:bg-hover aria-selected:bg-accent-soft"
                      >
                        <td className="truncate px-2" title={text}>
                          <span className="flex items-center gap-2">
                            {e.kind === "symlink" ? (
                              <Link2 size={14} className="shrink-0 text-faint" aria-label="Link" />
                            ) : isDir(e) ? (
                              <Folder size={14} className="shrink-0 text-accent" aria-hidden />
                            ) : (
                              <File size={14} className="shrink-0 text-faint" aria-hidden />
                            )}
                            <span className="truncate">{text}</span>
                            {suspicious && (
                              <AlertTriangle size={13} className="shrink-0 text-warn" aria-label="This name contains hidden or control characters" />
                            )}
                          </span>
                        </td>
                        <td className="px-2 text-right tabular-nums text-muted">{isDir(e) ? "" : formatBytes(e.size)}</td>
                        <td className="truncate px-2 text-muted">{formatTime(e.modified)}</td>
                        <td className="px-2 font-mono text-xs text-faint">{formatMode(e.mode, e.kind)}</td>
                      </tr>
                    </ContextMenu.Trigger>
                    <ContextMenu.Portal>
                      <ContextMenu.Content className={menuContent}>
                        <ContextItem onSelect={() => activate(e)}>Open</ContextItem>
                        {actions.edit && !isDir(e) && <ContextItem onSelect={() => actions.edit!(p, e)}>Edit</ContextItem>}
                        <ContextItem onSelect={() => actions.transfer(selected.size ? selectedPaths() : [p])}>{actions.transferLabel}</ContextItem>
                        <ContextMenu.Separator className={menuSeparator} />
                        <ContextItem onSelect={() => actions.rename(p, e)}>Rename</ContextItem>
                        {actions.duplicate && <ContextItem onSelect={() => actions.duplicate!(p, e)}>Duplicate</ContextItem>}
                        <ContextItem onSelect={() => actions.copyPath(p)}>Copy path</ContextItem>
                        {actions.permissions && <ContextItem onSelect={() => actions.permissions!(p, e)}>Permissions</ContextItem>}
                        <ContextMenu.Separator className={menuSeparator} />
                        <ContextItem danger onSelect={() => actions.remove(selected.size ? selectedPaths() : [p])}>
                          {adapter.side === "local" ? "Move to trash" : "Delete"}
                        </ContextItem>
                      </ContextMenu.Content>
                    </ContextMenu.Portal>
                  </ContextMenu.Root>
                );
              })}
            </tbody>
          </table>
        )}
        {!error && !loading && visible.length === 0 && <p className="p-4 text-muted">{filter ? "Nothing matches the filter." : "This folder is empty."}</p>}
      </div>
      <div className="border-t border-line px-3 py-1 text-xs text-faint" aria-live="polite">
        {selected.size > 0 ? `${selected.size} selected` : `${visible.length} items`}
      </div>
    </section>
  );
}
