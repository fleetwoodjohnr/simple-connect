import { lazy, Suspense, useEffect, useMemo, useState, type ReactNode } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { ArrowLeftRight } from "lucide-react";
import { api, errorMessage } from "../services/ipc";
import { useSettings } from "../stores/settings";
import type { Entry } from "../types/ipc";
import { DRAG_TYPE, FilePane, type FsAdapter, type PaneActions } from "./FilePane";
import { joinPath, looksLikeText, parentPath } from "./format";
import type { EditTarget } from "./Editor";
import { PermissionsDialog } from "./PermissionsDialog";
import { PromptDialog, type PromptRequest } from "../components/ui/PromptDialog";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";

// CodeMirror is only loaded when a file is first opened for editing.
const Editor = lazy(() => import("./Editor").then((m) => ({ default: m.Editor })));

type Confirm = { title: string; description: ReactNode; confirmLabel: string; onConfirm: () => Promise<void> };

const baseName = (p: string) => p.replace(/\/+$/, "").split("/").pop() ?? p;

export function FileManager({ session, startDir }: { session: string; startDir: string | null }) {
  const settings = useSettings((s) => s.settings);
  const saveSettings = useSettings((s) => s.save);
  const [localPath, setLocalPath] = useState<string | null>(null);
  const [remotePath, setRemotePath] = useState<string | null>(null);
  const [refresh, setRefresh] = useState({ local: 0, remote: 0 });
  const [prompt, setPrompt] = useState<PromptRequest | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [perms, setPerms] = useState<{ path: string; mode: number } | null>(null);
  const [edit, setEdit] = useState<EditTarget | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.localHome().then(setLocalPath, () => setLocalPath("/"));
    api.remoteHome(session).then(
      (home) => setRemotePath(startDir ?? home),
      (e) => setError(errorMessage(e, "The file browser couldn't start.")),
    );
  }, [session, startDir]);

  const bump = (side: "local" | "remote") => setRefresh((r) => ({ ...r, [side]: r[side] + 1 }));
  const run = async (side: "local" | "remote", op: () => Promise<unknown>) => {
    try {
      await op();
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      bump(side);
    }
  };

  const local: FsAdapter = useMemo(() => ({ side: "local", list: api.listLocal }), []);
  const remote: FsAdapter = useMemo(() => ({ side: "remote", list: (p) => api.listRemote(session, p) }), [session]);

  const upload = (paths: string[]) => remotePath && run("remote", () => api.enqueueUpload(session, paths, remotePath));
  const download = (paths: string[]) => localPath && run("local", () => api.enqueueDownload(session, paths, localPath));

  // Files dropped from the desktop onto the remote pane are uploaded.
  useEffect(() => {
    const off = getCurrentWebview().onDragDropEvent((e) => {
      if (e.payload.type !== "drop" || !remotePath) return;
      const scale = window.devicePixelRatio || 1;
      const el = document.elementFromPoint(e.payload.position.x / scale, e.payload.position.y / scale);
      if (el?.closest('[data-pane="remote"]')) void upload(e.payload.paths);
    });
    return () => void off.then((f) => f());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [remotePath, session]);

  const rename = (side: "local" | "remote") => (path: string) =>
    setPrompt({
      title: "Rename",
      label: "New name",
      initial: baseName(path),
      submitLabel: "Rename",
      onSubmit: async (name) => {
        const to = joinPath(parentPath(path), name);
        await (side === "local" ? api.localRename(path, to) : api.remoteRename(session, path, to));
        bump(side);
      },
    });

  const newFolder = (side: "local" | "remote") => (dir: string) =>
    setPrompt({
      title: "New folder",
      label: "Folder name",
      submitLabel: "Create folder",
      onSubmit: async (name) => {
        const p = joinPath(dir, name);
        await (side === "local" ? api.localMkdir(p) : api.remoteMkdir(session, p));
        bump(side);
      },
    });

  const remove = (side: "local" | "remote") => (paths: string[]) =>
    setConfirm(
      side === "local"
        ? {
            title: paths.length === 1 ? `Move “${baseName(paths[0])}” to the trash?` : `Move ${paths.length} items to the trash?`,
            description: "You can restore them from your desktop's trash.",
            confirmLabel: "Move to trash",
            onConfirm: () => run("local", () => Promise.all(paths.map(api.localTrash))),
          }
        : {
            title: paths.length === 1 ? `Delete “${baseName(paths[0])}” from the server?` : `Delete ${paths.length} items from the server?`,
            description: "Folders are deleted with everything inside them. This can't be undone.",
            confirmLabel: "Delete",
            onConfirm: () => run("remote", () => Promise.all(paths.map((p) => api.remoteDelete(session, p)))),
          },
    );

  const openEditor = (path: string, entry: Entry) => setEdit({ session, path, name: entry.name });

  const fromDrag = (data: DataTransfer, type: string): string[] => {
    try {
      return JSON.parse(data.getData(type)) as string[];
    } catch {
      return [];
    }
  };

  const localActions: PaneActions = {
    open: () => {},
    transfer: (paths) => void upload(paths),
    transferLabel: "Upload",
    newFolder: newFolder("local"),
    rename: rename("local"),
    remove: remove("local"),
    copyPath: (p) => void api.copyText(p),
    dropped: (d) => void download(fromDrag(d, DRAG_TYPE.remote)),
  };

  const remoteActions: PaneActions = {
    open: (path, entry) => (looksLikeText(entry.name) ? openEditor(path, entry) : void download([path])),
    edit: openEditor,
    transfer: (paths) => void download(paths),
    transferLabel: "Download",
    newFolder: newFolder("remote"),
    rename: rename("remote"),
    remove: remove("remote"),
    copyPath: (p) => void api.copyText(p),
    duplicate: (path) =>
      setPrompt({
        title: "Duplicate",
        label: "Name of the copy",
        initial: `${baseName(path)} copy`,
        submitLabel: "Duplicate",
        onSubmit: async (name) => {
          await api.remoteCopy(session, path, joinPath(parentPath(path), name));
          bump("remote");
        },
      }),
    permissions: (path, entry) => setPerms({ path, mode: entry.mode ?? 0o644 }),
    dropped: (d) => void upload(fromDrag(d, DRAG_TYPE.local)),
  };

  const hidden = settings.showHiddenFiles;
  const setHidden = (v: boolean) => void saveSettings({ showHiddenFiles: v });

  return (
    <div className="flex h-full flex-col gap-2 p-2">
      {error && (
        <div role="alert" className="flex items-center gap-3 rounded-control bg-bad-soft px-3 py-2 text-bad">
          <span className="flex-1">{error}</span>
          <button type="button" onClick={() => setError(null)} className="underline">
            Dismiss
          </button>
        </div>
      )}
      <div className="flex min-h-0 flex-1 gap-2">
        {localPath && (
          <FilePane title="This computer" adapter={local} path={localPath} setPath={setLocalPath} actions={localActions} showHidden={hidden} setShowHidden={setHidden} refreshKey={refresh.local} />
        )}
        <div className="flex flex-col items-center justify-center text-faint" aria-hidden>
          <ArrowLeftRight size={16} />
        </div>
        {remotePath && (
          <FilePane title="Server" adapter={remote} path={remotePath} setPath={setRemotePath} actions={remoteActions} showHidden={hidden} setShowHidden={setHidden} refreshKey={refresh.remote} />
        )}
      </div>
      <p className="text-xs text-faint">Drag files between the panes, or from your desktop onto the server, to transfer them.</p>

      <PromptDialog request={prompt} onClose={() => setPrompt(null)} />
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={confirm?.title}
        description={confirm?.description}
        confirmLabel={confirm?.confirmLabel ?? ""}
        onConfirm={() => confirm?.onConfirm()}
      />
      <PermissionsDialog
        target={perms}
        onClose={() => setPerms(null)}
        onSave={async (mode) => {
          if (perms) await api.remoteChmod(session, perms.path, mode);
          bump("remote");
        }}
      />
      {edit && (
        <Suspense fallback={null}>
          <Editor target={edit} onClose={() => setEdit(null)} />
        </Suspense>
      )}
    </div>
  );
}
