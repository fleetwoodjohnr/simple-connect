import { useEditorDrafts } from "../updates/editor-drafts";
import { useEffect, useRef, useState } from "react";
import { EditorState, type Extension } from "@codemirror/state";
import { EditorView, keymap, lineNumbers, highlightActiveLine, drawSelection } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, foldGutter, HighlightStyle, indentOnInput, StreamLanguage, syntaxHighlighting } from "@codemirror/language";
import { highlightSelectionMatches, searchKeymap } from "@codemirror/search";
import { tags as t } from "@lezer/highlight";
import { json } from "@codemirror/lang-json";
import { yaml } from "@codemirror/lang-yaml";
import { python } from "@codemirror/lang-python";
import { javascript } from "@codemirror/lang-javascript";
import { rust } from "@codemirror/lang-rust";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { toml } from "@codemirror/legacy-modes/mode/toml";
import { properties } from "@codemirror/legacy-modes/mode/properties";
import { dockerFile } from "@codemirror/legacy-modes/mode/dockerfile";
import { nginx } from "@codemirror/legacy-modes/mode/nginx";
import { Dialog } from "../components/ui/Dialog";
import { Button } from "../components/ui/Button";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { api, errorMessage } from "../services/ipc";

/** Picks a syntax mode from the file name. */
export function languageFor(name: string): Extension | null {
  const n = name.toLowerCase();
  const ext = n.includes(".") ? n.slice(n.lastIndexOf(".") + 1) : "";
  if (n === "dockerfile" || n === "containerfile" || n.startsWith("dockerfile.")) return StreamLanguage.define(dockerFile);
  if (n.includes("nginx") && ext === "conf") return StreamLanguage.define(nginx);
  if (/^\.(bashrc|zshrc|profile|bash_profile|bash_aliases)$/.test(n)) return StreamLanguage.define(shell);
  switch (ext) {
    case "json":
      return json();
    case "yaml":
    case "yml":
      return yaml();
    case "py":
      return python();
    case "js":
    case "mjs":
    case "cjs":
    case "jsx":
      return javascript({ jsx: true });
    case "ts":
    case "tsx":
      return javascript({ jsx: ext === "tsx", typescript: true });
    case "rs":
      return rust();
    case "sh":
    case "bash":
    case "zsh":
      return StreamLanguage.define(shell);
    case "toml":
      return StreamLanguage.define(toml);
    case "service":
    case "timer":
    case "socket":
    case "mount":
    case "target":
    case "path":
    case "ini":
    case "conf":
    case "cfg":
    case "env":
    case "properties":
      return StreamLanguage.define(properties);
    default:
      return null;
  }
}

const highlight = HighlightStyle.define([
  { tag: [t.keyword, t.controlKeyword, t.operatorKeyword], color: "var(--accent)" },
  { tag: [t.string, t.special(t.string)], color: "var(--ok)" },
  { tag: [t.number, t.bool, t.null, t.atom], color: "var(--warn)" },
  { tag: [t.comment, t.lineComment, t.blockComment], color: "var(--text-faint)", fontStyle: "italic" },
  { tag: [t.propertyName, t.attributeName, t.definition(t.variableName)], color: "#b493e8" },
  { tag: [t.typeName, t.className, t.heading], color: "#5cc8cf" },
]);

const theme = EditorView.theme({
  "&": { height: "100%", backgroundColor: "var(--ink)", color: "var(--text)", fontSize: "13px" },
  ".cm-content": { fontFamily: "var(--font-mono)", caretColor: "var(--accent)" },
  ".cm-gutters": { backgroundColor: "var(--panel)", color: "var(--text-faint)", border: "none" },
  ".cm-activeLine": { backgroundColor: "var(--hover)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--hover)" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground": { backgroundColor: "var(--accent-soft) !important" },
  ".cm-panels": { backgroundColor: "var(--raised)", color: "var(--text)" },
});

export interface EditTarget {
  session: string;
  path: string;
  name: string;
}

/**
 * Edits a remote text file. The working copy stays in memory (never written to
 * a local temporary file) and is saved back atomically over SFTP.
 */
export function Editor({ target, onClose }: { target: EditTarget | null; onClose: () => void }) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "saving" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const original = useRef("");
  useEffect(() => {
    if (!target) return;
    const id = `${target.session}:${target.path}`;
    useEditorDrafts.getState().mark(id, dirty);
    return () => useEditorDrafts.getState().mark(id, false);
  }, [target, dirty]);


  const save = async () => {
    if (!target || !view.current) return;
    setState("saving");
    try {
      const text = view.current.state.doc.toString();
      await api.writeRemoteText(target.session, target.path, text);
      original.current = text;
      setDirty(false);
      setState("ready");
      setError(null);
    } catch (e) {
      setError(errorMessage(e, "The file couldn't be saved."));
      setState("ready");
    }
  };
  const saveRef = useRef(save);
  saveRef.current = save;

  useEffect(() => {
    if (!target) return;
    let alive = true;
    setState("loading");
    setDirty(false);
    setError(null);
    api
      .readRemoteText(target.session, target.path)
      .then((text) => {
        if (!alive || !host.current) return;
        original.current = text;
        const lang = languageFor(target.name);
        view.current = new EditorView({
          parent: host.current,
          state: EditorState.create({
            doc: text,
            extensions: [
              lineNumbers(),
              foldGutter(),
              history(),
              drawSelection(),
              highlightActiveLine(),
              highlightSelectionMatches(),
              indentOnInput(),
              bracketMatching(),
              syntaxHighlighting(highlight),
              keymap.of([
                { key: "Mod-s", preventDefault: true, run: () => (void saveRef.current(), true) },
                indentWithTab,
                ...defaultKeymap,
                ...historyKeymap,
                ...searchKeymap,
              ]),
              EditorView.updateListener.of((u) => u.docChanged && setDirty(u.state.doc.toString() !== original.current)),
              theme,
              ...(lang ? [lang] : []),
            ],
          }),
        });
        view.current.focus();
        setState("ready");
      })
      .catch((e) => {
        if (!alive) return;
        setError(errorMessage(e, "The file couldn't be opened."));
        setState("error");
      });
    return () => {
      alive = false;
      view.current?.destroy();
      view.current = null;
    };
  }, [target]);

  const requestClose = () => (dirty ? setConfirmClose(true) : onClose());

  return (
    <>
      <Dialog
        open={target !== null}
        onOpenChange={(o) => !o && requestClose()}
        title={
          <span className="font-mono text-sm">
            {target?.path}
            {dirty && <span className="ml-2 text-warn">●</span>}
          </span>
        }
        width="w-[min(1100px,95vw)] h-[88vh]"
        footer={
          <>
            {error && <p className="mr-auto self-center text-bad">{error}</p>}
            <Button onClick={requestClose}>Close</Button>
            <Button variant="primary" disabled={!dirty || state !== "ready"} onClick={() => void save()}>
              {state === "saving" ? "Saving…" : "Save"}
            </Button>
          </>
        }
      >
        {state === "loading" && <p className="text-muted">Opening…</p>}
        <div ref={host} className="h-full min-h-[50vh] overflow-hidden rounded-control border border-line" hidden={state === "error"} />
      </Dialog>
      <ConfirmDialog
        open={confirmClose}
        onOpenChange={setConfirmClose}
        title="Discard unsaved changes?"
        description="Your edits to this file haven't been saved to the server."
        confirmLabel="Discard changes"
        onConfirm={onClose}
      />
    </>
  );
}
