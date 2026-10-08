import { useEffect, useRef, useState } from "react";
import { Channel } from "@tauri-apps/api/core";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { WebglAddon } from "@xterm/addon-webgl";
import "@xterm/xterm/css/xterm.css";
import { ChevronDown, ChevronUp, KeyRound, X } from "lucide-react";
import { Kbd } from "../components/ui/Kbd";
import { api } from "../services/ipc";
import { useSettings } from "../stores/settings";
import { useSessions } from "../stores/sessions";
import { useUi } from "../stores/ui";
import { resolveTerminalTheme } from "./themes";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";

const ACK_EVERY = 64 * 1024;
const encoder = new TextEncoder();

/** `file://host/path` (OSC 7) → `/path`. */
export function parseOsc7(data: string): string | null {
  try {
    const url = new URL(data);
    return url.protocol === "file:" ? decodeURIComponent(url.pathname) : null;
  } catch {
    return null;
  }
}

/**
 * One remote shell. The xterm instance lives as long as the component; the
 * backend shell is (re)opened whenever the session is connected and none is
 * running. Input typed while disconnected is dropped, never replayed.
 */
export function TerminalView({ session, connected, visible }: { session: string; connected: boolean; visible: boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const search = useRef<SearchAddon | null>(null);
  const backendId = useRef<string | null>(null);
  const opening = useRef(false);
  const settings = useSettings((s) => s.settings.terminal);
  const appTheme = useUi((s) => s.theme);
  const setCwd = useSessions((s) => s.setCwd);
  const [findOpen, setFindOpen] = useState(false);
  const [findText, setFindText] = useState("");
  const [pasteConfirm, setPasteConfirm] = useState<string | null>(null);
  /** Bumped to start a new shell after the previous one ended. */
  const [shellGen, setShellGen] = useState(0);
  const ended = useRef(false);
  /** The backend sees a sudo/su prompt and can answer it with the login password. */
  const [offer, setOffer] = useState(false);
  const offerRef = useRef(false);
  offerRef.current = offer;
  const sendPassword = () => {
    if (backendId.current) void api.terminalSendPassword(session, backendId.current).catch(() => undefined);
    setOffer(false);
    term.current?.focus();
  };
  const sendRef = useRef(sendPassword);
  sendRef.current = sendPassword;

  const paste = async () => {
    const text = await api.pasteText().catch(() => "");
    if (!text) return;
    if (settings.confirmMultilinePaste && text.includes("\n")) setPasteConfirm(text);
    else term.current?.paste(text);
  };
  const copySelection = () => {
    const sel = term.current?.getSelection();
    if (sel) void api.copyText(sel);
  };

  // Create the xterm instance once.
  useEffect(() => {
    const t = new Terminal({
      allowProposedApi: true,
      fontFamily: `"${settings.fontFamily}", "IBM Plex Mono", monospace`,
      fontSize: settings.fontSize,
      lineHeight: settings.lineHeight,
      cursorBlink: settings.cursorBlink,
      scrollback: settings.scrollback,
      theme: resolveTerminalTheme(settings.theme),
      macOptionIsMeta: true,
      rightClickSelectsWord: true,
    });
    const f = new FitAddon();
    const s = new SearchAddon();
    t.loadAddon(f);
    t.loadAddon(s);
    t.loadAddon(new Unicode11Addon());
    t.unicode.activeVersion = "11";
    t.open(host.current!);
    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      t.loadAddon(webgl);
    } catch {
      /* DOM renderer fallback */
    }
    t.parser.registerOscHandler(7, (data) => {
      const cwd = parseOsc7(data);
      if (cwd) setCwd(session, cwd);
      return true;
    });
    // Terminal-standard clipboard keys; plain Ctrl+C/V stay with the shell.
    t.attachCustomKeyEventHandler((e) => {
      // A password prompt is offered: Enter answers it from the backend, Esc
      // declines; anything else is typed normally (and withdraws the offer).
      if (offerRef.current && e.type === "keydown" && !e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey) {
        if (e.key === "Enter") {
          e.preventDefault();
          sendRef.current();
          return false;
        }
        if (e.key === "Escape") {
          setOffer(false);
          return false;
        }
        setOffer(false);
      }
      if (e.type !== "keydown" || !e.ctrlKey || !e.shiftKey) return true;
      const k = e.key.toLowerCase();
      if (k === "c") copySelection();
      else if (k === "v") void paste();
      else if (k === "f") setFindOpen(true);
      else return true;
      e.preventDefault();
      return false;
    });
    t.onSelectionChange(() => {
      if (useSettings.getState().settings.terminal.copyOnSelect) copySelection();
    });
    term.current = t;
    fit.current = f;
    search.current = s;
    return () => {
      if (backendId.current) void api.closeTerminal(session, backendId.current);
      t.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  // Apply setting changes live.
  useEffect(() => {
    const t = term.current;
    if (!t) return;
    t.options.fontFamily = `"${settings.fontFamily}", "IBM Plex Mono", monospace`;
    t.options.fontSize = settings.fontSize;
    t.options.lineHeight = settings.lineHeight;
    t.options.cursorBlink = settings.cursorBlink;
    t.options.scrollback = settings.scrollback;
    t.options.theme = resolveTerminalTheme(settings.theme);
    fit.current?.fit();
  }, [settings, appTheme]);

  // Keep the grid sized to the container.
  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      if (el.offsetWidth > 0) fit.current?.fit();
    });
    ro.observe(el);
    const sub = term.current?.onResize(({ cols, rows }) => {
      if (backendId.current) void api.terminalResize(session, backendId.current, cols, rows);
    });
    return () => {
      ro.disconnect();
      sub?.dispose();
    };
  }, [session]);

  useEffect(() => {
    if (visible) {
      fit.current?.fit();
      term.current?.focus();
    }
  }, [visible]);

  // Open a shell whenever connected without one.
  useEffect(() => {
    const t = term.current;
    if (!t) return;
    if (!connected) {
      // The shell died with the connection; a new one opens after reconnecting.
      if (backendId.current || ended.current) {
        t.write("\r\n\x1b[2m— Connection lost. A new shell opens when the connection is back. —\x1b[0m\r\n");
      }
      backendId.current = null;
      ended.current = false;
      return;
    }
    if (backendId.current || opening.current || ended.current) return;
    opening.current = true;
    let unacked = 0;
    const channel = new Channel<ArrayBuffer>();
    channel.onmessage = (buf) => {
      const bytes = new Uint8Array(buf);
      t.write(bytes, () => {
        unacked += bytes.length;
        if (unacked >= ACK_EVERY && backendId.current) {
          void api.terminalAck(session, backendId.current, unacked);
          unacked = 0;
        }
      });
    };
    const wasOpenBefore = t.buffer.active.length > t.rows;
    api
      .openTerminal(session, t.cols, t.rows, channel)
      .then((id) => {
        backendId.current = id;
        if (wasOpenBefore) t.write("\x1b[2m— New shell —\x1b[0m\r\n");
      })
      .catch((e) => t.write(`\r\n\x1b[31m${e?.message ?? "The shell couldn't be opened."}\x1b[0m\r\n`))
      .finally(() => (opening.current = false));
  }, [connected, session, shellGen]);

  // Keystrokes → backend. Dropped while no shell is attached.
  useEffect(() => {
    const t = term.current;
    if (!t) return;
    const send = (bytes: Uint8Array) => {
      if (backendId.current) void api.terminalWrite(session, backendId.current, bytes);
    };
    const a = t.onData((d) => send(encoder.encode(d)));
    const b = t.onBinary((d) => send(Uint8Array.from(d, (c) => c.charCodeAt(0) & 0xff)));
    const onExit = (e: Event) => {
      if (connected && (e as CustomEvent<string>).detail === backendId.current) {
        backendId.current = null;
        ended.current = true;
        t.write("\r\n\x1b[2m— Shell ended. Press Enter for a new one. —\x1b[0m\r\n");
      }
    };
    const c = t.onKey(({ domEvent }) => {
      if (ended.current && domEvent.key === "Enter") {
        ended.current = false;
        setShellGen((n) => n + 1);
      }
    });
    const onPrompt = (e: Event) => {
      const d = (e as CustomEvent<{ terminal: string; visible: boolean }>).detail;
      if (d.terminal === backendId.current) setOffer(d.visible);
    };
    window.addEventListener("password-prompt", onPrompt);
    window.addEventListener("terminal-exit", onExit);
    return () => {
      a.dispose();
      b.dispose();
      c.dispose();
      window.removeEventListener("password-prompt", onPrompt);
      window.removeEventListener("terminal-exit", onExit);
    };
  }, [session, connected]);

  const find = (forward: boolean) => {
    if (!findText) return;
    if (forward) search.current?.findNext(findText);
    else search.current?.findPrevious(findText);
  };

  return (
    <div className="relative h-full w-full" data-terminal onContextMenu={(e) => e.preventDefault()}>
      <div ref={host} className="h-full w-full px-2 pt-1.5" />
      {offer && visible && (
        <button
          type="button"
          role="status"
          onClick={sendPassword}
          className="animate-pop absolute bottom-3 right-4 flex items-center gap-2 rounded-full border border-line-strong bg-raised px-3.5 py-1.5 text-xs text-text shadow-pop hover:border-accent"
        >
          <KeyRound size={13} className="text-accent" aria-hidden />
          <span>
            Press <Kbd keys="Enter" /> to use your SSH password
          </span>
          <span className="text-faint">Esc to type it</span>
        </button>
      )}
      {findOpen && (
        <div className="animate-pop absolute right-3 top-2 flex items-center gap-1 rounded-control bg-raised p-1 shadow-pop">
          <input
            autoFocus
            value={findText}
            onChange={(e) => setFindText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") find(!e.shiftKey);
              if (e.key === "Escape") {
                setFindOpen(false);
                term.current?.focus();
              }
            }}
            placeholder="Find"
            aria-label="Find in terminal"
            className="h-7 w-48 rounded-[5px] bg-ink px-2 outline-none"
          />
          <button type="button" aria-label="Previous match" onClick={() => find(false)} className="grid size-7 place-items-center rounded-[5px] hover:bg-hover">
            <ChevronUp size={14} />
          </button>
          <button type="button" aria-label="Next match" onClick={() => find(true)} className="grid size-7 place-items-center rounded-[5px] hover:bg-hover">
            <ChevronDown size={14} />
          </button>
          <button
            type="button"
            aria-label="Close find"
            onClick={() => {
              setFindOpen(false);
              term.current?.focus();
            }}
            className="grid size-7 place-items-center rounded-[5px] hover:bg-hover"
          >
            <X size={14} />
          </button>
        </div>
      )}
      <ConfirmDialog
        open={pasteConfirm !== null}
        onOpenChange={(o) => !o && setPasteConfirm(null)}
        title="Paste multiple lines?"
        description={
          <>
            The text contains {pasteConfirm?.split("\n").length} lines. Each line may run as a command.
            <pre className="mt-3 max-h-40 overflow-auto rounded-control bg-ink p-2 font-mono text-xs text-text" data-selectable>
              {pasteConfirm}
            </pre>
          </>
        }
        confirmLabel="Paste"
        variant="primary"
        onConfirm={() => {
          if (pasteConfirm) term.current?.paste(pasteConfirm);
          term.current?.focus();
        }}
      />
    </div>
  );
}
