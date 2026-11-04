import { Channel } from "@tauri-apps/api/core";
import { api } from "../services/ipc";
import type { DesktopInput, DesktopOpenRequest, DesktopState } from "../types/ipc";

const ACK_EVERY = 256 * 1024;

// State events can arrive before desktopOpen() returns the id they belong to.
const listeners = new Map<string, (s: DesktopState) => void>();
const early = new Map<string, DesktopState[]>();
if (typeof window !== "undefined") {
  window.addEventListener("desktop-state", (e) => {
    const { desktop, state } = (e as CustomEvent<{ desktop: string; state: DesktopState }>).detail;
    const listener = listeners.get(desktop);
    if (listener) return listener(state);
    early.set(desktop, [...(early.get(desktop) ?? []), state].slice(-8));
    if (early.size > 32) early.delete(early.keys().next().value!);
  });
}

export interface DesktopStream {
  /** VNC: bytes for the server, kept in order; batched while a write is in flight. */
  write(data: Uint8Array): void;
  /** RDP: input events, kept in order; mouse moves coalesce while a send is in flight. */
  input(event: DesktopInput): void;
  /** RDP: asks the server to change the desktop size. */
  resize(width: number, height: number): void;
  /** RDP: offers text as the remote clipboard. */
  clipboard(text: string): void;
  close(): void;
}

/** Opens a remote desktop. `onData` gets the server's stream (acknowledged here). */
export function openDesktop(
  session: string,
  request: DesktopOpenRequest,
  onData: (buf: ArrayBuffer) => void,
  onState: (s: DesktopState) => void,
): DesktopStream {
  let id: string | null = null;
  let closed = false;
  let unacked = 0;
  let pending: Uint8Array[] = [];
  let events: DesktopInput[] = [];
  let writing = false;

  const flush = async () => {
    if (writing) return;
    writing = true;
    while ((pending.length || events.length) && id && !closed) {
      if (events.length) {
        const batch = events.splice(0, 256);
        await api.desktopInput(session, id, batch).catch(() => undefined);
        continue;
      }
      const parts = pending;
      pending = [];
      const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let at = 0;
      for (const p of parts) {
        buf.set(p, at);
        at += p.length;
      }
      await api.desktopWrite(session, id, buf).catch(() => undefined);
    }
    writing = false;
  };

  const channel = new Channel<ArrayBuffer>();
  channel.onmessage = (buf) => {
    if (closed) return;
    onData(buf);
    unacked += buf.byteLength;
    if (unacked >= ACK_EVERY && id) {
      void api.desktopAck(session, id, unacked);
      unacked = 0;
    }
  };

  const close = () => {
    if (closed) return;
    closed = true;
    if (id) {
      listeners.delete(id);
      void api.desktopClose(session, id).catch(() => undefined);
    }
  };

  api
    .desktopOpen(session, request, channel)
    .then((desktop) => {
      id = desktop;
      if (closed) {
        closed = false;
        return close();
      }
      listeners.set(desktop, (s) => !closed && onState(s));
      for (const s of early.get(desktop) ?? []) onState(s);
      early.delete(desktop);
      void flush();
    })
    .catch((e) => onState({ state: "closed", error: { code: "invalid", message: e?.message ?? "The remote desktop couldn't be opened.", details: null } }));

  return {
    write: (data) => {
      if (closed) return;
      pending.push(data);
      void flush();
    },
    input: (event) => {
      if (closed) return;
      const last = events.at(-1);
      if (event.type === "mouse" && last?.type === "mouse") events[events.length - 1] = event;
      else events.push(event);
      void flush();
    },
    resize: (width, height) => id && !closed && void api.desktopResize(session, id, width, height).catch(() => undefined),
    clipboard: (text) => id && !closed && void api.desktopClipboard(session, id, text).catch(() => undefined),
    close,
  };
}
