import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import RFB from "@novnc/novnc";
import type { DesktopOpenRequest, DesktopQuality, DesktopScale, DesktopState } from "../types/ipc";
import { openDesktop } from "./stream";
import { SPECIAL_KEYS, type ViewerHandle } from "./keys";

/** noVNC's quality (JPEG, 0–9) and compression (zlib, 0–9) per tier. */
const QUALITY: Record<Exclude<DesktopQuality, "auto">, [number, number]> = {
  high: [8, 1],
  balanced: [6, 4],
  low: [3, 8],
};

/**
 * Looks like a WebSocket to noVNC, but carries the bytes over Tauri IPC: the
 * backend's ssh forward, after it has signed in (so noVNC sees security None).
 */
class IpcSocket {
  binaryType = "arraybuffer";
  protocol = "";
  readyState = "open";
  onopen: ((e: Event) => void) | null = null;
  onmessage: ((e: { data: ArrayBuffer }) => void) | null = null;
  onclose: ((e: { code: number; reason: string; wasClean: boolean }) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  out: (data: Uint8Array) => void = () => undefined;
  closing: () => void = () => undefined;

  send(data: Uint8Array) {
    // noVNC reuses its send buffer: copy before it's queued.
    this.out(data.slice());
  }
  close() {
    this.ended(true);
    this.closing();
  }
  deliver(data: ArrayBuffer) {
    if (this.readyState === "open") this.onmessage?.({ data });
  }
  ended(clean: boolean) {
    if (this.readyState === "closed") return;
    this.readyState = "closed";
    this.onclose?.({ code: clean ? 1000 : 1006, reason: "", wasClean: clean });
  }
}

export interface ViewerProps {
  session: string;
  request: DesktopOpenRequest;
  scale: DesktopScale;
  quality: Exclude<DesktopQuality, "auto">;
  onState: (s: DesktopState) => void;
  /** The remote computer's clipboard changed. */
  onClipboard: (text: string) => void;
  /** Bytes received in the last second. */
  onStats: (bytesPerSec: number) => void;
}

/** A VNC desktop drawn by noVNC. */
export const VncViewer = forwardRef<ViewerHandle, ViewerProps>(function VncViewer({ session, request, scale, quality, onState, onClipboard, onStats }, ref) {
  const host = useRef<HTMLDivElement>(null);
  const rfb = useRef<RFB | null>(null);
  const cb = useRef({ onState, onClipboard, onStats });
  cb.current = { onState, onClipboard, onStats };

  useEffect(() => {
    const sock = new IpcSocket();
    const r = new RFB(host.current!, sock, { shared: true });
    r.background = "#000";
    let bytes = 0;
    const stream = openDesktop(
      session,
      request,
      (buf) => {
        bytes += buf.byteLength;
        sock.deliver(buf);
      },
      (s) => {
        if (s.state === "closed") sock.ended(false);
        cb.current.onState(s);
      },
    );
    sock.out = stream.write;
    sock.closing = stream.close;
    r.addEventListener("clipboard", (e) => cb.current.onClipboard((e as CustomEvent<{ text: string }>).detail.text));
    r.addEventListener("connect", () => r.focus());
    const timer = setInterval(() => {
      cb.current.onStats(bytes);
      bytes = 0;
    }, 1000);
    rfb.current = r;
    return () => {
      clearInterval(timer);
      rfb.current = null;
      r.disconnect();
      stream.close();
    };
    // The request is fixed for this viewer's lifetime (it is remounted to reconnect).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  useEffect(() => {
    const r = rfb.current;
    if (!r) return;
    r.scaleViewport = scale !== "actual";
    r.resizeSession = scale === "remote";
    r.clipViewport = false;
    [r.qualityLevel, r.compressionLevel] = QUALITY[quality];
  }, [scale, quality]);

  useImperativeHandle(ref, () => ({
    sendKeys: (keys) => {
      const r = rfb.current;
      if (!r) return;
      if (keys.join("+") === "ctrl+alt+del") return r.sendCtrlAltDel();
      for (const k of keys) r.sendKey(SPECIAL_KEYS[k].keysym, SPECIAL_KEYS[k].code, true);
      for (const k of [...keys].reverse()) r.sendKey(SPECIAL_KEYS[k].keysym, SPECIAL_KEYS[k].code, false);
    },
    paste: (text) => rfb.current?.clipboardPasteFrom(text),
    focus: () => rfb.current?.focus(),
  }));

  return <div ref={host} className="h-full w-full overflow-auto" />;
});
