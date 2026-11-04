import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from "react";
import type { DesktopInput } from "../types/ipc";
import { openDesktop, type DesktopStream } from "./stream";
import { scancode } from "./keymap";
import { SPECIAL_KEYS, type ViewerHandle } from "./keys";
import type { ViewerProps } from "./VncViewer";

// Messages from the backend (crates/core/src/desktop/rdp.rs), little-endian.
const RECT = 1; // x, y, w, h: u16, then RGBA
const SIZE = 2; // w, h
const CURSOR = 3; // hotX, hotY, w, h, then RGBA
const CURSOR_HIDDEN = 4;
const CURSOR_DEFAULT = 5;
const CLIPBOARD = 6; // UTF-8 text

const BUTTONS: Record<number, "left" | "middle" | "right" | "x1" | "x2"> = { 0: "left", 1: "middle", 2: "right", 3: "x1", 4: "x2" };

function cursorCss(view: DataView, buf: ArrayBuffer): string {
  const [hx, hy, w, h] = [view.getUint16(1, true), view.getUint16(3, true), view.getUint16(5, true), view.getUint16(7, true)];
  if (!w || !h) return "none";
  const c = document.createElement("canvas");
  c.width = w;
  c.height = h;
  c.getContext("2d")!.putImageData(new ImageData(new Uint8ClampedArray(buf, 9, w * h * 4), w, h), 0, 0);
  return `url(${c.toDataURL()}) ${hx} ${hy}, default`;
}

/** An RDP desktop: the backend decodes, this draws changed rectangles and sends input. */
export const RdpViewer = forwardRef<ViewerHandle, ViewerProps>(function RdpViewer({ session, request, scale, onState, onClipboard, onStats }, ref) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const stream = useRef<DesktopStream | null>(null);
  const [size, setSize] = useState<[number, number]>([request.width, request.height]);
  const cb = useRef({ onState, onClipboard, onStats });
  cb.current = { onState, onClipboard, onStats };

  useEffect(() => {
    const el = canvas.current!;
    const ctx = el.getContext("2d", { alpha: false })!;
    let bytes = 0;
    const decoder = new TextDecoder();
    const s = openDesktop(
      session,
      request,
      (buf) => {
        bytes += buf.byteLength;
        const view = new DataView(buf);
        switch (view.getUint8(0)) {
          case RECT: {
            const [x, y, w, h] = [view.getUint16(1, true), view.getUint16(3, true), view.getUint16(5, true), view.getUint16(7, true)];
            if (w && h) ctx.putImageData(new ImageData(new Uint8ClampedArray(buf, 9, w * h * 4), w, h), x, y);
            break;
          }
          case SIZE:
            el.width = view.getUint16(1, true);
            el.height = view.getUint16(3, true);
            setSize([el.width, el.height]);
            break;
          case CURSOR:
            el.style.cursor = cursorCss(view, buf);
            break;
          case CURSOR_HIDDEN:
            el.style.cursor = "none";
            break;
          case CURSOR_DEFAULT:
            el.style.cursor = "default";
            break;
          case CLIPBOARD:
            cb.current.onClipboard(decoder.decode(new Uint8Array(buf, 1)));
            break;
        }
      },
      (st) => {
        cb.current.onState(st);
        if (st.state === "connected") el.focus();
      },
    );
    stream.current = s;
    const timer = setInterval(() => {
      cb.current.onStats(bytes);
      bytes = 0;
    }, 1000);
    return () => {
      clearInterval(timer);
      stream.current = null;
      s.close();
    };
    // The request is fixed for this viewer's lifetime (it is remounted to reconnect).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  // "Resize remote desktop": follow the view's size (debounced; DisplayControl).
  useEffect(() => {
    const parent = canvas.current?.parentElement;
    if (scale !== "remote" || !parent) return;
    let timer = 0;
    const ro = new ResizeObserver(() => {
      clearTimeout(timer);
      timer = window.setTimeout(() => {
        if (parent.clientWidth > 0) stream.current?.resize(Math.round(parent.clientWidth), Math.round(parent.clientHeight));
      }, 400);
    });
    ro.observe(parent);
    return () => {
      clearTimeout(timer);
      ro.disconnect();
    };
  }, [scale]);

  const send = (e: DesktopInput) => stream.current?.input(e);

  /** Screen → remote pixels, allowing for letterboxing when scaled to fit. */
  const toRemote = (clientX: number, clientY: number) => {
    const el = canvas.current!;
    const r = el.getBoundingClientRect();
    const k = scale === "actual" ? 1 : Math.min(r.width / el.width, r.height / el.height);
    const ox = scale === "actual" ? 0 : (r.width - el.width * k) / 2;
    const oy = scale === "actual" ? 0 : (r.height - el.height * k) / 2;
    const x = Math.round((clientX - r.left - ox) / k);
    const y = Math.round((clientY - r.top - oy) / k);
    return { x: Math.max(0, Math.min(el.width - 1, x)), y: Math.max(0, Math.min(el.height - 1, y)) };
  };

  const key = (e: React.KeyboardEvent, down: boolean) => {
    e.preventDefault();
    e.stopPropagation();
    const sc = scancode(e.code);
    if (sc) send({ type: "key", ...sc, down });
    else if (e.key.length === 1) send({ type: "unicode", ch: e.key.codePointAt(0)!, down });
  };

  useImperativeHandle(ref, () => ({
    sendKeys: (keys) => {
      for (const k of keys) send({ type: "key", scancode: SPECIAL_KEYS[k].scancode, extended: SPECIAL_KEYS[k].extended, down: true });
      for (const k of [...keys].reverse()) send({ type: "key", scancode: SPECIAL_KEYS[k].scancode, extended: SPECIAL_KEYS[k].extended, down: false });
    },
    paste: (text) => stream.current?.clipboard(text),
    focus: () => canvas.current?.focus(),
  }));

  const fit = scale !== "actual";
  return (
    <div className={`h-full w-full ${fit ? "overflow-hidden" : "overflow-auto"}`}>
      <canvas
        ref={canvas}
        width={size[0]}
        height={size[1]}
        tabIndex={0}
        aria-label="Remote desktop"
        className={`block outline-none ${fit ? "h-full w-full object-contain" : ""}`}
        onContextMenu={(e) => e.preventDefault()}
        onPointerMove={(e) => send({ type: "mouse", ...toRemote(e.clientX, e.clientY) })}
        onPointerDown={(e) => {
          e.currentTarget.focus();
          e.currentTarget.setPointerCapture(e.pointerId);
          send({ type: "mouse", ...toRemote(e.clientX, e.clientY) });
          if (BUTTONS[e.button]) send({ type: "button", button: BUTTONS[e.button], down: true });
        }}
        onPointerUp={(e) => BUTTONS[e.button] && send({ type: "button", button: BUTTONS[e.button], down: false })}
        onWheel={(e) => {
          const horizontal = Math.abs(e.deltaX) > Math.abs(e.deltaY);
          const d = horizontal ? e.deltaX : e.deltaY;
          // One notch is 120 units; lines and pages are scaled to roughly match.
          const units = e.deltaMode === 0 ? d * 1.2 : e.deltaMode === 1 ? d * 40 : d * 400;
          send({ type: "wheel", delta: Math.max(-1200, Math.min(1200, Math.round(horizontal ? units : -units))), horizontal });
        }}
        onKeyDown={(e) => key(e, true)}
        onKeyUp={(e) => key(e, false)}
        onBlur={() => send({ type: "releaseAll" })}
      />
    </div>
  );
});
