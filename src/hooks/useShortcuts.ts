import { useEffect, useRef } from "react";
import { matches, SHORTCUTS, type ShortcutId } from "../shortcuts";

/**
 * Global shortcuts, handled in the capture phase so they win over focused widgets
 * (including xterm.js). Elements marked `data-terminal` get the terminal variants.
 */
export function useShortcuts(handlers: Partial<Record<ShortcutId, () => void>>) {
  const ref = useRef(handlers);
  ref.current = handlers;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const inTerminal = e.target instanceof Element && e.target.closest("[data-terminal]") !== null;
      for (const id of Object.keys(SHORTCUTS) as ShortcutId[]) {
        const handler = ref.current[id];
        const s = SHORTCUTS[id];
        const combo = inTerminal && s.inTerminal !== undefined ? s.inTerminal : s.keys;
        if (handler && combo && matches(e, combo)) {
          e.preventDefault();
          e.stopPropagation();
          handler();
          return;
        }
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, []);
}
