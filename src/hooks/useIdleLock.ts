import { useEffect } from "react";
import { api } from "../services/ipc";

/** Locks the app after `minutes` without keyboard or pointer input (0 = never). */
export function useIdleLock(minutes: number, enabled: boolean) {
  useEffect(() => {
    if (!enabled || minutes <= 0) return;
    let timer = window.setTimeout(lock, minutes * 60_000);
    function lock() {
      void api.lockApp();
    }
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(lock, minutes * 60_000);
    };
    const events = ["keydown", "pointerdown", "pointermove", "wheel"] as const;
    events.forEach((e) => window.addEventListener(e, reset, { passive: true, capture: true }));
    return () => {
      window.clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset, { capture: true }));
    };
  }, [minutes, enabled]);
}
