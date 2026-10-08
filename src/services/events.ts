import { listen } from "@tauri-apps/api/event";
import { useSessions } from "../stores/sessions";
import type { UiEvent } from "../types/ipc";

let started = false;

/** Subscribes once to backend events for the life of the window. */
export async function startEventBridge() {
  if (started) return;
  started = true;
  const { handle, setLocked } = useSessions.getState();
  await listen<UiEvent>("ui-event", (e) => handle(e.payload));
  await listen("app-locked", () => setLocked(true));
  await listen("app-unlocked", () => setLocked(false));
}
