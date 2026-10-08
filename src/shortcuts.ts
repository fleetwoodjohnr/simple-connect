/**
 * Keyboard shortcuts, kept in one table so they can be made user-configurable.
 * While a terminal has focus, shortcuts that collide with common shell keys
 * (Ctrl+K kill-line, Ctrl+W delete-word, Ctrl+L clear) use their Shift variant.
 */
export type ShortcutId = "palette" | "newConnection" | "newTerminal" | "closeTab" | "search" | "settings" | "lock";

export interface Shortcut {
  label: string;
  keys: string;
  /** Variant while a terminal has focus; `null` leaves the keys to the terminal. */
  inTerminal?: string | null;
}

export const SHORTCUTS: Record<ShortcutId, Shortcut> = {
  palette: { label: "Quick connect and commands", keys: "Mod+K", inTerminal: "Mod+Shift+K" },
  newConnection: { label: "New connection", keys: "Mod+Shift+N" },
  newTerminal: { label: "New terminal", keys: "Mod+Shift+T" },
  closeTab: { label: "Close tab", keys: "Mod+W", inTerminal: "Mod+Shift+W" },
  search: { label: "Search connections", keys: "Mod+Shift+F", inTerminal: null },
  settings: { label: "Settings", keys: "Mod+," },
  lock: { label: "Lock", keys: "Mod+L", inTerminal: "Mod+Shift+L" },
};

export const isMac = typeof navigator !== "undefined" && /Mac/.test(navigator.platform);

type KeyLike = Pick<KeyboardEvent, "key" | "ctrlKey" | "metaKey" | "shiftKey" | "altKey">;

/** Exact match: "Mod+Shift+K" requires Mod and Shift and no other modifier. */
export function matches(e: KeyLike, combo: string, mac = isMac): boolean {
  const parts = combo.split("+");
  const key = parts.pop()!.toLowerCase();
  const want = new Set(parts.map((p) => (p === "Mod" ? (mac ? "Meta" : "Ctrl") : p)));
  return (
    e.key.toLowerCase() === key &&
    e.ctrlKey === want.has("Ctrl") &&
    e.metaKey === want.has("Meta") &&
    e.shiftKey === want.has("Shift") &&
    e.altKey === want.has("Alt")
  );
}

/** Human label, e.g. "Ctrl+Shift+K" or "⌘⇧K". */
export function formatKeys(combo: string, mac = isMac): string {
  if (!mac) return combo.replace("Mod", "Ctrl");
  const sym: Record<string, string> = { Mod: "⌘", Shift: "⇧", Alt: "⌥", Ctrl: "⌃" };
  return combo
    .split("+")
    .map((p) => sym[p] ?? p)
    .join("");
}
