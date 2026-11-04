// Special keys the toolbar can send, for both protocols: an X keysym (VNC) and
// a PC scan code (RDP, `e0`-extended keys marked).

export type SpecialKey = "ctrl" | "alt" | "del" | "super" | "tab" | "f4" | "print" | "esc";

export const SPECIAL_KEYS: Record<SpecialKey, { keysym: number; code: string; scancode: number; extended: boolean }> = {
  ctrl: { keysym: 0xffe3, code: "ControlLeft", scancode: 0x1d, extended: false },
  alt: { keysym: 0xffe9, code: "AltLeft", scancode: 0x38, extended: false },
  del: { keysym: 0xffff, code: "Delete", scancode: 0x53, extended: true },
  super: { keysym: 0xffeb, code: "MetaLeft", scancode: 0x5b, extended: true },
  tab: { keysym: 0xff09, code: "Tab", scancode: 0x0f, extended: false },
  f4: { keysym: 0xffc1, code: "F4", scancode: 0x3e, extended: false },
  print: { keysym: 0xff61, code: "PrintScreen", scancode: 0x37, extended: true },
  esc: { keysym: 0xff1b, code: "Escape", scancode: 0x01, extended: false },
};

/** Combinations offered in the Keys menu: pressed in order, released in reverse. */
export const KEY_COMBOS: { label: string; keys: SpecialKey[] }[] = [
  { label: "Ctrl+Alt+Del", keys: ["ctrl", "alt", "del"] },
  { label: "Windows / Super key", keys: ["super"] },
  { label: "Alt+Tab", keys: ["alt", "tab"] },
  { label: "Alt+F4", keys: ["alt", "f4"] },
  { label: "Print Screen", keys: ["print"] },
  { label: "Escape", keys: ["esc"] },
];

/** What a viewer exposes to the toolbar. */
export interface ViewerHandle {
  sendKeys(keys: SpecialKey[]): void;
  /** Gives the remote computer this text as its clipboard. */
  paste(text: string): void;
  focus(): void;
}
