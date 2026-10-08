import { create } from "zustand";
import type { Profile, ProfileDraft } from "../types/ipc";

export type ThemePref = "dark" | "light" | "system";
export type MotionPref = "system" | "reduce";
export type View = "workspace" | "settings";

interface UiState {
  theme: ThemePref;
  setTheme: (t: ThemePref) => void;
  textScale: number;
  setTextScale: (s: number) => void;
  motion: MotionPref;
  setMotion: (m: MotionPref) => void;
  view: View;
  setView: (v: View) => void;
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
  drawerOpen: boolean;
  toggleDrawer: () => void;
  /** Connection editor: an existing profile, or initial values for a new one.
   *  `linkSession`: an open quick connection to attach the saved profile to. */
  editing: { profile?: Profile; initial?: Partial<ProfileDraft>; linkSession?: string } | null;
  scannerOpen: boolean;
  setScannerOpen: (open: boolean) => void;
  setEditing: (e: UiState["editing"]) => void;
}

// UI preferences are non-sensitive; localStorage avoids a theme flash at startup.
function stored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function store(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable: preference lasts for this session */
  }
}
function storedTheme(): ThemePref {
  const t = stored("theme");
  return t === "light" || t === "system" ? t : "dark";
}

export const useUi = create<UiState>((set) => ({
  theme: storedTheme(),
  setTheme: (theme) => {
    store("theme", theme);
    set({ theme });
  },
  textScale: Number(stored("textScale")) || 1,
  setTextScale: (textScale) => {
    store("textScale", String(textScale));
    set({ textScale });
  },
  motion: stored("motion") === "reduce" ? "reduce" : "system",
  setMotion: (motion) => {
    store("motion", motion);
    set({ motion });
  },
  view: "workspace",
  setView: (view) => set({ view }),
  paletteOpen: false,
  setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
  drawerOpen: false,
  toggleDrawer: () => set((s) => ({ drawerOpen: !s.drawerOpen })),
  editing: null,
  setEditing: (editing) => set({ editing }),
  scannerOpen: false,
  setScannerOpen: (scannerOpen) => set({ scannerOpen }),
}));
