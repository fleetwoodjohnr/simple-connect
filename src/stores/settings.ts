import { create } from "zustand";
import { api } from "../services/ipc";
import type { Settings } from "../types/ipc";

export const DEFAULT_SETTINGS: Settings = {
  autoCheckUpdates: true,
  autoReconnect: true,
  includeUserSshConfig: true,
  keepaliveSecs: 30,
  connectTimeoutSecs: 15,
  verifyChecksums: true,
  editorMaxMb: 5,
  clipboardClearSecs: 30,
  autoLockMinutes: 0,
  lockOnSleep: true,
  lockOnSessionLock: true,
  credentialStorage: "keyring",
  writeUserKnownHosts: false,
  showHiddenFiles: false,
  reuseSshPassword: true,
  terminal: {
    fontFamily: "IBM Plex Mono",
    fontSize: 14,
    lineHeight: 1.2,
    theme: "auto",
    scrollback: 10000,
    cursorBlink: true,
    copyOnSelect: false,
    confirmMultilinePaste: true,
  },
  remoteDesktop: { quality: "auto", scale: "fit", clipboardSync: false, uploadDir: "Desktop" },
};

interface SettingsState {
  settings: Settings;
  loaded: boolean;
  load: () => Promise<void>;
  save: (patch: Partial<Settings>) => Promise<void>;
}

export const useSettings = create<SettingsState>((set, get) => ({
  settings: DEFAULT_SETTINGS,
  loaded: false,
  load: async () => set({ settings: await api.getSettings(), loaded: true }),
  save: async (patch) => set({ settings: await api.saveSettings({ ...get().settings, ...patch }) }),
}));
