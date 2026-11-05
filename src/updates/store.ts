import { create } from "zustand";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { api, errorMessage } from "../services/ipc";
import { useSessions } from "../stores/sessions";
import { useEditorDrafts } from "./editor-drafts";
import type { JobState } from "../types/ipc";

export function updateBlockReason(sessions: number, jobs: { state: JobState }[], dirtyEditors: boolean): string | null {
  if (dirtyEditors) return "Save or close unsaved files before installing an update.";
  if (sessions) return "Close connection tabs before installing an update.";
  if (jobs.some((j) => ["queued", "running", "paused", "conflict"].includes(j.state))) {
    return "Finish or cancel pending transfers before installing an update.";
  }
  return null;
}

function busyReason() {
  const { tabs, jobs } = useSessions.getState();
  return updateBlockReason(tabs.length, jobs, useEditorDrafts.getState().dirty.size > 0);
}

export function scheduleUpdateChecks(checkNow: () => void): () => void {
  checkNow();
  const timer = setInterval(checkNow, 24 * 60 * 60 * 1000);
  return () => clearInterval(timer);
}

interface UpdateState {
  update: Update | null;
  state: "idle" | "checking" | "none" | "downloading" | "installing" | "error";
  error: string | null;
  downloaded: number;
  total: number | null;
  checkNow: () => Promise<void>;
  install: () => Promise<void>;
}

export const useUpdates = create<UpdateState>((set, get) => ({
  update: null, state: "idle", error: null, downloaded: 0, total: null,
  checkNow: async () => {
    if (["checking", "downloading", "installing"].includes(get().state)) return;
    set({ state: "checking", error: null });
    try {
      const update = await check({ timeout: 15000 });
      const old = get().update;
      set({ update, state: update ? "idle" : "none" });
      if (old && old !== update) await old.close().catch(() => undefined);
    } catch (e) {
      // Background failures stay in About; they never interrupt a connection.
      set({ state: "error", error: errorMessage(e, String(e)) });
    }
  },
  install: async () => {
    const { update, state } = get();
    if (!update || ["checking", "downloading", "installing"].includes(state)) return;
    const busy = busyReason();
    if (busy) { set({ state: "error", error: busy }); return; }
    set({ state: "downloading", error: null, downloaded: 0, total: null });
    try {
      // download() verifies the signature before we prepare or execute an installer.
      await update.download((event) => {
        if (event.event === "Started") set({ total: event.data.contentLength ?? null });
        if (event.event === "Progress") set((s) => ({ downloaded: s.downloaded + event.data.chunkLength }));
      });
      const nowBusy = busyReason();
      if (nowBusy) throw new Error(nowBusy);
      await api.prepareUpdateInstall();
      set({ state: "installing" });
      await update.install();
      // Windows exits inside install(); the installer restarts the application.
      await relaunch();
    } catch (e) {
      set({ state: "error", error: errorMessage(e, String(e)) });
    }
  },
}));
