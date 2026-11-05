import { beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ check: vi.fn(), relaunch: vi.fn(), prepare: vi.fn() }));
vi.mock("@tauri-apps/plugin-updater", () => ({ check: mocks.check }));
vi.mock("@tauri-apps/plugin-process", () => ({ relaunch: mocks.relaunch }));
vi.mock("../services/ipc", () => ({ api: { prepareUpdateInstall: mocks.prepare }, errorMessage: (e: unknown) => String(e) }));
import { scheduleUpdateChecks, updateBlockReason, useUpdates } from "./store";
import { useSessions } from "../stores/sessions";
import { useEditorDrafts } from "./editor-drafts";

describe("signed update flow", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    useUpdates.setState({ update: null, state: "idle", error: null, downloaded: 0, total: null });
    useSessions.setState({ tabs: [], jobs: [] });
    useEditorDrafts.setState({ dirty: new Set() });
  });
  it("checks without downloading, deduplicating concurrent checks", async () => {
    const update = { version: "0.2.0", download: vi.fn() };
    let finish!: (u: unknown) => void;
    mocks.check.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const first = useUpdates.getState().checkNow();
    const second = useUpdates.getState().checkNow();
    finish(update);
    await Promise.all([first, second]);
    expect(mocks.check).toHaveBeenCalledTimes(1);
    expect(update.download).not.toHaveBeenCalled();
    expect(useUpdates.getState().update).toBe(update);
  });
  it("blocks download while a connection tab is still open", async () => {
    const update = { download: vi.fn(), install: vi.fn() };
    useUpdates.setState({ update: update as never });
    useSessions.setState({ tabs: [{ id: "connected" }] as never });
    await useUpdates.getState().install();
    expect(update.download).not.toHaveBeenCalled();
    expect(mocks.prepare).not.toHaveBeenCalled();
  });
  it("keeps the app running when the native busy-state check rejects installation", async () => {
    const update = { download: vi.fn(), install: vi.fn() };
    mocks.prepare.mockRejectedValue({ code: "busy", message: "A connection was opened" });
    useUpdates.setState({ update: update as never });
    await useUpdates.getState().install();
    expect(update.download).toHaveBeenCalledTimes(1);
    expect(update.install).not.toHaveBeenCalled();
    expect(mocks.relaunch).not.toHaveBeenCalled();
  });
  it("does not install or restart when signature verification fails", async () => {
    const update = { download: vi.fn().mockRejectedValue(new Error("invalid signature")), install: vi.fn() };
    useUpdates.setState({ update: update as never });
    await useUpdates.getState().install();
    expect(update.install).not.toHaveBeenCalled();
    expect(mocks.prepare).not.toHaveBeenCalled();
    expect(mocks.relaunch).not.toHaveBeenCalled();
    expect(useUpdates.getState().state).toBe("error");
  });
  it("rechecks busy state after downloading before native installation", async () => {
    const update = { download: vi.fn(async () => { useEditorDrafts.setState({ dirty: new Set(["draft"]) }); }), install: vi.fn() };
    useUpdates.setState({ update: update as never });
    await useUpdates.getState().install();
    expect(mocks.prepare).not.toHaveBeenCalled();
    expect(update.install).not.toHaveBeenCalled();
  });
  it("verifies download, prepares, installs and restarts in order", async () => {
    const calls: string[] = [];
    const update = { download: vi.fn(async () => { calls.push("download"); }), install: vi.fn(async () => { calls.push("install"); }) };
    mocks.prepare.mockImplementation(async () => { calls.push("prepare"); });
    mocks.relaunch.mockImplementation(async () => { calls.push("restart"); });
    useUpdates.setState({ update: update as never });
    await useUpdates.getState().install();
    expect(calls).toEqual(["download", "prepare", "install", "restart"]);
  });
  it("blocks sessions, unfinished transfers and unsaved editors", () => {
    expect(updateBlockReason(1, [], false)).toBeTruthy();
    for (const state of ["queued", "running", "paused", "conflict"] as const) {
      expect(updateBlockReason(0, [{ state }], false)).toBeTruthy();
    }
    expect(updateBlockReason(0, [], true)).toBeTruthy();
    expect(updateBlockReason(0, [{ state: "done" }], false)).toBeNull();
  });
  it("checks at startup and daily, stopping when disabled/unmounted", async () => {
    vi.useFakeTimers();
    const check = vi.fn();
    const stop = scheduleUpdateChecks(check);
    expect(check).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1000);
    expect(check).toHaveBeenCalledTimes(2);
    stop();
    await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1000);
    expect(check).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });
});
