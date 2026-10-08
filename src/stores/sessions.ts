import { create } from "zustand";
import { api, errorMessage } from "../services/ipc";
import type { ConnectFailure, JobView, SecretPromptKind, SecurityInfo, SessionStatus, Tunnel, UiEvent } from "../types/ipc";
import type { ConnectTarget } from "../types/session";
import { findProfile, useConnections } from "./connections";
import { formatDestination } from "../connections/RoutePreview";

export type SubView = "terminal" | "files" | "tunnels" | "info";

export interface TerminalSlot {
  key: string;
  title: string;
}

export interface SessionTab {
  id: string;
  label: string;
  profileId: string | null;
  /** Where a quick connection went, so it can be saved as a connection. */
  quick: { host: string; port: number | null; user: string | null; mac: string | null } | null;
  status: SessionStatus;
  info: SecurityInfo | null;
  failure: ConnectFailure | null;
  /** True once the session has been connected at least once. */
  everConnected: boolean;
  view: SubView;
  terminals: TerminalSlot[];
  activeTerminal: string | null;
  tunnels: Tunnel[];
  /** Remote working directory reported by the shell (OSC 7), if any. */
  cwd: string | null;
  log: { at: number; text: string }[];
}

export type Prompt =
  | {
      type: "hostKey";
      id: number;
      session: string;
      host: string;
      address: string | null;
      keyType: string;
      fingerprint: string;
      changed: boolean;
      previous: { keyType: string; fingerprint: string; file: string }[];
    }
  | { type: "secret"; id: number; session: string; kind: SecretPromptKind; prompt: string; canSave: boolean };

interface SessionsState {
  tabs: SessionTab[];
  activeId: string | null;
  prompts: Prompt[];
  notices: { id: number; session: string; text: string }[];
  jobs: JobView[];
  locked: boolean;
  connectError: string | null;
  connect: (target: ConnectTarget) => Promise<void>;
  close: (id: string) => Promise<void>;
  setActive: (id: string | null) => void;
  setView: (id: string, view: SubView) => void;
  addTerminal: (id: string) => void;
  removeTerminal: (id: string, key: string) => void;
  setActiveTerminal: (id: string, key: string) => void;
  setCwd: (id: string, cwd: string) => void;
  setLocked: (locked: boolean) => void;
  dismissConnectError: () => void;
  /** A quick connection was saved: show it under its new name from now on. */
  linkProfile: (id: string, profile: { id: string; name: string }) => void;
  handle: (e: UiEvent) => void;
}

const statusText: Record<SessionStatus["state"], string> = {
  connecting: "Connecting…",
  authenticating: "Authenticating…",
  connected: "Connected",
  reconnecting: "Reconnecting…",
  disconnected: "Disconnected",
  failed: "Connection failed",
};

export function describeStatus(s: SessionStatus): string {
  return s.state === "reconnecting" ? `Reconnecting in ${s.delaySecs}s (attempt ${s.attempt})` : statusText[s.state];
}

let terminalCounter = 0;
const newSlot = (n: number): TerminalSlot => ({ key: `t${++terminalCounter}`, title: n === 1 ? "Shell" : `Shell ${n}` });

type TabMeta = { label: string; profileId: string | null; quick: SessionTab["quick"] };

function newTab(id: string, { label, profileId, quick }: TabMeta): SessionTab {
  const slot = newSlot(1);
  return {
    id,
    label,
    profileId,
    quick,
    status: { state: "connecting" },
    info: null,
    failure: null,
    everConnected: false,
    view: "terminal",
    terminals: [slot],
    activeTerminal: slot.key,
    tunnels: [],
    cwd: null,
    log: [],
  };
}

export const useSessions = create<SessionsState>((set, get) => {
  const update = (id: string, f: (t: SessionTab) => Partial<SessionTab>) =>
    set((s) => ({ tabs: s.tabs.map((t) => (t.id === id ? { ...t, ...f(t) } : t)) }));
  // Session events can arrive before connect() resolves; remember labels by id.
  const pending = new Map<string, TabMeta>();

  return {
    tabs: [],
    activeId: null,
    prompts: [],
    notices: [],
    jobs: [],
    locked: false,
    connectError: null,

    connect: async (target) => {
      try {
        let id: string;
        let meta: TabMeta;
        if (target.kind === "profile") {
          id = await api.connectProfile(target.profile.id);
          meta = { label: target.profile.name, profileId: target.profile.id, quick: null };
        } else if (target.kind === "alias") {
          id = await api.connectAlias(target.host.alias);
          meta = { label: target.host.alias, profileId: null, quick: null };
        } else {
          id = await api.connectQuick(target.input);
          const { host, port, user } = target.dest;
          // Show the saved name for a known device instead of its address.
          const saved = findProfile(useConnections.getState().profiles, { host, port: port ?? 22, user });
          meta = { label: saved?.name ?? formatDestination(target.dest), profileId: null, quick: { host, port, user, mac: target.mac ?? null } };
        }
        if (!get().tabs.some((t) => t.id === id)) {
          pending.set(id, meta);
          set((s) => ({ tabs: [...s.tabs, newTab(id, meta)] }));
        } else {
          update(id, () => meta);
        }
        set({ activeId: id, connectError: null });
      } catch (e) {
        set({ connectError: errorMessage(e, "The connection couldn't be started.") });
      }
    },

    close: async (id) => {
      set((s) => {
        const idx = s.tabs.findIndex((t) => t.id === id);
        const tabs = s.tabs.filter((t) => t.id !== id);
        const activeId = s.activeId === id ? (tabs[Math.max(0, idx - 1)]?.id ?? null) : s.activeId;
        return { tabs, activeId, prompts: s.prompts.filter((p) => p.session !== id) };
      });
      await api.disconnect(id).catch(() => undefined);
    },

    setActive: (activeId) => set({ activeId }),
    setView: (id, view) => update(id, () => ({ view })),
    addTerminal: (id) =>
      update(id, (t) => {
        const slot = newSlot(t.terminals.length + 1);
        return { terminals: [...t.terminals, slot], activeTerminal: slot.key, view: "terminal" };
      }),
    removeTerminal: (id, key) =>
      update(id, (t) => {
        const terminals = t.terminals.filter((x) => x.key !== key);
        return { terminals, activeTerminal: t.activeTerminal === key ? (terminals.at(-1)?.key ?? null) : t.activeTerminal };
      }),
    setActiveTerminal: (id, key) => update(id, () => ({ activeTerminal: key })),
    setCwd: (id, cwd) => update(id, () => ({ cwd })),
    setLocked: (locked) => set({ locked }),
    dismissConnectError: () => set({ connectError: null }),
    linkProfile: (id, profile) => update(id, () => ({ profileId: profile.id, label: profile.name, quick: null })),

    handle: (e) => {
      switch (e.type) {
        case "session": {
          if (!get().tabs.some((t) => t.id === e.session)) {
            const meta = pending.get(e.session) ?? { label: e.label, profileId: null, quick: null };
            set((s) => ({ tabs: [...s.tabs, newTab(e.session, meta)] }));
          }
          update(e.session, (t) => ({
            status: e.status,
            info: e.info ?? t.info,
            failure: e.status.state === "connected" ? null : (e.failure ?? t.failure),
            everConnected: t.everConnected || e.status.state === "connected",
            log: [...t.log.slice(-199), { at: Date.now(), text: e.failure ? `${describeStatus(e.status)}: ${e.failure.message}` : describeStatus(e.status) }],
          }));
          break;
        }
        case "hostKeyPrompt":
          set((s) => ({ prompts: [...s.prompts, { ...e, type: "hostKey" }] }));
          break;
        case "secretPrompt":
          set((s) => ({ prompts: [...s.prompts, { ...e, type: "secret" }] }));
          break;
        case "promptClosed":
          set((s) => ({ prompts: s.prompts.filter((p) => p.id !== e.id) }));
          break;
        case "notice":
          set((s) => ({ notices: [...s.notices, { id: e.id, session: e.session, text: e.text }] }));
          break;
        case "noticeDone":
          set((s) => ({ notices: s.notices.filter((n) => n.id !== e.id) }));
          break;
        case "transfers":
          set({ jobs: e.jobs });
          break;
        case "tunnels":
          update(e.session, () => ({ tunnels: e.tunnels }));
          break;
        case "terminalExit":
          window.dispatchEvent(new CustomEvent("terminal-exit", { detail: e.terminal }));
          break;
        case "passwordPrompt":
          window.dispatchEvent(new CustomEvent("password-prompt", { detail: { terminal: e.terminal, visible: e.visible } }));
          break;
      }
    },
  };
});

export const isConnected = (t: SessionTab | undefined) => t?.status.state === "connected";

/** Editor values for saving a quick connection as a named connection. */
export function quickToDraft(t: SessionTab) {
  return { name: t.label, host: t.quick?.host ?? "", port: t.quick?.port ?? null, username: t.quick?.user ?? null, mac: t.quick?.mac ?? null };
}
