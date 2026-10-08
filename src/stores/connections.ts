import { create } from "zustand";
import { api } from "../services/ipc";
import type { Group, Profile, ProfileDraft, SshConfigHost } from "../types/ipc";
import { formatDestination } from "../connections/RoutePreview";

interface ConnectionsState {
  profiles: Profile[];
  groups: Group[];
  sshConfigHosts: SshConfigHost[];
  loaded: boolean;
  load: () => Promise<void>;
  save: (draft: ProfileDraft, id?: string) => Promise<Profile>;
  remove: (id: string) => Promise<void>;
  setFavorite: (id: string, favorite: boolean) => Promise<void>;
  move: (id: string, groupId: string | null) => Promise<void>;
  createGroup: (name: string) => Promise<Group>;
  renameGroup: (id: string, name: string) => Promise<void>;
  deleteGroup: (id: string) => Promise<void>;
}

export const useConnections = create<ConnectionsState>((set, get) => {
  const refresh = async () => {
    const [profiles, groups] = await Promise.all([api.listProfiles(), api.listGroups()]);
    set({ profiles, groups });
  };
  return {
    profiles: [],
    groups: [],
    sshConfigHosts: [],
    loaded: false,
    load: async () => {
      const [, sshConfigHosts] = await Promise.all([refresh(), api.listSshConfigHosts()]);
      set({ sshConfigHosts, loaded: true });
    },
    save: async (draft, id) => {
      const saved = id ? await api.updateProfile(id, draft) : await api.createProfile(draft);
      await refresh();
      return saved;
    },
    remove: async (id) => {
      await api.deleteProfile(id);
      await refresh();
    },
    setFavorite: async (id, favorite) => {
      await api.setFavorite(id, favorite);
      set({ profiles: get().profiles.map((p) => (p.id === id ? { ...p, favorite } : p)) });
    },
    move: async (id, groupId) => {
      await api.moveProfile(id, groupId);
      set({ profiles: get().profiles.map((p) => (p.id === id ? { ...p, groupId } : p)) });
    },
    createGroup: async (name) => {
      const g = await api.createGroup(name);
      await refresh();
      return g;
    },
    renameGroup: async (id, name) => {
      await api.renameGroup(id, name);
      await refresh();
    },
    deleteGroup: async (id) => {
      await api.deleteGroup(id);
      await refresh();
    },
  };
});

/** Case-insensitive match on name, host, user, MAC and tags; `#tag` matches a tag exactly. */
export function matchesFilter(p: Profile, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  if (needle.startsWith("#")) return p.tags.some((t) => t.toLowerCase() === needle.slice(1));
  return [p.name, p.host, p.username ?? "", p.mac ?? "", ...p.tags].some((s) => s.toLowerCase().includes(needle));
}

/** The saved connection for a device or address: same MAC first, then same host (and port/user when given). */
export function findProfile(
  profiles: Profile[],
  target: { host?: string | null; port?: number | null; user?: string | null; mac?: string | null },
): Profile | undefined {
  if (target.mac) {
    const byMac = profiles.find((p) => p.mac === target.mac);
    if (byMac) return byMac;
  }
  const host = target.host?.toLowerCase();
  return profiles.find(
    (p) =>
      p.host.toLowerCase() === host &&
      (target.port == null || (p.port ?? 22) === target.port) &&
      (target.user == null || p.username === null || p.username === target.user),
  );
}

export function profileToDraft(p: Profile): ProfileDraft {
  return {
    name: p.name,
    host: p.host,
    port: p.port,
    username: p.username,
    groupId: p.groupId,
    auth: p.auth,
    identityFile: p.identityFile,
    jump: p.jump.length ? p.jump.map(formatDestination).join(",") : null,
    startDir: p.startDir,
    keepaliveSecs: p.keepaliveSecs,
    terminalTheme: p.terminalTheme,
    color: p.color,
    icon: p.icon,
    tags: p.tags,
    mac: p.mac,
    reusePassword: p.reusePassword,
  };
}
