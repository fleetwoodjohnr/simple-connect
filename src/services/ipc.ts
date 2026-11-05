import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  AppInfo,
  CmdError,
  Entry,
  Group,
  ImportReport,
  JobView,
  KeyInfo,
  KeyKind,
  Profile,
  ProfileDraft,
  QuickConnect,
  Settings,
  SshConfigHost,
  SysInfo,
  TrustedHost,
  Tunnel,
  TunnelSpec,
  LocalNetwork,
  ScanEvent,
  DesktopInput,
  DesktopOpenRequest,
  DesktopProbe,
} from "../types/ipc";

export function isCmdError(e: unknown): e is CmdError {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

export function errorMessage(e: unknown, fallback = "Something went wrong."): string {
  return isCmdError(e) ? e.message : fallback;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw isCmdError(e) ? e : ({ code: "internal", message: "Something went wrong.", details: String(e) } satisfies CmdError);
  }
}

export const api = {
  prepareUpdateInstall: () => call<void>("prepare_update_install"),
  appInfo: () => call<AppInfo>("app_info"),
  parseQuickConnect: (input: string) => call<QuickConnect>("parse_quick_connect", { input }),
  getSettings: () => call<Settings>("get_settings"),
  saveSettings: (settings: Settings) => call<Settings>("save_settings", { settings }),

  listProfiles: () => call<Profile[]>("list_profiles"),
  createProfile: (draft: ProfileDraft) => call<Profile>("create_profile", { draft }),
  updateProfile: (id: string, draft: ProfileDraft) => call<Profile>("update_profile", { id, draft }),
  deleteProfile: (id: string) => call<void>("delete_profile", { id }),
  forgetSavedPassword: (id: string, desktop = false) => call<void>("forget_saved_password", { id, desktop }),
  setFavorite: (id: string, favorite: boolean) => call<void>("set_favorite", { id, favorite }),
  setLegacyCrypto: (id: string, allow: boolean) => call<void>("set_legacy_crypto", { id, allow }),
  moveProfile: (id: string, groupId: string | null) => call<void>("move_profile", { id, groupId }),
  listGroups: () => call<Group[]>("list_groups"),
  createGroup: (name: string) => call<Group>("create_group", { name }),
  renameGroup: (id: string, name: string) => call<void>("rename_group", { id, name }),
  deleteGroup: (id: string) => call<void>("delete_group", { id }),
  listSshConfigHosts: () => call<SshConfigHost[]>("list_ssh_config_hosts"),

  connectProfile: (id: string) => call<string>("connect_profile", { id }),
  connectQuick: (input: string) => call<string>("connect_quick", { input }),
  connectAlias: (alias: string) => call<string>("connect_alias", { alias }),
  disconnect: (session: string) => call<void>("disconnect", { session }),
  reconnect: (session: string) => call<void>("reconnect", { session }),
  answerHostKey: (id: number, trust: boolean, typedHost?: string) => call<void>("answer_host_key", { id, trust, typedHost: typedHost ?? null }),
  answerSecret: (id: number, value: string | null, save: boolean) => call<void>("answer_secret", { id, value, save }),
  systemInfo: (session: string) => call<SysInfo>("system_info", { session }),

  /** With `recipe`, runs that remote desktop setup step (an id from the probe) in the terminal. */
  openTerminal: (session: string, cols: number, rows: number, onOutput: Channel<ArrayBuffer>, recipe: string | null = null) =>
    call<string>("open_terminal", { session, cols, rows, onOutput, recipe }),
  terminalWrite: (session: string, terminal: string, data: Uint8Array) =>
    call<void>("terminal_write", { session, terminal, data: Array.from(data) }),
  terminalResize: (session: string, terminal: string, cols: number, rows: number) =>
    call<void>("terminal_resize", { session, terminal, cols, rows }),
  terminalAck: (session: string, terminal: string, bytes: number) => call<void>("terminal_ack", { session, terminal, bytes }),
  closeTerminal: (session: string, terminal: string) => call<void>("close_terminal", { session, terminal }),
  /** Sends the login password to a waiting sudo prompt (it never leaves the backend). */
  terminalSendPassword: (session: string, terminal: string) => call<void>("terminal_send_password", { session, terminal }),

  desktopProbe: (session: string) => call<DesktopProbe>("desktop_probe", { session }),
  desktopOpen: (session: string, request: DesktopOpenRequest, onData: Channel<ArrayBuffer>) =>
    call<string>("desktop_open", { session, request, onData }),
  desktopWrite: (session: string, desktop: string, data: Uint8Array) => call<void>("desktop_write", { session, desktop, data: Array.from(data) }),
  desktopAck: (session: string, desktop: string, bytes: number) => call<void>("desktop_ack", { session, desktop, bytes }),
  desktopInput: (session: string, desktop: string, events: DesktopInput[]) => call<void>("desktop_input", { session, desktop, events }),
  desktopResize: (session: string, desktop: string, width: number, height: number) =>
    call<void>("desktop_resize", { session, desktop, width, height }),
  desktopClipboard: (session: string, desktop: string, text: string) => call<void>("desktop_clipboard", { session, desktop, text }),
  desktopClose: (session: string, desktop: string) => call<void>("desktop_close", { session, desktop }),
  desktopEndVirtual: (session: string) => call<void>("desktop_end_virtual", { session }),

  listNetworks: () => call<LocalNetwork[]>("list_networks"),
  scanNetwork: (networkId: string, port: number, onEvent: Channel<ScanEvent>) => call<number>("scan_network", { networkId, port, onEvent }),
  cancelScan: () => call<void>("cancel_scan"),

  remoteHome: (session: string) => call<string>("remote_home", { session }),
  listRemote: (session: string, path: string) => call<Entry[]>("list_remote", { session, path }),
  remoteMkdir: (session: string, path: string) => call<void>("remote_mkdir", { session, path }),
  remoteRename: (session: string, from: string, to: string) => call<void>("remote_rename", { session, from, to }),
  remoteDelete: (session: string, path: string) => call<void>("remote_delete", { session, path }),
  remoteCopy: (session: string, from: string, to: string) => call<void>("remote_copy", { session, from, to }),
  remoteChmod: (session: string, path: string, mode: number) => call<void>("remote_chmod", { session, path, mode }),
  readRemoteText: (session: string, path: string) => call<string>("read_remote_text", { session, path }),
  writeRemoteText: (session: string, path: string, content: string) => call<void>("write_remote_text", { session, path, content }),
  localHome: () => call<string>("local_home"),
  listLocal: (path: string) => call<Entry[]>("list_local", { path }),
  localMkdir: (path: string) => call<void>("local_mkdir", { path }),
  localRename: (from: string, to: string) => call<void>("local_rename", { from, to }),
  localTrash: (path: string) => call<void>("local_trash", { path }),
  enqueueUpload: (session: string, localPaths: string[], remoteDir: string) => call<void>("enqueue_upload", { session, localPaths, remoteDir }),
  enqueueDownload: (session: string, remotePaths: string[], localDir: string) =>
    call<void>("enqueue_download", { session, remotePaths, localDir }),
  listTransfers: () => call<JobView[]>("list_transfers"),
  transferAction: (id: number, action: "pause" | "resume" | "cancel" | "retry") => call<void>("transfer_action", { id, action }),
  resolveConflict: (id: number, choice: "overwrite" | "skip" | "keepBoth", applyToAll: boolean) =>
    call<void>("resolve_conflict", { id, choice, applyToAll }),
  clearTransfers: () => call<void>("clear_transfers"),

  addTunnel: (session: string, spec: TunnelSpec) => call<Tunnel>("add_tunnel", { session, spec }),
  removeTunnel: (session: string, id: string) => call<void>("remove_tunnel", { session, id }),
  listTunnels: (session: string) => call<Tunnel[]>("list_tunnels", { session }),

  listKeys: () => call<KeyInfo[]>("list_keys"),
  generateKey: (kind: KeyKind, name: string, comment: string, passphrase: string) =>
    call<KeyInfo>("generate_key", { kind, name, comment, passphrase }),
  changeKeyPassphrase: (path: string, old: string, newPassphrase: string) => call<void>("change_key_passphrase", { path, old, new: newPassphrase }),
  importKey: (source: string, name: string, passphrase: string) => call<KeyInfo>("import_key", { source, name, passphrase }),
  exportPublicKey: (path: string, destination: string) => call<void>("export_public_key", { path, destination }),

  lockApp: () => call<void>("lock_app"),
  unlockApp: (password: string) => call<void>("unlock_app", { password }),
  setLockPassword: (current: string | null, next: string | null) => call<void>("set_lock_password", { current, new: next }),
  enableVault: (password: string) => call<void>("enable_vault", { password }),
  disableVault: (password: string) => call<void>("disable_vault", { password }),
  changeVaultPassword: (current: string, next: string) => call<void>("change_vault_password", { current, new: next }),
  listKnownHosts: () => call<TrustedHost[]>("list_known_hosts"),
  forgetKnownHost: (host: string) => call<void>("forget_known_host", { host }),
  copyText: (text: string) => call<void>("copy_text", { text }),
  pasteText: () => call<string>("paste_text"),
  logFolder: () => call<string>("log_folder"),
  clearLogs: () => call<void>("clear_logs"),

  exportProfiles: (destination: string, backupPassword: string | null) => call<void>("export_profiles", { destination, backupPassword }),
  importProfiles: (source: string, password: string | null) => call<ImportReport>("import_profiles", { source, password }),
};
