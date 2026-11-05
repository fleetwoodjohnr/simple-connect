// Mirrors of the Rust IPC types (crates/core, src-tauri/src/commands).

export interface CmdError {
  code: string;
  message: string;
  details?: string | null;
  fields?: FieldError[] | null;
}

export interface AppInfo {
  version: string;
  openssh: string | null;
  startupError: string | null;
  keyringAvailable: boolean;
  locked: boolean;
  vaultExists: boolean;
  lockConfigured: boolean;
}

export interface JumpHop {
  user: string | null;
  host: string;
  port: number | null;
}

export interface QuickConnect {
  user: string | null;
  host: string;
  port: number | null;
  jump: JumpHop[];
  identityFile: string | null;
}

export interface FieldError {
  field: string;
  message: string;
}

export type AuthMethod = "auto" | "password" | "key" | "agent";

export interface ProfileDraft {
  name: string;
  host: string;
  port: number | null;
  username: string | null;
  groupId: string | null;
  auth: AuthMethod;
  identityFile: string | null;
  jump: string | null;
  startDir: string | null;
  keepaliveSecs: number | null;
  terminalTheme: string | null;
  color: string | null;
  icon: string | null;
  tags: string[];
  /** Hardware address of a device found on the network. */
  mac: string | null;
  /** Offer the login password at sudo prompts; null follows the app setting. */
  reusePassword: boolean | null;
  /** Remote desktop sign-in name; null uses the SSH user. */
  rdUser: string | null;
  /** Preferred remote desktop method; null chooses automatically. */
  rdMethod: DesktopMethod | null;
}

export interface Profile extends Omit<ProfileDraft, "jump"> {
  id: string;
  jump: JumpHop[];
  favorite: boolean;
  legacyCrypto: boolean;
  hasSavedSecret: boolean;
  hasSavedDesktopSecret: boolean;
  lastUsedAt: number | null;
}

export interface Group {
  id: string;
  name: string;
}

export interface SshConfigHost {
  alias: string;
  hostName: string | null;
  user: string | null;
  port: number | null;
  identityFile: string | null;
  proxyJump: string | null;
}

// ---- sessions ---------------------------------------------------------------

export type SessionStatus =
  | { state: "connecting" }
  | { state: "authenticating" }
  | { state: "connected" }
  | { state: "reconnecting"; attempt: number; delaySecs: number }
  | { state: "disconnected" }
  | { state: "failed" };

export interface SecurityInfo {
  remoteAddress: string | null;
  serverSoftware: string | null;
  kex: string | null;
  hostKeyAlgorithm: string | null;
  hostKeyFingerprint: string | null;
  cipher: string | null;
  mac: string | null;
  authMethod: string | null;
}

export interface ConnectFailure {
  kind: string;
  message: string;
  details: string;
}

export interface KnownKey {
  keyType: string;
  fingerprint: string;
  file: string;
}

export type SecretPromptKind = "password" | "passphrase" | "pin" | "server" | "confirm";

export type JobState = "queued" | "running" | "paused" | "conflict" | "done" | "skipped" | "failed" | "cancelled";

export interface JobView {
  id: number;
  session: string;
  direction: "upload" | "download";
  name: string;
  local: string;
  remote: string;
  size: number;
  done: number;
  state: JobState;
  error: string | null;
  verified: boolean | null;
  bytesPerSec: number;
}

export type TunnelKind = "local" | "remote" | "dynamic";

export interface TunnelSpec {
  kind: TunnelKind;
  bindAddress: string;
  bindPort: number;
  targetHost: string | null;
  targetPort: number | null;
  allowExternal: boolean;
}

export interface Tunnel {
  id: string;
  spec: TunnelSpec;
  active: boolean;
  error: string | null;
}

export type UiEvent =
  | { type: "session"; session: string; label: string; status: SessionStatus; info: SecurityInfo | null; failure: ConnectFailure | null }
  | {
      type: "hostKeyPrompt";
      id: number;
      session: string;
      host: string;
      address: string | null;
      keyType: string;
      fingerprint: string;
      changed: boolean;
      previous: KnownKey[];
    }
  | { type: "secretPrompt"; id: number; session: string; kind: SecretPromptKind; prompt: string; canSave: boolean }
  | { type: "promptClosed"; id: number }
  | { type: "notice"; id: number; session: string; text: string }
  | { type: "noticeDone"; id: number }
  | { type: "terminalExit"; session: string; terminal: string }
  | { type: "transfers"; jobs: JobView[] }
  | { type: "tunnels"; session: string; tunnels: Tunnel[] }
  | { type: "passwordPrompt"; session: string; terminal: string; visible: boolean }
  | { type: "desktop"; session: string; desktop: string; state: DesktopState };

// ---- remote desktop ---------------------------------------------------------

export type DesktopMethod = "x11" | "wayland" | "virtual" | "vnc" | "rdp";
export type DesktopQuality = "auto" | "high" | "balanced" | "low";
export type DesktopScale = "fit" | "actual" | "remote";

export interface DesktopOffer {
  method: DesktopMethod;
  port: number | null;
  display: number | null;
  wayland: string | null;
  title: string;
  detail: string;
  recommended: boolean;
  signIn: boolean;
  running: boolean;
}

export interface DesktopSetup {
  recipe: string;
  title: string;
  detail: string;
  commands: string[];
}

export interface DesktopProbe {
  os: "linux" | "macos" | "windows" | "other";
  osName: string | null;
  user: string | null;
  jetson: boolean;
  offers: DesktopOffer[];
  setups: DesktopSetup[];
  notes: string[];
  sessions: { id: string; name: string }[];
}

export interface DesktopOpenRequest {
  method: DesktopMethod;
  port: number | null;
  display: number | null;
  wayland: string | null;
  session: string | null;
  width: number;
  height: number;
  user: string | null;
  quality: DesktopQuality;
}

export interface DesktopError {
  code: string;
  message: string;
  details: string | null;
}

export type DesktopState =
  | { state: "connecting"; step: "starting" | "connecting" | "signingIn" }
  | { state: "connected"; protocol: "vnc" | "rdp"; latencyMs: number }
  | { state: "closed"; error: DesktopError | null };

/** RDP input; keys are PC scan codes, positions are remote desktop pixels. */
export type DesktopInput =
  | { type: "key"; scancode: number; extended: boolean; down: boolean }
  | { type: "unicode"; ch: number; down: boolean }
  | { type: "mouse"; x: number; y: number }
  | { type: "button"; button: "left" | "middle" | "right" | "x1" | "x2"; down: boolean }
  | { type: "wheel"; delta: number; horizontal: boolean }
  | { type: "releaseAll" };

export interface DesktopSettings {
  quality: DesktopQuality;
  scale: DesktopScale;
  clipboardSync: boolean;
  uploadDir: string;
}

// ---- files ------------------------------------------------------------------

export interface Entry {
  name: string;
  kind: "file" | "dir" | "symlink" | "other";
  targetIsDir: boolean;
  size: number;
  modified: number | null;
  mode: number | null;
}

export interface SysInfo {
  hostname: string | null;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  uptimeSecs: number | null;
  cpus: number | null;
  memTotalKb: number | null;
  memAvailableKb: number | null;
  diskTotalKb: number | null;
  diskUsedKb: number | null;
  addresses: string[];
}

// ---- keys, hosts, settings ---------------------------------------------------

export interface KeyInfo {
  path: string;
  keyType: string;
  fingerprint: string;
  comment: string;
  publicKey: string;
  encrypted: boolean | null;
  hardware: boolean;
}

export type KeyKind = "ed25519" | "ed25519-sk" | "ecdsa" | "ecdsa-sk" | "rsa";

export interface TrustedHost {
  host: string;
  keyType: string;
  fingerprint: string;
}

export interface TerminalSettings {
  fontFamily: string;
  fontSize: number;
  lineHeight: number;
  theme: string;
  scrollback: number;
  cursorBlink: boolean;
  copyOnSelect: boolean;
  confirmMultilinePaste: boolean;
}

export interface Settings {
  autoCheckUpdates: boolean;
  autoReconnect: boolean;
  includeUserSshConfig: boolean;
  keepaliveSecs: number;
  connectTimeoutSecs: number;
  verifyChecksums: boolean;
  editorMaxMb: number;
  clipboardClearSecs: number;
  autoLockMinutes: number;
  lockOnSleep: boolean;
  lockOnSessionLock: boolean;
  credentialStorage: "keyring" | "vault";
  writeUserKnownHosts: boolean;
  showHiddenFiles: boolean;
  reuseSshPassword: boolean;
  terminal: TerminalSettings;
  remoteDesktop: DesktopSettings;
}

export interface ImportReport {
  imported: number;
  skipped: string[];
}

// ---- network discovery ------------------------------------------------------

export interface LocalNetwork {
  id: string;
  interface: string;
  address: string;
  cidr: string;
  scanCidr: string;
  hosts: number;
  preferred: boolean;
}

export type SshStatus = { state: "open"; software: string | null; os: string | null } | { state: "closed" } | { state: "unknown" };

export interface Device {
  ip: string;
  hostname: string | null;
  mac: string | null;
  ssh: SshStatus;
}

export type ScanEvent =
  | { type: "progress"; done: number; total: number }
  | { type: "device"; device: Device }
  | { type: "done"; found: number; cancelled: boolean };
