import type { Profile, QuickConnect, SshConfigHost } from "./ipc";

/** What the user asked to connect to. */
export type ConnectTarget =
  | { kind: "profile"; profile: Profile }
  | { kind: "quick"; input: string; dest: QuickConnect; mac?: string | null }
  | { kind: "alias"; host: SshConfigHost };
