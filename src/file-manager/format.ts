import type { Entry } from "../types/ipc";

const UNITS = ["B", "KB", "MB", "GB", "TB"];

export function formatBytes(n: number): string {
  let i = 0;
  let v = n;
  while (v >= 1000 && i < UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)} ${UNITS[i]}`;
}

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
export const formatTime = (secs: number | null) => (secs ? dateFmt.format(new Date(secs * 1000)) : "");

export function formatMode(mode: number | null, kind: Entry["kind"]): string {
  if (mode === null) return "";
  const t = kind === "dir" ? "d" : kind === "symlink" ? "l" : "-";
  const bits = "rwxrwxrwx";
  return t + [...bits].map((c, i) => (mode & (1 << (8 - i)) ? c : "-")).join("");
}

// Bidi overrides/isolates can make "gpj.exe" display as "exe.jpg".
const SUSPICIOUS = /[\u0000-\u001f\u007f‪-‮⁦-⁩‎‏]/;

/** Untrusted file names are shown with control and bidi characters made visible. */
export function displayName(name: string): { text: string; suspicious: boolean } {
  if (!SUSPICIOUS.test(name)) return { text: name, suspicious: false };
  const text = [...name]
    .map((c) => {
      const code = c.codePointAt(0)!;
      if (c === "\n") return "␤";
      if (code < 0x20 || code === 0x7f) return "�";
      if (SUSPICIOUS.test(c)) return `⟨U+${code.toString(16).toUpperCase().padStart(4, "0")}⟩`;
      return c;
    })
    .join("");
  return { text, suspicious: true };
}

export function joinPath(dir: string, name: string): string {
  return dir.endsWith("/") ? dir + name : `${dir}/${name}`;
}

export function parentPath(path: string): string {
  const trimmed = path.replace(/\/+$/, "");
  const i = trimmed.lastIndexOf("/");
  return i <= 0 ? "/" : trimmed.slice(0, i);
}

export type SortKey = "name" | "size" | "modified";

export function sortEntries(entries: Entry[], key: SortKey, asc: boolean): Entry[] {
  const dir = (e: Entry) => e.kind === "dir" || e.targetIsDir;
  return [...entries].sort((a, b) => {
    if (dir(a) !== dir(b)) return dir(a) ? -1 : 1;
    const r =
      key === "size" ? a.size - b.size : key === "modified" ? (a.modified ?? 0) - (b.modified ?? 0) : a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
    return asc ? r : -r;
  });
}

const TEXT_EXT = /\.(txt|md|json|ya?ml|toml|ini|conf|cfg|env|py|js|mjs|cjs|jsx|ts|tsx|rs|go|c|h|cpp|java|rb|php|sh|bash|zsh|fish|service|timer|socket|mount|target|xml|html|css|sql|log|csv|properties|lua|pl)$/i;
const TEXT_NAMES = /^(Dockerfile|Containerfile|Makefile|\.?[a-z]*rc|\.profile|\.gitignore|authorized_keys|known_hosts|hosts|crontab|fstab|config)$/i;

export const looksLikeText = (name: string) => TEXT_EXT.test(name) || TEXT_NAMES.test(name);
