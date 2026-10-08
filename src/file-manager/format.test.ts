import { describe, expect, it } from "vitest";
import { displayName, formatBytes, formatMode, joinPath, parentPath, sortEntries } from "./format";
import type { Entry } from "../types/ipc";

const e = (name: string, kind: Entry["kind"] = "file", size = 0): Entry => ({ name, kind, targetIsDir: false, size, modified: null, mode: null });

describe("file manager formatting", () => {
  it("makes hostile names visible", () => {
    expect(displayName("normal.txt")).toEqual({ text: "normal.txt", suspicious: false });
    expect(displayName("new\nline").text).toBe("new␤line");
    expect(displayName("‮gpj.exe")).toEqual({ text: "⟨U+202E⟩gpj.exe", suspicious: true });
  });

  it("formats sizes, modes and paths", () => {
    expect(formatBytes(999)).toBe("999 B");
    expect(formatBytes(2_100_000_000)).toBe("2.1 GB");
    expect(formatMode(0o755, "dir")).toBe("drwxr-xr-x");
    expect(formatMode(0o640, "file")).toBe("-rw-r-----");
    expect(joinPath("/", "etc")).toBe("/etc");
    expect(parentPath("/home/u/")).toBe("/home");
    expect(parentPath("/home")).toBe("/");
  });

  it("sorts folders first, naturally", () => {
    const sorted = sortEntries([e("b10"), e("dir", "dir"), e("b2"), e("A")], "name", true).map((x) => x.name);
    expect(sorted).toEqual(["dir", "A", "b2", "b10"]);
  });
});
