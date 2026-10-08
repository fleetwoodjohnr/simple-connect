import { describe, expect, it } from "vitest";
import { formatKeys, matches } from "./shortcuts";

const key = (k: string, mods: Partial<Record<"ctrlKey" | "metaKey" | "shiftKey" | "altKey", boolean>> = {}) => ({
  key: k,
  ctrlKey: false,
  metaKey: false,
  shiftKey: false,
  altKey: false,
  ...mods,
});

describe("shortcuts", () => {
  it("matches exact modifiers", () => {
    expect(matches(key("k", { ctrlKey: true }), "Mod+K", false)).toBe(true);
    expect(matches(key("K", { ctrlKey: true, shiftKey: true }), "Mod+Shift+K", false)).toBe(true);
    expect(matches(key("k", { ctrlKey: true, shiftKey: true }), "Mod+K", false)).toBe(false);
    expect(matches(key("k"), "Mod+K", false)).toBe(false);
    expect(matches(key("k", { metaKey: true }), "Mod+K", true)).toBe(true);
    expect(matches(key("k", { ctrlKey: true }), "Mod+K", true)).toBe(false);
    expect(matches(key(",", { ctrlKey: true }), "Mod+,", false)).toBe(true);
  });

  it("formats per platform", () => {
    expect(formatKeys("Mod+Shift+T", false)).toBe("Ctrl+Shift+T");
    expect(formatKeys("Mod+Shift+T", true)).toBe("⌘⇧T");
  });
});
