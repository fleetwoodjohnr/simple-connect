import { describe, expect, it } from "vitest";
import { scancode } from "./keymap";
import { SPECIAL_KEYS } from "./keys";
import { autoQuality } from "./quality";

describe("scan codes", () => {
  it("maps physical keys, extended ones flagged", () => {
    expect(scancode("KeyA")).toEqual({ scancode: 0x1e, extended: false });
    expect(scancode("Enter")).toEqual({ scancode: 0x1c, extended: false });
    expect(scancode("NumpadEnter")).toEqual({ scancode: 0x1c, extended: true });
    expect(scancode("ArrowLeft")).toEqual({ scancode: 0x4b, extended: true });
    expect(scancode("Fn")).toBeNull();
  });
  it("agrees with the toolbar's special keys", () => {
    for (const k of Object.values(SPECIAL_KEYS)) expect(scancode(k.code)).toEqual({ scancode: k.scancode, extended: k.extended });
  });
});

describe("automatic quality", () => {
  it("follows latency", () => {
    expect(autoQuality(5)).toBe("high");
    expect(autoQuality(80)).toBe("balanced");
    expect(autoQuality(300)).toBe("low");
    expect(autoQuality(undefined)).toBe("balanced");
  });
});
