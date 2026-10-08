import { describe, expect, it } from "vitest";
import { findProfile, matchesFilter } from "./connections";
import type { Profile } from "../types/ipc";

const profile = (over: Partial<Profile>): Profile => ({
  id: "1",
  name: "Atlas",
  host: "192.168.1.25",
  port: null,
  username: "jrf",
  groupId: null,
  auth: "auto",
  identityFile: null,
  jump: [],
  startDir: null,
  keepaliveSecs: null,
  terminalTheme: null,
  color: null,
  icon: null,
  tags: ["Jetson", "Development"],
  mac: "48:b0:2d:00:00:01",
  reusePassword: null,
  favorite: false,
  legacyCrypto: false,
  hasSavedSecret: false,
  lastUsedAt: null,
  ...over,
});

describe("connection search", () => {
  it("matches name, address, MAC and tags", () => {
    const p = profile({});
    for (const q of ["atlas", "192.168.1", "48:b0", "jetson", "JRF"]) expect(matchesFilter(p, q)).toBe(true);
    expect(matchesFilter(p, "server")).toBe(false);
  });

  it("filters by exact tag with #", () => {
    expect(matchesFilter(profile({}), "#jetson")).toBe(true);
    expect(matchesFilter(profile({}), "#jet")).toBe(false);
  });
});

describe("finding the saved device", () => {
  const atlas = profile({});
  const server = profile({ id: "2", name: "Home Server", host: "192.168.1.30", mac: null, port: 2222 });

  it("prefers the MAC address, so a device is recognised after its IP changes", () => {
    expect(findProfile([atlas, server], { host: "192.168.1.99", mac: "48:b0:2d:00:00:01" })?.name).toBe("Atlas");
  });

  it("falls back to host, port and user", () => {
    expect(findProfile([atlas, server], { host: "192.168.1.30", port: 2222 })?.name).toBe("Home Server");
    expect(findProfile([atlas, server], { host: "192.168.1.30", port: 22 })).toBeUndefined();
    expect(findProfile([atlas, server], { host: "192.168.1.25", port: 22, user: "jrf" })?.name).toBe("Atlas");
    expect(findProfile([atlas, server], { host: "192.168.1.25", user: "root" })).toBeUndefined();
  });
});

import { friendlyHost } from "../connections/NetworkScanner";

describe("device names", () => {
  it("drops local suffixes and names the gateway", () => {
    expect(friendlyHost("atlas.local")).toBe("atlas");
    expect(friendlyHost("nas.lan")).toBe("nas");
    expect(friendlyHost("_gateway")).toBe("Router (gateway)");
    expect(friendlyHost(null)).toBeNull();
  });
});
