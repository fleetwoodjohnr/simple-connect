import type { DesktopQuality } from "../types/ipc";

/**
 * Quality tier for "Automatic", from the latency measured when connecting.
 * ponytail: one measurement per connection; re-measure periodically if users
 * on changing networks (Wi-Fi to VPN) report the wrong tier sticking.
 */
export function autoQuality(latencyMs?: number): Exclude<DesktopQuality, "auto"> {
  if (latencyMs === undefined) return "balanced";
  return latencyMs < 40 ? "high" : latencyMs < 120 ? "balanced" : "low";
}
