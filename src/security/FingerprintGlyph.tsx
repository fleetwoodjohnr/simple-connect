/**
 * A deterministic picture of a host-key fingerprint, in the spirit of
 * OpenSSH's VisualHostKey: the same key always draws the same glyph, so a
 * changed key is noticeable at a glance. It supplements, never replaces, the
 * full fingerprint text.
 */
export function fingerprintBytes(fingerprint: string): number[] {
  const b64 = fingerprint.replace(/^SHA256:/, "");
  try {
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    return [...atob(padded)].map((c) => c.charCodeAt(0));
  } catch {
    return [];
  }
}

export function FingerprintGlyph({ fingerprint, size = 64, label }: { fingerprint: string; size?: number; label?: string }) {
  const bytes = fingerprintBytes(fingerprint);
  if (bytes.length < 8) return null;
  const n = 7;
  const half = Math.ceil(n / 2);
  // Hues stay in blue–magenta so the glyph never reads as a trust colour.
  const hue = 190 + (bytes[0] % 140);
  const hue2 = 190 + (bytes[1] % 140);
  const cells: { x: number; y: number; alt: boolean }[] = [];
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < half; x++) {
      const i = y * half + x;
      const on = (bytes[2 + (i >> 3)] >> (i & 7)) & 1;
      if (!on) continue;
      const alt = ((bytes[(i + 7) % bytes.length] >> 3) & 1) === 1;
      cells.push({ x, y, alt });
      if (x !== n - 1 - x) cells.push({ x: n - 1 - x, y, alt });
    }
  }
  return (
    <svg
      width={size}
      height={size}
      viewBox={`-1 -1 ${n + 2} ${n + 2}`}
      role="img"
      aria-label={label ?? "Fingerprint picture"}
      className="shrink-0 rounded-[18%] bg-ink"
    >
      {cells.map((c, i) => (
        <rect key={i} x={c.x + 0.08} y={c.y + 0.08} width={0.84} height={0.84} rx={0.2} fill={`hsl(${c.alt ? hue2 : hue} 62% 62%)`} />
      ))}
    </svg>
  );
}
