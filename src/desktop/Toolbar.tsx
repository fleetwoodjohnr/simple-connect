import type { ReactNode } from "react";
import { DropdownMenu } from "radix-ui";
import { ClipboardCopy, ClipboardPaste, FolderTree, Gauge, Keyboard, LogOut, Maximize2, Minimize2, Power, Scaling, Unplug } from "lucide-react";
import type { DesktopQuality, DesktopScale } from "../types/ipc";
import { IconButton } from "../components/ui/IconButton";
import { menuContent, menuItem, menuSeparator } from "../components/ui/Menu";
import { formatBytes } from "../file-manager/format";
import { KEY_COMBOS, type SpecialKey } from "./keys";

const SCALES: { id: DesktopScale; label: string; hint: string }[] = [
  { id: "fit", label: "Fit to window", hint: "Scale the remote screen to fit" },
  { id: "actual", label: "Actual size", hint: "One remote pixel per pixel, with scroll bars" },
  { id: "remote", label: "Resize remote desktop", hint: "Change the remote resolution to match the window, where supported" },
];

const QUALITIES: { id: DesktopQuality; label: string }[] = [
  { id: "auto", label: "Automatic" },
  { id: "high", label: "High quality (fast networks)" },
  { id: "balanced", label: "Balanced" },
  { id: "low", label: "Low bandwidth" },
];

function Menu({ label, icon, children }: { label: string; icon: ReactNode; children: ReactNode }) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          aria-label={label}
          title={label}
          className="grid size-8 place-items-center rounded-control text-muted outline-none hover:bg-hover hover:text-text focus-visible:ring-2 focus-visible:ring-accent data-[state=open]:bg-hover"
        >
          {icon}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="start" sideOffset={4} className={menuContent}>
          {children}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function Choice<T extends string>({ value, current, onSelect, children }: { value: T; current: T; onSelect: (v: T) => void; children: ReactNode }) {
  return (
    <DropdownMenu.RadioItem value={value} onSelect={() => onSelect(value)} className={`${menuItem} pl-7 relative`} aria-checked={value === current}>
      <DropdownMenu.ItemIndicator className="absolute left-2 size-1.5 rounded-full bg-accent" />
      {children}
    </DropdownMenu.RadioItem>
  );
}

/** Connection health: colour only signals latency (see the design tokens). */
function Health({ protocol, latencyMs, bytesPerSec }: { protocol?: string; latencyMs?: number; bytesPerSec: number }) {
  const tone = latencyMs === undefined ? "bg-faint" : latencyMs < 40 ? "bg-ok" : latencyMs < 120 ? "bg-warn" : "bg-bad";
  return (
    <span className="flex items-center gap-2 px-2 text-xs text-muted" role="status" title="Connection to the remote desktop">
      <span className={`size-2 rounded-full ${tone}`} aria-hidden />
      {protocol?.toUpperCase()}
      {latencyMs !== undefined && <span>{latencyMs} ms</span>}
      <span className="tabular-nums text-faint">{formatBytes(bytesPerSec)}/s</span>
    </span>
  );
}

export function Toolbar(p: {
  title: string;
  protocol?: "vnc" | "rdp";
  latencyMs?: number;
  bytesPerSec: number;
  scale: DesktopScale;
  canResizeRemote: boolean;
  onScale: (s: DesktopScale) => void;
  quality: DesktopQuality;
  effectiveQuality: Exclude<DesktopQuality, "auto">;
  onQuality: (q: DesktopQuality) => void;
  clipboardSync: boolean;
  onClipboardSync: (on: boolean) => void;
  remoteClipboard: boolean;
  onSendClipboard: () => void;
  onCopyRemote: () => void;
  onKeys: (keys: SpecialKey[]) => void;
  onFiles: () => void;
  fullscreen: boolean;
  onFullscreen: () => void;
  onDisconnect: () => void;
  onEndVirtual?: () => void;
}) {
  return (
    <div role="toolbar" aria-label="Remote desktop" className="flex h-10 shrink-0 items-center gap-0.5 border-b border-line bg-panel px-2">
      <span className="mr-2 truncate font-medium" title={p.title}>
        {p.title}
      </span>
      <Health protocol={p.protocol} latencyMs={p.latencyMs} bytesPerSec={p.bytesPerSec} />
      <span className="mx-1 h-5 w-px bg-line" aria-hidden />

      <Menu label="Scaling" icon={<Scaling size={15} />}>
        <DropdownMenu.RadioGroup value={p.scale}>
          {SCALES.filter((s) => s.id !== "remote" || p.canResizeRemote).map((s) => (
            <Choice key={s.id} value={s.id} current={p.scale} onSelect={p.onScale}>
              <span title={s.hint}>{s.label}</span>
            </Choice>
          ))}
        </DropdownMenu.RadioGroup>
      </Menu>
      <Menu label="Image quality" icon={<Gauge size={15} />}>
        <DropdownMenu.RadioGroup value={p.quality}>
          {QUALITIES.map((q) => (
            <Choice key={q.id} value={q.id} current={p.quality} onSelect={p.onQuality}>
              {q.label}
              {q.id === "auto" && <span className="ml-auto text-xs text-faint">{p.effectiveQuality}</span>}
            </Choice>
          ))}
        </DropdownMenu.RadioGroup>
      </Menu>
      <Menu label="Clipboard" icon={<ClipboardPaste size={15} />}>
        <DropdownMenu.Item onSelect={p.onSendClipboard} className={menuItem}>
          <ClipboardPaste size={14} /> Send my clipboard to the remote computer
        </DropdownMenu.Item>
        <DropdownMenu.Item onSelect={p.onCopyRemote} disabled={!p.remoteClipboard} className={menuItem}>
          <ClipboardCopy size={14} /> Copy the remote clipboard
        </DropdownMenu.Item>
        <DropdownMenu.Separator className={menuSeparator} />
        <DropdownMenu.CheckboxItem checked={p.clipboardSync} onCheckedChange={p.onClipboardSync} className={`${menuItem} pl-7 relative`}>
          <DropdownMenu.ItemIndicator className="absolute left-2 text-accent">✓</DropdownMenu.ItemIndicator>
          Share the clipboard automatically
        </DropdownMenu.CheckboxItem>
      </Menu>
      <Menu label="Send keys" icon={<Keyboard size={15} />}>
        {KEY_COMBOS.map((c) => (
          <DropdownMenu.Item key={c.label} onSelect={() => p.onKeys(c.keys)} className={menuItem}>
            {c.label}
          </DropdownMenu.Item>
        ))}
      </Menu>
      <IconButton label="Files on this computer" onClick={p.onFiles}>
        <FolderTree size={15} />
      </IconButton>

      <span className="ml-auto" />
      <IconButton label={p.fullscreen ? "Exit full screen" : "Full screen"} shortcut="Ctrl+Alt+Enter" onClick={p.onFullscreen}>
        {p.fullscreen ? <Minimize2 size={15} /> : <Maximize2 size={15} />}
      </IconButton>
      {p.onEndVirtual && (
        <IconButton label="Sign out of the virtual desktop" onClick={p.onEndVirtual}>
          <LogOut size={15} />
        </IconButton>
      )}
      <IconButton label="Disconnect remote desktop" onClick={p.onDisconnect}>
        {p.onEndVirtual ? <Unplug size={15} /> : <Power size={15} />}
      </IconButton>
    </div>
  );
}
