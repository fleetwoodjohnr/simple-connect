import { useSettings } from "../stores/settings";
import { useUi } from "../stores/ui";
import { TERMINAL_THEMES } from "../terminal/themes";
import { Choice, NumberRow, Row, Section, Toggle } from "./controls";
import { inputClass } from "../components/ui/Field";

export function AppearanceSettings() {
  const { theme, setTheme, textScale, setTextScale, motion, setMotion } = useUi();
  return (
    <Section title="Appearance">
      <Choice
        label="Theme"
        value={theme}
        onChange={setTheme}
        options={[
          { value: "dark", label: "Dark" },
          { value: "light", label: "Light" },
          { value: "system", label: "Match system" },
        ]}
      />
      <Choice
        label="Text size"
        value={textScale}
        onChange={setTextScale}
        options={[
          { value: 0.9, label: "Smaller" },
          { value: 1, label: "Default" },
          { value: 1.1, label: "Larger" },
          { value: 1.25, label: "Largest" },
        ]}
      />
      <Choice
        label="Motion"
        hint="Animations are also reduced when your system asks for it."
        value={motion}
        onChange={setMotion}
        options={[
          { value: "system", label: "Follow system" },
          { value: "reduce", label: "Reduce" },
        ]}
      />
    </Section>
  );
}

export function TerminalSettings() {
  const { settings, save } = useSettings();
  const t = settings.terminal;
  const set = (patch: Partial<typeof t>) => void save({ terminal: { ...t, ...patch } });
  return (
    <Section title="Terminal">
      <Row label="Font" hint="Any monospace font installed on this computer.">
        <input className={`${inputClass} w-48`} value={t.fontFamily} onChange={(e) => set({ fontFamily: e.target.value })} />
      </Row>
      <NumberRow label="Font size" value={t.fontSize} min={8} max={40} onChange={(fontSize) => set({ fontSize })} suffix="px" />
      <Choice
        label="Line spacing"
        value={t.lineHeight}
        onChange={(lineHeight) => set({ lineHeight })}
        options={[
          { value: 1, label: "Compact" },
          { value: 1.2, label: "Default" },
          { value: 1.4, label: "Relaxed" },
        ]}
      />
      <Choice
        label="Colour scheme"
        value={t.theme}
        onChange={(theme) => set({ theme })}
        options={[{ value: "auto", label: "Match app theme" }, ...Object.entries(TERMINAL_THEMES).map(([value, { label }]) => ({ value, label }))]}
      />
      <NumberRow label="Scrollback" value={t.scrollback} min={500} max={200000} onChange={(scrollback) => set({ scrollback })} suffix="lines" />
      <Toggle label="Blinking cursor" checked={t.cursorBlink} onChange={(cursorBlink) => set({ cursorBlink })} />
      <Toggle label="Copy on select" checked={t.copyOnSelect} onChange={(copyOnSelect) => set({ copyOnSelect })} />
      <Toggle
        label="Confirm multi-line paste"
        hint="Pasting several lines can run several commands at once."
        checked={t.confirmMultilinePaste}
        onChange={(confirmMultilinePaste) => set({ confirmMultilinePaste })}
      />
    </Section>
  );
}

export function ConnectionSettings() {
  const { settings, save } = useSettings();
  return (
    <Section title="Connections">
      <Toggle
        label="Reconnect automatically"
        hint="Retries with increasing delays when an established connection drops. Commands are never re-sent."
        checked={settings.autoReconnect}
        onChange={(autoReconnect) => void save({ autoReconnect })}
      />
      <NumberRow
        label="Keepalive interval"
        hint="How often to check that the server is still there. 0 turns it off."
        value={settings.keepaliveSecs}
        min={0}
        max={3600}
        onChange={(keepaliveSecs) => void save({ keepaliveSecs })}
        suffix="s"
      />
      <NumberRow label="Connection timeout" value={settings.connectTimeoutSecs} min={3} max={120} onChange={(connectTimeoutSecs) => void save({ connectTimeoutSecs })} suffix="s" />
      <Toggle
        label="Use ~/.ssh/config"
        hint="Show its host aliases and apply its settings (identity files, users, proxies). The file is never changed."
        checked={settings.includeUserSshConfig}
        onChange={(includeUserSshConfig) => void save({ includeUserSshConfig })}
      />
      <Toggle
        label="Verify transfers with checksums"
        hint="Compares SHA-256 with the server after each transfer, when the server supports it."
        checked={settings.verifyChecksums}
        onChange={(verifyChecksums) => void save({ verifyChecksums })}
      />
      <NumberRow
        label="Largest file to open in the editor"
        value={settings.editorMaxMb}
        min={1}
        max={100}
        onChange={(editorMaxMb) => void save({ editorMaxMb })}
        suffix="MB"
      />
    </Section>
  );
}

export function DesktopSettings() {
  const { settings, save } = useSettings();
  const d = settings.remoteDesktop;
  const set = (patch: Partial<typeof d>) => void save({ remoteDesktop: { ...d, ...patch } });
  return (
    <Section title="Remote desktop">
      <Choice
        label="Image quality"
        hint="Automatic picks from the connection's latency. You can change it while connected."
        value={d.quality}
        onChange={(quality) => set({ quality })}
        options={[
          { value: "auto", label: "Automatic" },
          { value: "high", label: "High" },
          { value: "balanced", label: "Balanced" },
          { value: "low", label: "Low bandwidth" },
        ]}
      />
      <Choice
        label="Scaling"
        value={d.scale}
        onChange={(scale) => set({ scale })}
        options={[
          { value: "fit", label: "Fit to window" },
          { value: "actual", label: "Actual size" },
          { value: "remote", label: "Resize remote desktop" },
        ]}
      />
      <Toggle
        label="Share the clipboard automatically"
        hint="Copies what you copy on the remote computer, and sends your clipboard when you click into the desktop. When off, use the clipboard menu."
        checked={d.clipboardSync}
        onChange={(clipboardSync) => set({ clipboardSync })}
      />
      <Row label="Upload dropped files to" hint="A folder in your home folder on the remote computer. Empty means the home folder itself.">
        <input
          key={d.uploadDir}
          className={`${inputClass} w-48`}
          defaultValue={d.uploadDir}
          placeholder="Home folder"
          aria-label="Upload folder"
          onBlur={(e) => e.target.value !== d.uploadDir && set({ uploadDir: e.target.value })}
        />
      </Row>
    </Section>
  );
}
