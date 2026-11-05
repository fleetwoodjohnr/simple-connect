import { useUpdates, updateBlockReason } from "../updates/store";
import { useSessions } from "../stores/sessions";
import { useSettings } from "../stores/settings";
import { useEditorDrafts } from "../updates/editor-drafts";
import type { AppInfo } from "../types/ipc";
import { Button } from "../components/ui/Button";
import { Row, Section, Toggle } from "./controls";

export function AboutSettings({ info }: { info: AppInfo | null }) {
  const { update, state, error, checkNow, install, downloaded, total } = useUpdates();
  const { settings, save } = useSettings();
  const { tabs, jobs } = useSessions();
  const dirty = useEditorDrafts((s) => s.dirty.size > 0);
  const blocked = updateBlockReason(tabs.length, jobs, dirty);
  const busy = state === "downloading" || state === "installing";

  return (
    <div className="flex flex-col gap-8">
      <Section title="About">
        <Row label="Simple Connect">
          <span className="font-mono text-muted">{info?.version}</span>
        </Row>
        <Row label="OpenSSH" hint="Simple Connect uses OpenSSH for every connection.">
          <span className="font-mono text-xs text-muted">{info?.openssh ?? "Not found"}</span>
        </Row>
        <Row label="Privacy" hint="No account, cloud service, analytics or telemetry. Everything stays on this computer.">
          <span className="text-muted">Local only</span>
        </Row>
      </Section>
      <Section
        title="Updates"
        description="Updates are downloaded over HTTPS and installed only if their signature matches the Simple Connect release key. Installing an update restarts the app. Linux packages may request administrator approval."
      >
        <Toggle
          label="Check for updates automatically"
          hint="Checks when the application starts and every 24 hours. Downloads only when you choose Install and restart."
          checked={settings.autoCheckUpdates}
          onChange={(autoCheckUpdates) => void save({ autoCheckUpdates })}
        />
        <Row label={update ? `Version ${update.version} is available` : state === "none" ? "You're up to date" : "Check for updates"}>
          {update ? (
            <Button
              variant="primary"
              disabled={busy || state === "checking" || !!blocked}
              onClick={() => void install()}
            >
              {state === "downloading" ? "Downloading…" : state === "installing" ? "Installing…" : "Install and restart"}
            </Button>
          ) : (
            <Button disabled={state === "checking"} onClick={() => void checkNow()}>
              {state === "checking" ? "Checking…" : "Check now"}
            </Button>
          )}
        </Row>
        {update && <div className="px-4"><Button disabled={busy || state === "checking"} onClick={() => void checkNow()}>{state === "checking" ? "Checking…" : "Check again"}</Button></div>}
        {update && blocked && <p className="px-4 text-muted">{blocked}</p>}
        {state === "downloading" && (
          <div className="px-4" role="status">
            <progress className="w-full" value={total ? downloaded : undefined} max={total ?? undefined} aria-label="Update download" />
            <p className="text-muted">{total ? `${Math.min(100, Math.round(downloaded / total * 100))}% downloaded` : "Downloading update…"}</p>
          </div>
        )}
        {update?.body && (
          <div className="px-4 py-3">
            <p className="mb-1 font-medium">What's new</p>
            <p className="whitespace-pre-wrap text-muted">{update.body}</p>
          </div>
        )}
        {state === "error" && <p className="px-4 py-3 text-bad">Update failed: {error}</p>}
      </Section>
    </div>
  );
}
