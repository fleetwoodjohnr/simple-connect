import { useState } from "react";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import type { AppInfo } from "../types/ipc";
import { Button } from "../components/ui/Button";
import { Row, Section } from "./controls";

export function AboutSettings({ info }: { info: AppInfo | null }) {
  const [update, setUpdate] = useState<Update | null>(null);
  const [state, setState] = useState<"idle" | "checking" | "none" | "installing" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  const checkNow = async () => {
    setState("checking");
    try {
      const u = await check();
      setUpdate(u);
      setState(u ? "idle" : "none");
    } catch (e) {
      setError(String(e));
      setState("error");
    }
  };

  return (
    <div className="flex flex-col gap-8">
      <Section title="About">
        <Row label="Simple Connect">
          <span className="font-mono text-muted">{info?.version}</span>
        </Row>
        <Row label="OpenSSH" hint="Simple Connect uses your system's OpenSSH for every connection.">
          <span className="font-mono text-xs text-muted">{info?.openssh ?? "Not found"}</span>
        </Row>
        <Row label="Privacy" hint="No account, cloud service, analytics or telemetry. Everything stays on this computer.">
          <span className="text-muted">Local only</span>
        </Row>
      </Section>
      <Section
        title="Updates"
        description="Updates are downloaded over HTTPS and installed only if their signature matches the Simple Connect release key. Packages from your distribution update through it instead."
      >
        <Row label={update ? `Version ${update.version} is available` : state === "none" ? "You're up to date" : "Check for updates"}>
          {update ? (
            <Button
              variant="primary"
              disabled={state === "installing"}
              onClick={async () => {
                setState("installing");
                try {
                  await update.downloadAndInstall();
                  await relaunch();
                } catch (e) {
                  setError(String(e));
                  setState("error");
                }
              }}
            >
              {state === "installing" ? "Installing…" : "Install and restart"}
            </Button>
          ) : (
            <Button disabled={state === "checking"} onClick={() => void checkNow()}>
              {state === "checking" ? "Checking…" : "Check now"}
            </Button>
          )}
        </Row>
        {update?.body && (
          <div className="px-4 py-3">
            <p className="mb-1 font-medium">What's new</p>
            <p className="whitespace-pre-wrap text-muted">{update.body}</p>
          </div>
        )}
        {state === "error" && <p className="px-4 py-3 text-bad">The update check failed: {error}</p>}
      </Section>
    </div>
  );
}
