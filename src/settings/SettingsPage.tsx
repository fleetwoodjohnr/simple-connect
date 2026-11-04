import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { api } from "../services/ipc";
import type { AppInfo } from "../types/ipc";
import { useUi } from "../stores/ui";
import { AppearanceSettings, ConnectionSettings, DesktopSettings, TerminalSettings } from "./GeneralSettings";
import { SecuritySettings } from "./SecuritySettings";
import { KeyManager } from "./KeyManager";
import { BackupSettings } from "./BackupSettings";
import { AboutSettings } from "./AboutSettings";

const PAGES = ["General", "Security", "SSH keys", "Backup", "About"] as const;
type Page = (typeof PAGES)[number];

export function SettingsPage({ initial = "General" }: { initial?: Page }) {
  const setView = useUi((s) => s.setView);
  const [page, setPage] = useState<Page>(initial);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const loadInfo = () => void api.appInfo().then(setInfo);
  useEffect(loadInfo, []);

  return (
    <div className="flex h-full">
      <nav aria-label="Settings" className="flex w-52 shrink-0 flex-col gap-0.5 border-r border-line p-3">
        <button type="button" onClick={() => setView("workspace")} className="mb-3 flex items-center gap-2 rounded-control px-2 py-1.5 text-muted hover:bg-hover hover:text-text">
          <ArrowLeft size={14} /> Back
        </button>
        {PAGES.map((p) => (
          <button
            key={p}
            type="button"
            aria-current={page === p ? "page" : undefined}
            onClick={() => setPage(p)}
            className="rounded-control px-2.5 py-1.5 text-left text-muted hover:bg-hover hover:text-text aria-[current=page]:bg-raised aria-[current=page]:text-text"
          >
            {p}
          </button>
        ))}
      </nav>
      <div className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto flex max-w-3xl flex-col gap-8 p-8">
          {page === "General" && (
            <>
              <AppearanceSettings />
              <TerminalSettings />
              <ConnectionSettings />
              <DesktopSettings />
            </>
          )}
          {page === "Security" && <SecuritySettings info={info} reloadInfo={loadInfo} />}
          {page === "SSH keys" && <KeyManager />}
          {page === "Backup" && <BackupSettings />}
          {page === "About" && <AboutSettings info={info} />}
        </div>
      </div>
    </div>
  );
}
