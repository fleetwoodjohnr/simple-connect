import { useEffect, useState } from "react";
import { Tooltip } from "radix-ui";
import { useThemeSync } from "./hooks/useThemeSync";
import { useShortcuts } from "./hooks/useShortcuts";
import { useIdleLock } from "./hooks/useIdleLock";
import { useUi } from "./stores/ui";
import { useConnections } from "./stores/connections";
import { useSessions } from "./stores/sessions";
import { useSettings } from "./stores/settings";
import { api } from "./services/ipc";
import { startEventBridge } from "./services/events";
import type { AppInfo } from "./types/ipc";
import { TopBar } from "./components/layout/TopBar";
import { Sidebar } from "./components/layout/Sidebar";
import { StatusBar } from "./components/layout/StatusBar";
import { TabStrip } from "./components/layout/TabStrip";
import { TransferDrawer } from "./components/layout/TransferDrawer";
import { CommandPalette } from "./components/CommandPalette";
import { Notices } from "./components/Notices";
import { ConnectionEditor } from "./connections/ConnectionEditor";
import { NetworkScanner } from "./connections/NetworkScanner";
import { Home } from "./pages/Home";
import { SessionView } from "./pages/SessionView";
import { SettingsPage } from "./settings/SettingsPage";
import { HostKeyDialog } from "./security/HostKeyDialog";
import { SecretPromptDialog } from "./security/SecretPromptDialog";
import { LockScreen } from "./security/LockScreen";

export default function App() {
  useThemeSync();
  const { setPaletteOpen, setEditing, view, setView } = useUi();
  const loadConnections = useConnections((s) => s.load);
  const { settings, load: loadSettings } = useSettings();
  const { tabs, activeId, prompts, locked, setLocked, connect, close, addTerminal } = useSessions();
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [settingsPage, setSettingsPage] = useState<"General" | "SSH keys">("General");

  useEffect(() => {
    void startEventBridge();
    void loadSettings().catch(() => undefined);
    void loadConnections().catch(() => undefined);
    void api.appInfo().then((i) => {
      setInfo(i);
      setLocked(i.locked);
    });
    void api.listTransfers().then((jobs) => useSessions.setState({ jobs }), () => undefined);
  }, [loadConnections, loadSettings, setLocked]);

  // Lock state changes (e.g. a lock password was just set) refresh what the UI offers.
  useEffect(() => {
    void api.appInfo().then(setInfo);
  }, [locked, settings]);

  useIdleLock(settings.autoLockMinutes, !!info?.lockConfigured && !locked);

  const openSettings = (page: "General" | "SSH keys" = "General") => {
    setSettingsPage(page);
    setView("settings");
  };

  useShortcuts({
    palette: () => setPaletteOpen(true),
    newConnection: () => setEditing({}),
    newTerminal: () => activeId && addTerminal(activeId),
    closeTab: () => activeId && void close(activeId),
    search: () => document.getElementById("connection-filter")?.focus(),
    settings: () => openSettings(),
    lock: () => void api.lockApp(),
  });

  const prompt = locked ? undefined : prompts[0];
  const promptLabel = prompt ? (tabs.find((t) => t.id === prompt.session)?.label ?? "") : "";

  return (
    <Tooltip.Provider delayDuration={400}>
      <div className="flex h-full flex-col" inert={locked} aria-hidden={locked}>
        <TopBar canLock={!!info?.lockConfigured} />
        <div className="flex min-h-0 flex-1">
          {view === "settings" ? (
            <main className="min-w-0 flex-1">
              <SettingsPage initial={settingsPage} />
            </main>
          ) : (
            <>
              <Sidebar onConnect={(t) => void connect(t)} />
              <main className="flex min-w-0 flex-1 flex-col">
                <TabStrip />
                <div className="relative min-h-0 flex-1">
                  {activeId === null && (
                    <div className="h-full overflow-auto">
                      <Home startupError={info?.startupError ?? null} />
                    </div>
                  )}
                  {tabs.map((t) => (
                    <div key={t.id} className="absolute inset-0" hidden={t.id !== activeId}>
                      <SessionView tab={t} visible={t.id === activeId} />
                    </div>
                  ))}
                </div>
              </main>
            </>
          )}
        </div>
        <TransferDrawer />
        <StatusBar />
      </div>
      <CommandPalette openSettings={openSettings} />
      <NetworkScanner />
      <ConnectionEditor />
      <HostKeyDialog prompt={prompt?.type === "hostKey" ? prompt : null} sessionLabel={promptLabel} />
      <SecretPromptDialog prompt={prompt?.type === "secret" ? prompt : null} sessionLabel={promptLabel} />
      <Notices />
      {locked && <LockScreen />}
    </Tooltip.Provider>
  );
}
