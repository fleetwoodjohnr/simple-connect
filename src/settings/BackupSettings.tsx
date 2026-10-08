import { useState } from "react";
import { open as openFile, save as saveFile } from "@tauri-apps/plugin-dialog";
import { api, errorMessage } from "../services/ipc";
import { useConnections } from "../stores/connections";
import { Button } from "../components/ui/Button";
import { Field } from "../components/ui/Field";
import { Row, Section, Toggle } from "./controls";

export function BackupSettings() {
  const reload = useConnections((s) => s.load);
  const [withPasswords, setWithPasswords] = useState(false);
  const [backupPw, setBackupPw] = useState("");
  const [importPw, setImportPw] = useState("");
  const [needsPw, setNeedsPw] = useState<string | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const exportNow = async () => {
    const dest = await saveFile({ defaultPath: withPasswords ? "simple-connect-backup.scbackup" : "simple-connect-connections.json" });
    if (!dest) return;
    try {
      await api.exportProfiles(dest, withPasswords ? backupPw : null);
      setMessage({ ok: true, text: withPasswords ? "Encrypted backup saved." : "Connections exported without passwords." });
    } catch (e) {
      setMessage({ ok: false, text: errorMessage(e) });
    }
  };

  const importFrom = async (source: string, password: string | null) => {
    try {
      const r = await api.importProfiles(source, password);
      await reload();
      setNeedsPw(null);
      setMessage({ ok: true, text: `Imported ${r.imported} connection${r.imported === 1 ? "" : "s"}.${r.skipped.length ? ` Skipped ${r.skipped.length}: ${r.skipped.join("; ")}` : ""}` });
    } catch (e) {
      if ((e as { code?: string }).code === "import" && /encrypted|password/i.test(errorMessage(e))) setNeedsPw(source);
      setMessage({ ok: false, text: errorMessage(e) });
    }
  };

  return (
    <div className="flex flex-col gap-8">
      <Section title="Export" description="Saves your connections, folders and tags. Passwords and private keys are not included unless you create an encrypted backup.">
        <Toggle label="Include saved passwords (encrypted backup)" checked={withPasswords} onChange={setWithPasswords} />
        {withPasswords && (
          <div className="px-4 py-3">
            <Field label="Backup password" type="password" value={backupPw} onChange={(e) => setBackupPw(e.target.value)} hint="At least 8 characters. Needed to restore the backup; it can't be recovered." />
          </div>
        )}
        <Row label="Export connections">
          <Button variant="primary" disabled={withPasswords && backupPw.length < 8} onClick={() => void exportNow()}>
            Export…
          </Button>
        </Row>
      </Section>
      <Section title="Import" description="Adds connections from an export or backup. Every entry is checked; invalid ones are skipped. Security settings are never imported.">
        <Row label="Import connections">
          <Button
            onClick={async () => {
              const src = await openFile({ multiple: false, directory: false });
              if (typeof src === "string") await importFrom(src, null);
            }}
          >
            Import…
          </Button>
        </Row>
        {needsPw && (
          <form
            className="flex items-end gap-2 px-4 py-3"
            onSubmit={(e) => {
              e.preventDefault();
              void importFrom(needsPw, importPw);
            }}
          >
            <Field className="flex-1" label="Backup password" type="password" autoFocus value={importPw} onChange={(e) => setImportPw(e.target.value)} />
            <Button type="submit" variant="primary">
              Restore
            </Button>
          </form>
        )}
      </Section>
      {message && (
        <p role="status" className={message.ok ? "text-ok" : "text-bad"}>
          {message.text}
        </p>
      )}
    </div>
  );
}
