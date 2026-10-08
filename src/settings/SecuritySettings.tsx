import { useEffect, useState } from "react";
import { Lock, ShieldCheck, Trash2 } from "lucide-react";
import { api, errorMessage } from "../services/ipc";
import { useSettings } from "../stores/settings";
import type { AppInfo, TrustedHost } from "../types/ipc";
import { Button } from "../components/ui/Button";
import { IconButton } from "../components/ui/IconButton";
import { PasswordDialog, type PasswordRequest } from "../components/ui/PasswordDialog";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { Choice, Row, Section, Toggle } from "./controls";
import { FingerprintGlyph } from "../security/FingerprintGlyph";
import { keyTypeName } from "../security/names";

export function SecuritySettings({ info, reloadInfo }: { info: AppInfo | null; reloadInfo: () => void }) {
  const { settings, save, load } = useSettings();
  const [hosts, setHosts] = useState<TrustedHost[]>([]);
  const [pw, setPw] = useState<PasswordRequest | null>(null);
  const [forget, setForget] = useState<TrustedHost | null>(null);
  const [logs, setLogs] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const vault = settings.credentialStorage === "vault";

  const refreshHosts = () => void api.listKnownHosts().then(setHosts, () => setHosts([]));
  useEffect(() => {
    refreshHosts();
    void api.logFolder().then(setLogs);
  }, []);

  const done = (msg: string) => async () => {
    await load();
    reloadInfo();
    setMessage(msg);
  };

  return (
    <div className="flex flex-col gap-8">
      <Section title="Server verification" description="Every server's identity is checked against the keys you trusted. This can't be turned off.">
        <Row label={<span className="flex items-center gap-2"><ShieldCheck size={15} className="text-ok" /> Require host-key verification</span>} hint="Unknown servers need your approval; changed keys are blocked until you decide.">
          <span className="text-muted">Always on</span>
        </Row>
        <Toggle
          label="Also record trusted keys in ~/.ssh/known_hosts"
          hint="Off: trusted keys are kept in Simple Connect's own file, and your OpenSSH files are only read."
          checked={settings.writeUserKnownHosts}
          onChange={(writeUserKnownHosts) => void save({ writeUserKnownHosts })}
        />
        <div className="px-4 py-3">
          <p className="mb-2">Trusted servers</p>
          {hosts.length === 0 ? (
            <p className="text-muted">No servers trusted yet. Keys from ~/.ssh/known_hosts are also accepted.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {hosts.map((h, i) => (
                <li key={`${h.host}-${i}`} className="flex items-center gap-3 rounded-control px-2 py-1.5 hover:bg-hover">
                  <FingerprintGlyph fingerprint={h.fingerprint} size={24} />
                  <span className="w-48 truncate font-mono">{h.host}</span>
                  <span className="w-28 text-xs text-muted">{keyTypeName(h.keyType)}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-faint" data-selectable>
                    {h.fingerprint}
                  </span>
                  <IconButton label={`Forget ${h.host}`} onClick={() => setForget(h)}>
                    <Trash2 size={14} />
                  </IconButton>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Section>

      <Section
        title="Saved passwords"
        description="Passwords and key passphrases you choose to save are kept here, never in the connection list or logs."
      >
        <Choice
          label="Storage"
          hint={
            vault
              ? "An encrypted vault file (Argon2id + XChaCha20-Poly1305), unlocked with your master password."
              : info?.keyringAvailable
                ? "Your desktop's keyring (GNOME Keyring, KWallet or compatible)."
                : "No desktop keyring was found. Use the encrypted vault to save passwords."
          }
          value={settings.credentialStorage}
          options={[
            { value: "keyring", label: "System keyring" },
            { value: "vault", label: "Encrypted vault" },
          ]}
          onChange={(v) => {
            if (v === "vault" && !vault)
              setPw({
                title: "Create an encrypted vault",
                description: "Choose a master password. You'll enter it to unlock Simple Connect. It can't be recovered if forgotten.",
                fields: [
                  { key: "new", label: "Master password" },
                  { key: "confirm", label: "Repeat master password" },
                ],
                submitLabel: "Create vault",
                onSubmit: async (f) => {
                  await api.enableVault(f.new ?? "");
                  await done("Saved passwords are now in the encrypted vault.")();
                },
              });
            if (v === "keyring" && vault)
              setPw({
                title: "Move back to the system keyring",
                description: "Saved passwords move to your desktop keyring and the vault file is deleted.",
                fields: [{ key: "current", label: "Master password" }],
                submitLabel: "Use system keyring",
                onSubmit: async (f) => {
                  await api.disableVault(f.current ?? "");
                  await done("Saved passwords are now in the system keyring.")();
                },
              });
          }}
        />
        <Toggle
          label="Offer your SSH password at sudo prompts"
          hint="When sudo or su asks for a password in a terminal, press Enter to send the password you signed in with. It's never sent without your keypress, never shown, and forgotten when you disconnect. Each connection can override this."
          checked={settings.reuseSshPassword}
          onChange={(reuseSshPassword) => void save({ reuseSshPassword })}
        />
        {vault && (
          <Row label="Master password">
            <Button
              onClick={() =>
                setPw({
                  title: "Change master password",
                  fields: [
                    { key: "current", label: "Current master password" },
                    { key: "new", label: "New master password" },
                    { key: "confirm", label: "Repeat new master password" },
                  ],
                  submitLabel: "Change password",
                  onSubmit: async (f) => {
                    await api.changeVaultPassword(f.current ?? "", f.new ?? "");
                    setMessage("Master password changed.");
                  },
                })
              }
            >
              Change…
            </Button>
          </Row>
        )}
      </Section>

      <Section title="App lock" description="Locking hides your sessions and makes saved passwords unavailable until you unlock. Connections stay open.">
        {!vault && (
          <Row
            label="Lock password"
            hint={info?.lockConfigured ? "A lock password is set." : "Set a password to enable locking. (With the encrypted vault, the master password is used.)"}
          >
            <Button
              onClick={() =>
                setPw({
                  title: info?.lockConfigured ? "Change lock password" : "Set a lock password",
                  description: "Leave the new password empty to turn locking off.",
                  fields: [...(info?.lockConfigured ? [{ key: "current", label: "Current password" }] : []), { key: "new", label: "New password" }, { key: "confirm", label: "Repeat new password" }],
                  submitLabel: "Save",
                  onSubmit: async (f) => {
                    await api.setLockPassword(f.current ?? null, f.new || null);
                    await done(f.new ? "Lock password saved." : "Locking turned off.")();
                  },
                })
              }
            >
              {info?.lockConfigured ? "Change…" : "Set…"}
            </Button>
          </Row>
        )}
        <Choice
          label="Lock after inactivity"
          value={settings.autoLockMinutes}
          onChange={(autoLockMinutes) => void save({ autoLockMinutes })}
          options={[
            { value: 0, label: "Never" },
            { value: 5, label: "5 minutes" },
            { value: 15, label: "15 minutes" },
            { value: 30, label: "30 minutes" },
            { value: 60, label: "1 hour" },
          ]}
        />
        <Toggle label="Lock when the computer sleeps" checked={settings.lockOnSleep} onChange={(lockOnSleep) => void save({ lockOnSleep })} />
        <Toggle label="Lock when the desktop session locks" checked={settings.lockOnSessionLock} onChange={(lockOnSessionLock) => void save({ lockOnSessionLock })} />
        <Row label="Lock now">
          <Button disabled={!info?.lockConfigured} onClick={() => void api.lockApp()}>
            <Lock size={14} /> Lock
          </Button>
        </Row>
      </Section>

      <Section title="Clipboard">
        <Choice
          label="Clear copied text after"
          hint="Only text copied from Simple Connect is cleared, and only if it's still on the clipboard."
          value={settings.clipboardClearSecs}
          onChange={(clipboardClearSecs) => void save({ clipboardClearSecs })}
          options={[
            { value: 15, label: "15 seconds" },
            { value: 30, label: "30 seconds" },
            { value: 60, label: "60 seconds" },
            { value: 0, label: "Never" },
          ]}
        />
      </Section>

      <Section title="Encryption" description="Connections use modern algorithms only. Obsolete ones (DES, 3DES, RC4, SHA-1 key exchange and signatures, CBC ciphers) are refused.">
        <Row label="Preferred ciphers" hint="In order of preference, limited to what your OpenSSH supports.">
          <span className="text-right text-xs text-muted">ChaCha20-Poly1305 · AES-256-GCM · AES-128-GCM · AES-CTR</span>
        </Row>
        <Row label="Key exchange" hint="Post-quantum hybrids first, then Curve25519 and NIST curves.">
          <span className="text-xs text-muted">ML-KEM-768 · NTRU Prime · Curve25519</span>
        </Row>
        <Row label="Legacy algorithms" hint="For old devices only, allow them per connection in its settings. You'll see a warning while connected.">
          <span className="text-muted">Off by default</span>
        </Row>
      </Section>

      <Section title="Logs" description="Logs never contain passwords, keys, passphrases, clipboard contents or what you type in terminals.">
        <Row label="Log folder" hint={<span className="font-mono" data-selectable>{logs}</span>}>
          <Button onClick={() => void api.clearLogs().then(() => setMessage("Logs cleared."), (e) => setMessage(errorMessage(e)))}>Clear logs</Button>
        </Row>
      </Section>

      {message && (
        <p role="status" className="text-ok">
          {message}
        </p>
      )}
      <PasswordDialog request={pw} onClose={() => setPw(null)} />
      <ConfirmDialog
        open={forget !== null}
        onOpenChange={(o) => !o && setForget(null)}
        title={`Forget ${forget?.host}?`}
        description="You'll be asked to verify this server's identity again on the next connection."
        confirmLabel="Forget"
        onConfirm={async () => {
          if (forget) await api.forgetKnownHost(forget.host);
          refreshHosts();
        }}
      />
    </div>
  );
}
