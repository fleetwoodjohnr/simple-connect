import { useEffect, useState } from "react";
import { open as openFile, save as saveFile } from "@tauri-apps/plugin-dialog";
import { Copy, Download, KeyRound, Plus, Upload, Usb } from "lucide-react";
import { api, errorMessage } from "../services/ipc";
import type { KeyInfo, KeyKind } from "../types/ipc";
import { Button } from "../components/ui/Button";
import { IconButton } from "../components/ui/IconButton";
import { Dialog } from "../components/ui/Dialog";
import { Field, inputClass } from "../components/ui/Field";
import { PasswordDialog, type PasswordRequest } from "../components/ui/PasswordDialog";
import { keyTypeName } from "../security/names";

const KINDS: { value: KeyKind; label: string; hint: string }[] = [
  { value: "ed25519", label: "Ed25519 (recommended)", hint: "Fast, small and secure. Works with OpenSSH 6.5 and newer." },
  { value: "ed25519-sk", label: "Ed25519 on a security key", hint: "Stored on a FIDO2 security key; needs a touch to sign in." },
  { value: "ecdsa", label: "ECDSA P-384", hint: "For servers that don't accept Ed25519." },
  { value: "ecdsa-sk", label: "ECDSA on a security key", hint: "For security keys without Ed25519 support." },
  { value: "rsa", label: "RSA 4096", hint: "For older systems that only accept RSA." },
];

function GenerateDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [kind, setKind] = useState<KeyKind>("ed25519");
  const [name, setName] = useState("id_ed25519");
  const [comment, setComment] = useState("");
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const hw = kind.endsWith("-sk");

  const create = async () => {
    if (pass !== confirm) return setError("The passphrases don't match.");
    setBusy(true);
    try {
      await api.generateKey(kind, name, comment, pass);
      onCreated();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title="Generate a new SSH key"
      footer={
        <>
          {error && <p className="mr-auto self-center text-bad">{error}</p>}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy || !name} onClick={() => void create()}>
            {busy ? (hw ? "Touch your security key…" : "Generating…") : "Generate key"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <label className="flex flex-col gap-1.5 text-muted">
          Key type
          <select
            className={inputClass}
            value={kind}
            onChange={(e) => {
              const k = e.target.value as KeyKind;
              setKind(k);
              setName(`id_${k.replace("-", "_")}`);
            }}
          >
            {KINDS.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </select>
          <span className="text-xs text-faint">{KINDS.find((k) => k.value === kind)?.hint}</span>
        </label>
        <Field label="File name (in ~/.ssh)" mono value={name} onChange={(e) => setName(e.target.value)} />
        <Field label="Comment" placeholder="you@laptop" value={comment} onChange={(e) => setComment(e.target.value)} hint="Shown next to the public key on servers." />
        <Field label="Passphrase" type="password" value={pass} onChange={(e) => setPass(e.target.value)} hint="Strongly recommended. Protects the key if this computer is stolen." />
        <Field label="Repeat passphrase" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </div>
    </Dialog>
  );
}

export function KeyManager() {
  const [keys, setKeys] = useState<KeyInfo[]>([]);
  const [generating, setGenerating] = useState(false);
  const [pw, setPw] = useState<PasswordRequest | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const refresh = () => void api.listKeys().then(setKeys, () => setKeys([]));
  useEffect(refresh, []);

  const importKey = async () => {
    const source = await openFile({ title: "Choose a private key", multiple: false, directory: false });
    if (typeof source !== "string") return;
    const name = source.split("/").pop() ?? "imported_key";
    setPw({
      title: "Import key",
      description: `The key is copied to ~/.ssh/${name} with private permissions. Leave the passphrase empty if the key has none.`,
      fields: [{ key: "pass", label: "Key passphrase" }],
      submitLabel: "Import",
      onSubmit: async (f) => {
        await api.importKey(source, name, f.pass ?? "");
        refresh();
        setMessage(`Imported ${name}.`);
      },
    });
  };

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <h2 className="flex-1 text-base font-semibold">SSH keys</h2>
        <Button onClick={() => void importKey()}>
          <Upload size={14} /> Import…
        </Button>
        <Button variant="primary" onClick={() => setGenerating(true)}>
          <Plus size={14} /> Generate key
        </Button>
      </div>
      <p className="text-muted">Keys in ~/.ssh. Private keys never leave this computer and are never shown.</p>
      {keys.length === 0 && <p className="rounded-panel border border-dashed border-line p-6 text-center text-muted">No SSH keys yet. Generate one to sign in without passwords.</p>}
      <ul className="flex flex-col gap-2">
        {keys.map((k) => (
          <li key={k.path} className="flex items-center gap-3 rounded-panel border border-line bg-panel px-4 py-3">
            {k.hardware ? <Usb size={18} className="shrink-0 text-accent" aria-label="Security key" /> : <KeyRound size={18} className="shrink-0 text-accent" aria-hidden />}
            <div className="min-w-0 flex-1">
              <p className="flex items-center gap-2">
                <span className="font-mono">{k.path.split("/").pop()}</span>
                <span className="text-xs text-muted">{keyTypeName(k.keyType)}</span>
                {k.encrypted === false && !k.hardware && <span className="rounded-chip bg-warn-soft px-1.5 text-xs text-warn">No passphrase</span>}
                {k.encrypted && <span className="rounded-chip bg-ok-soft px-1.5 text-xs text-ok">Passphrase</span>}
              </p>
              <p className="truncate font-mono text-xs text-faint" data-selectable>
                {k.fingerprint} {k.comment && `· ${k.comment}`}
              </p>
            </div>
            <IconButton label="Copy public key" onClick={() => void api.copyText(k.publicKey).then(() => setMessage("Public key copied."))}>
              <Copy size={14} />
            </IconButton>
            <IconButton
              label="Save public key to a file"
              onClick={async () => {
                const dest = await saveFile({ defaultPath: `${k.path.split("/").pop()}.pub` });
                if (dest) await api.exportPublicKey(k.path, dest);
              }}
            >
              <Download size={14} />
            </IconButton>
            {!k.hardware && (
              <Button
                variant="ghost"
                onClick={() =>
                  setPw({
                    title: "Change passphrase",
                    description: "Leave the new passphrase empty to remove it (not recommended).",
                    fields: [...(k.encrypted ? [{ key: "current", label: "Current passphrase" }] : []), { key: "new", label: "New passphrase" }, { key: "confirm", label: "Repeat new passphrase" }],
                    submitLabel: "Change passphrase",
                    onSubmit: async (f) => {
                      await api.changeKeyPassphrase(k.path, f.current ?? "", f.new ?? "");
                      refresh();
                      setMessage("Passphrase changed.");
                    },
                  })
                }
              >
                Passphrase…
              </Button>
            )}
          </li>
        ))}
      </ul>
      {message && (
        <p role="status" className="text-ok">
          {message}
        </p>
      )}
      <GenerateDialog open={generating} onClose={() => setGenerating(false)} onCreated={refresh} />
      <PasswordDialog request={pw} onClose={() => setPw(null)} />
    </section>
  );
}
