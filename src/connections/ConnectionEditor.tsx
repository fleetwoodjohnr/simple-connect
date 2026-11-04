import { useEffect, useState, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import { Collapsible } from "radix-ui";
import { useUi } from "../stores/ui";
import { profileToDraft, useConnections } from "../stores/connections";
import { useSessions } from "../stores/sessions";
import { api, isCmdError } from "../services/ipc";
import type { AuthMethod, DesktopMethod, KeyInfo, ProfileDraft } from "../types/ipc";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { Dialog } from "../components/ui/Dialog";
import { Button } from "../components/ui/Button";
import { Field, inputClass } from "../components/ui/Field";
import { PROFILE_COLORS, PROFILE_ICONS } from "./appearance";
import { useParsedDestination } from "../pages/Home";
import { RoutePreview } from "./RoutePreview";

const EMPTY: ProfileDraft = {
  name: "",
  host: "",
  port: null,
  username: null,
  groupId: null,
  auth: "auto",
  identityFile: null,
  jump: null,
  startDir: null,
  keepaliveSecs: null,
  terminalTheme: null,
  color: null,
  icon: null,
  tags: [],
  mac: null,
  reusePassword: null,
  rdUser: null,
  rdMethod: null,
};

const DESKTOP_METHODS: { value: DesktopMethod | ""; label: string }[] = [
  { value: "", label: "Choose automatically" },
  { value: "x11", label: "Share the computer's screen (X11)" },
  { value: "wayland", label: "Share the computer's screen (Wayland)" },
  { value: "virtual", label: "Virtual desktop" },
  { value: "rdp", label: "Remote Desktop (RDP)" },
  { value: "vnc", label: "VNC server" },
];

const AUTH: { value: AuthMethod; label: string; hint: string }[] = [
  { value: "auto", label: "Automatic", hint: "Try your SSH agent and keys, then ask for a password." },
  { value: "key", label: "Key file", hint: "Use a specific private key." },
  { value: "agent", label: "SSH agent", hint: "Use keys loaded in your SSH agent, including security keys." },
  { value: "password", label: "Password", hint: "Ask for a password, or use a saved one." },
];

const nullIfEmpty = (s: string) => (s.trim() === "" ? null : s);

function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="flex rounded-control border border-line bg-ink p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className="h-7 flex-1 rounded-[5px] px-2 text-muted transition-colors aria-checked:bg-raised aria-checked:text-text aria-checked:shadow-sm"
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

function Section({ title, children, defaultOpen = false }: { title: string; children: ReactNode; defaultOpen?: boolean }) {
  return (
    <Collapsible.Root defaultOpen={defaultOpen} className="border-t border-line pt-3">
      <Collapsible.Trigger className="group flex w-full items-center gap-1.5 font-medium text-muted hover:text-text">
        <ChevronRight size={14} className="transition-transform group-data-[state=open]:rotate-90" aria-hidden />
        {title}
      </Collapsible.Trigger>
      <Collapsible.Content className="grid grid-cols-2 gap-3 pt-3">{children}</Collapsible.Content>
    </Collapsible.Root>
  );
}

export function ConnectionEditor() {
  const { editing, setEditing } = useUi();
  const { groups, save } = useConnections();
  const [draft, setDraft] = useState<ProfileDraft>(EMPTY);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const route = useParsedDestination(draft.jump ? `-J ${draft.jump} ${draft.host || "host"}` : "");
  const load = useConnections((s) => s.load);
  const [keys, setKeys] = useState<KeyInfo[]>([]);
  const [legacy, setLegacy] = useState(false);
  const [confirmLegacy, setConfirmLegacy] = useState(false);
  const [hasSecret, setHasSecret] = useState(false);
  const [hasDesktopSecret, setHasDesktopSecret] = useState(false);

  useEffect(() => {
    if (!editing) return;
    setDraft(editing.profile ? profileToDraft(editing.profile) : { ...EMPTY, ...editing.initial });
    setLegacy(editing.profile?.legacyCrypto ?? false);
    setHasSecret(editing.profile?.hasSavedSecret ?? false);
    setHasDesktopSecret(editing.profile?.hasSavedDesktopSecret ?? false);
    setErrors({});
    setFormError(null);
    void api.listKeys().then(setKeys, () => setKeys([]));
  }, [editing]);

  const setLegacyNow = async (allow: boolean) => {
    if (!editing?.profile) return;
    await api.setLegacyCrypto(editing.profile.id, allow);
    setLegacy(allow);
    await load();
  };

  const set = <K extends keyof ProfileDraft>(key: K, value: ProfileDraft[K]) => setDraft((d) => ({ ...d, [key]: value }));
  const text = (key: "name" | "host" | "username" | "identityFile" | "jump" | "startDir" | "rdUser") => ({
    value: draft[key] ?? "",
    error: errors[key],
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => set(key, key === "name" || key === "host" ? e.target.value : nullIfEmpty(e.target.value)),
  });
  const number = (key: "port" | "keepaliveSecs") => ({
    value: draft[key] ?? "",
    error: errors[key],
    inputMode: "numeric" as const,
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => {
      const v = e.target.value.replace(/\D/g, "");
      set(key, v === "" ? null : Number(v));
    },
  });

  const submit = async () => {
    setSaving(true);
    setFormError(null);
    try {
      const saved = await save(draft, editing?.profile?.id);
      if (editing?.linkSession) useSessions.getState().linkProfile(editing.linkSession, saved);
      setEditing(null);
    } catch (e) {
      if (isCmdError(e) && e.fields?.length) {
        setErrors(Object.fromEntries(e.fields.map((f) => [f.field, f.message])));
      } else {
        setFormError(isCmdError(e) ? e.message : "The connection could not be saved.");
      }
    } finally {
      setSaving(false);
    }
  };

  const auth = AUTH.find((a) => a.value === draft.auth)!;

  return (
    <Dialog
      open={editing !== null}
      onOpenChange={(o) => !o && setEditing(null)}
      title={editing?.profile ? "Edit connection" : "New connection"}
      footer={
        <>
          {formError && <p className="mr-auto self-center text-bad">{formError}</p>}
          <Button onClick={() => setEditing(null)}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={saving}>
            {editing?.profile ? "Save changes" : "Save connection"}
          </Button>
        </>
      }
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label="Name" autoFocus placeholder="Raspberry Pi" {...text("name")} />
        <div className="grid grid-cols-[1fr_6rem] gap-3">
          <Field label="Host name or IP address" mono placeholder="192.168.1.100" {...text("host")} />
          <Field label="Port" mono placeholder="22" {...number("port")} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="User name" mono placeholder="pi" {...text("username")} />
          <div className="flex flex-col gap-1.5">
            <label htmlFor="folder" className="font-medium text-muted">
              Folder
            </label>
            <select id="folder" className={inputClass} value={draft.groupId ?? ""} onChange={(e) => set("groupId", nullIfEmpty(e.target.value))}>
              <option value="">No folder</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex flex-col gap-1.5">
          <span className="font-medium text-muted">Sign in with</span>
          <Segmented label="Sign in with" value={draft.auth} options={AUTH} onChange={(v) => set("auth", v)} />
          <p className="text-xs text-faint">{auth.hint}</p>
        </div>
        {(draft.auth === "key" || draft.identityFile) && (
          <>
            <Field label="Private key file" mono placeholder="~/.ssh/id_ed25519" list="known-keys" hint="Choose one of your keys or type a path." {...text("identityFile")} />
            <datalist id="known-keys">
              {keys.map((k) => (
                <option key={k.path} value={k.path}>
                  {k.keyType} {k.comment}
                </option>
              ))}
            </datalist>
          </>
        )}

        <Section title="Jump hosts" defaultOpen={!!draft.jump}>
          <Field
            className="col-span-2"
            label="Connect through"
            mono
            placeholder="user@bastion.example.com:22"
            hint="Separate several jump hosts with commas, in the order they are reached."
            {...text("jump")}
          />
          {draft.jump && route.parsed && (
            <div className="col-span-2">
              <RoutePreview jump={route.parsed.jump} target={{ user: draft.username, host: draft.host || "host", port: draft.port }} />
            </div>
          )}
        </Section>

        <Section title="Options">
          <Field label="Start in folder" mono placeholder="/var/www" {...text("startDir")} />
          <Field label="Keepalive interval (seconds)" placeholder="30" hint="0 turns keepalive off." {...number("keepaliveSecs")} />
          <div className="col-span-2 flex flex-col gap-1.5">
            <label htmlFor="reuse-password" className="font-medium text-muted">
              At sudo and su password prompts
            </label>
            <select
              id="reuse-password"
              className={inputClass}
              value={draft.reusePassword === null ? "" : String(draft.reusePassword)}
              onChange={(e) => set("reusePassword", e.target.value === "" ? null : e.target.value === "true")}
            >
              <option value="">Use the app setting</option>
              <option value="true">Offer my SSH password (press Enter to send)</option>
              <option value="false">Don't offer it</option>
            </select>
          </div>
          {draft.mac && (
            <div className="col-span-2 flex items-center gap-2 text-muted">
              <span>Recognised on the network by</span>
              <span className="font-mono text-text">{draft.mac}</span>
              <button type="button" className="ml-auto text-accent hover:underline" onClick={() => set("mac", null)}>
                Forget
              </button>
            </div>
          )}
          <Field
            className="col-span-2"
            label="Tags"
            placeholder="production, web"
            value={draft.tags.join(", ")}
            error={errors.tags}
            onChange={(e) => set("tags", e.target.value.split(",").map((t) => t.trimStart()))}
            onBlur={() => set("tags", draft.tags.map((t) => t.trim()).filter(Boolean))}
          />
          <div className="col-span-2 flex flex-col gap-1.5">
            <span className="font-medium text-muted">Color and icon</span>
            <div className="flex flex-wrap items-center gap-1.5">
              {Object.entries(PROFILE_COLORS).map(([name, hex]) => (
                <button
                  key={name}
                  type="button"
                  aria-label={`${name} label`}
                  aria-pressed={draft.color === name}
                  onClick={() => set("color", draft.color === name ? null : name)}
                  className="size-6 rounded-full border-2 border-transparent aria-pressed:border-text"
                  style={{ background: hex }}
                />
              ))}
              <span className="mx-2 h-5 w-px bg-line" aria-hidden />
              {Object.entries(PROFILE_ICONS).map(([name, Icon]) => (
                <button
                  key={name}
                  type="button"
                  aria-label={`${name} icon`}
                  aria-pressed={draft.icon === name}
                  onClick={() => set("icon", draft.icon === name ? null : name)}
                  className="grid size-7 place-items-center rounded-control text-muted hover:bg-hover aria-pressed:bg-accent-soft aria-pressed:text-accent"
                >
                  <Icon size={15} />
                </button>
              ))}
            </div>
          </div>
        </Section>

        <Section title="Remote desktop" defaultOpen={!!(draft.rdUser || draft.rdMethod)}>
          <Field
            label="Sign in as"
            placeholder={draft.username ?? "Same as SSH user"}
            hint="For Windows Remote Desktop and macOS Screen Sharing. Use DOMAIN\\name for domain accounts."
            {...text("rdUser")}
          />
          <div className="flex flex-col gap-1.5">
            <label htmlFor="rd-method" className="font-medium text-muted">
              Open with
            </label>
            <select
              id="rd-method"
              className={inputClass}
              value={draft.rdMethod ?? ""}
              onChange={(e) => set("rdMethod", (e.target.value || null) as DesktopMethod | null)}
            >
              {DESKTOP_METHODS.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
            {errors.rdMethod && <p className="text-xs text-bad">{errors.rdMethod}</p>}
          </div>
          {editing?.profile && hasDesktopSecret && (
            <div className="col-span-2 flex items-center justify-between">
              <span className="text-muted">A remote desktop password is saved for this connection.</span>
              <Button
                onClick={async () => {
                  await api.forgetSavedPassword(editing.profile!.id, true);
                  setHasDesktopSecret(false);
                  await load();
                }}
              >
                Forget it
              </Button>
            </div>
          )}
        </Section>

        {editing?.profile && (
          <Section title="Security">
            {hasSecret && (
              <div className="col-span-2 flex items-center justify-between">
                <span className="text-muted">A password is saved for this connection.</span>
                <Button
                  onClick={async () => {
                    await api.forgetSavedPassword(editing.profile!.id);
                    setHasSecret(false);
                    await load();
                  }}
                >
                  Forget saved password
                </Button>
              </div>
            )}
            <label className={`col-span-2 flex items-start gap-2 rounded-control p-2.5 ${legacy ? "bg-warn-soft text-warn" : "text-muted"}`}>
              <input type="checkbox" className="mt-0.5" checked={legacy} onChange={(e) => (e.target.checked ? setConfirmLegacy(true) : void setLegacyNow(false))} />
              <span>
                Allow legacy algorithms
                <span className="block text-xs">Only for old devices that can't use modern encryption. Weakens this connection.</span>
              </span>
            </label>
          </Section>
        )}
        <button type="submit" hidden />
      </form>
      <ConfirmDialog
        open={confirmLegacy}
        onOpenChange={setConfirmLegacy}
        title="Allow legacy algorithms?"
        description="This connection may then use SHA-1 key exchange and signatures and CBC ciphers, which are known to be weak. Use it only for old equipment that can't be upgraded. 3DES, DES and RC4 stay disabled."
        confirmLabel="Allow legacy algorithms"
        onConfirm={() => setLegacyNow(true)}
      />
    </Dialog>
  );
}
