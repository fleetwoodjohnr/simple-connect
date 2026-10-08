import { useEffect, useState } from "react";
import { AlertDialog } from "radix-ui";
import { ShieldAlert, ShieldQuestion } from "lucide-react";
import { api, errorMessage } from "../services/ipc";
import type { Prompt } from "../stores/sessions";
import { Button } from "../components/ui/Button";
import { inputClass } from "../components/ui/Field";
import { FingerprintGlyph } from "./FingerprintGlyph";
import { keyTypeName } from "./names";

type HostKeyPrompt = Extract<Prompt, { type: "hostKey" }>;

/** Splits a fingerprint into groups so it can be compared aloud or by eye. */
function Fingerprint({ value, tone = "text-text" }: { value: string; tone?: string }) {
  const [algo, b64] = value.includes(":") ? [value.slice(0, value.indexOf(":") + 1), value.slice(value.indexOf(":") + 1)] : ["", value];
  const groups = b64.match(/.{1,4}/g) ?? [];
  return (
    <p className={`min-w-0 break-words font-mono text-sm leading-relaxed [word-spacing:0.35em] ${tone}`} data-selectable aria-label={value}>
      <span className="text-faint">{algo}</span>
      {groups.join(" ")}
    </p>
  );
}

export function HostKeyDialog({ prompt, sessionLabel }: { prompt: HostKeyPrompt | null; sessionLabel: string }) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setTyped("");
    setError(null);
  }, [prompt?.id]);
  if (!prompt) return null;

  const answer = async (trust: boolean) => {
    setBusy(true);
    try {
      await api.answerHostKey(prompt.id, trust, prompt.changed ? typed : undefined);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const confirmed = !prompt.changed || typed.trim() === prompt.host;

  return (
    <AlertDialog.Root open onOpenChange={(o) => !o && void answer(false)}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 z-40 bg-black/55" />
        <AlertDialog.Content
          className={`animate-pop fixed left-1/2 top-1/2 z-50 max-h-[94vh] w-[min(560px,94vw)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-panel bg-raised p-6 shadow-pop ${prompt.changed ? "ring-2 ring-bad" : ""}`}
        >
          <div className="flex items-start gap-4">
            {prompt.changed ? <ShieldAlert size={28} className="shrink-0 text-bad" /> : <ShieldQuestion size={28} className="shrink-0 text-accent" />}
            <div className="min-w-0 flex-1">
              <AlertDialog.Title className={`text-lg font-semibold ${prompt.changed ? "text-bad" : ""}`}>
                {prompt.changed ? "The SSH identity of this server has changed" : "Check this server's identity"}
              </AlertDialog.Title>
              <AlertDialog.Description className="mt-1 text-muted">
                {prompt.changed
                  ? `${prompt.host} is presenting a different key than the one you trusted before.`
                  : `This is the first connection to ${prompt.host}${sessionLabel && sessionLabel !== prompt.host ? ` (${sessionLabel})` : ""}. Compare the fingerprint with the one from the server's administrator before trusting it.`}
              </AlertDialog.Description>
            </div>
          </div>

          <dl className="mt-5 grid grid-cols-[7rem_1fr] gap-x-3 gap-y-2">
            <dt className="text-muted">Host</dt>
            <dd className="font-mono" data-selectable>
              {prompt.host}
            </dd>
            {prompt.address && prompt.address !== prompt.host && (
              <>
                <dt className="text-muted">IP address</dt>
                <dd className="font-mono" data-selectable>
                  {prompt.address}
                </dd>
              </>
            )}
            <dt className="text-muted">Key type</dt>
            <dd>
              {keyTypeName(prompt.keyType)} <span className="font-mono text-xs text-faint">{prompt.keyType}</span>
            </dd>
          </dl>

          {prompt.changed &&
            prompt.previous.map((p, i) => (
              <div key={i} className="mt-4 rounded-control border border-line p-3">
                <p className="mb-1 text-xs text-muted">
                  Previous fingerprint · {keyTypeName(p.keyType)} · <span className="font-mono">{p.file.replace(/^\/home\/[^/]+/, "~")}</span>
                </p>
                <div className="flex items-center gap-3">
                  <FingerprintGlyph fingerprint={p.fingerprint} size={44} label="Previous fingerprint picture" />
                  <Fingerprint value={p.fingerprint} tone="text-muted" />
                </div>
              </div>
            ))}
          <div className={`mt-3 rounded-control border p-3 ${prompt.changed ? "border-bad/50 bg-bad-soft" : "border-line bg-ink"}`}>
            <p className="mb-1 text-xs text-muted">{prompt.changed ? "Current fingerprint" : "Fingerprint"}</p>
            <div className="flex items-center gap-3">
              <FingerprintGlyph fingerprint={prompt.fingerprint} size={56} label="Fingerprint picture" />
              <Fingerprint value={prompt.fingerprint} />
            </div>
          </div>

          {prompt.changed && (
            <>
              <div className="mt-4 text-muted">
                <p>This may mean:</p>
                <ul className="ml-5 mt-1 list-disc">
                  <li>the server was rebuilt or reinstalled,</li>
                  <li>its SSH keys were changed,</li>
                  <li>the host name now points to a different machine,</li>
                  <li>or someone is intercepting the connection (a man-in-the-middle attack).</li>
                </ul>
                <p className="mt-2">Only continue if you know why the key changed.</p>
              </div>
              <label className="mt-4 flex flex-col gap-1.5 text-muted">
                To trust the new key, type <span className="font-mono text-text">{prompt.host}</span>
                <input className={`${inputClass} font-mono`} value={typed} onChange={(e) => setTyped(e.target.value)} spellCheck={false} autoComplete="off" />
              </label>
            </>
          )}

          {error && <p className="mt-3 text-bad">{error}</p>}
          <div className="mt-6 flex justify-end gap-2">
            <AlertDialog.Cancel asChild>
              <Button variant={prompt.changed ? "primary" : "secondary"} disabled={busy}>
                {prompt.changed ? "Disconnect" : "Cancel"}
              </Button>
            </AlertDialog.Cancel>
            <Button variant={prompt.changed ? "danger" : "primary"} disabled={busy || !confirmed} onClick={() => void answer(true)}>
              {prompt.changed ? "Trust new key" : "Trust and connect"}
            </Button>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
