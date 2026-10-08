import { useEffect, useState } from "react";
import { Eye, EyeOff, KeyRound } from "lucide-react";
import { api } from "../services/ipc";
import type { Prompt } from "../stores/sessions";
import { Dialog } from "../components/ui/Dialog";
import { Button } from "../components/ui/Button";
import { inputClass } from "../components/ui/Field";

type SecretPrompt = Extract<Prompt, { type: "secret" }>;

const TITLES = {
  password: "Enter your password",
  passphrase: "Unlock your key",
  pin: "Enter your security key PIN",
  server: "The server is asking for input",
  confirm: "Confirm",
} as const;

export function SecretPromptDialog({ prompt, sessionLabel }: { prompt: SecretPrompt | null; sessionLabel: string }) {
  const [value, setValue] = useState("");
  const [save, setSave] = useState(false);
  const [show, setShow] = useState(false);
  useEffect(() => {
    setValue("");
    setSave(false);
    setShow(false);
  }, [prompt?.id]);
  if (!prompt) return null;

  const send = (v: string | null) => {
    void api.answerSecret(prompt.id, v, save && v !== null);
    setValue("");
  };

  if (prompt.kind === "confirm") {
    return (
      <Dialog
        open
        onOpenChange={(o) => !o && send(null)}
        title={TITLES.confirm}
        description={sessionLabel}
        width="w-[min(440px,92vw)]"
        footer={
          <>
            <Button onClick={() => send(null)}>No</Button>
            <Button variant="primary" onClick={() => send("yes")}>
              Yes
            </Button>
          </>
        }
      >
        <p className="whitespace-pre-wrap" data-selectable>
          {prompt.prompt}
        </p>
      </Dialog>
    );
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && send(null)}
      title={
        <span className="flex items-center gap-2">
          <KeyRound size={16} className="text-accent" /> {TITLES[prompt.kind]}
        </span>
      }
      description={sessionLabel || undefined}
      width="w-[min(440px,92vw)]"
      footer={
        <>
          <Button onClick={() => send(null)}>Cancel</Button>
          <Button variant="primary" onClick={() => send(value)}>
            Continue
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          send(value);
        }}
        className="flex flex-col gap-3"
      >
        {prompt.kind === "server" ? (
          <blockquote className="whitespace-pre-wrap rounded-control border-l-2 border-line-strong bg-ink px-3 py-2 font-mono text-xs" data-selectable>
            {prompt.prompt}
          </blockquote>
        ) : (
          <p className="text-muted">{prompt.prompt.trim()}</p>
        )}
        <div className="flex items-center gap-1">
          <input
            autoFocus
            type={show ? "text" : "password"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            aria-label={TITLES[prompt.kind]}
            className={inputClass}
          />
          <button
            type="button"
            aria-label={show ? "Hide" : "Show"}
            onClick={() => setShow(!show)}
            className="grid size-8 place-items-center rounded-control text-muted hover:bg-hover"
          >
            {show ? <EyeOff size={15} /> : <Eye size={15} />}
          </button>
        </div>
        {prompt.kind === "server" && <p className="text-xs text-faint">This text comes from the server. Saved passwords are never filled in here.</p>}
        {prompt.canSave && (
          <label className="flex items-center gap-2 text-muted">
            <input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} />
            {prompt.kind === "passphrase" ? "Save passphrase in secure storage" : "Save password in secure storage"}
          </label>
        )}
      </form>
    </Dialog>
  );
}
