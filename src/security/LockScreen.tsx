import { useState } from "react";
import { Lock } from "lucide-react";
import { api, errorMessage } from "../services/ipc";
import { Button } from "../components/ui/Button";
import { inputClass } from "../components/ui/Field";

/** Covers the whole window while locked; the app underneath is inert. */
export function LockScreen() {
  const [pw, setPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const unlock = async () => {
    setBusy(true);
    try {
      await api.unlockApp(pw);
      setPw("");
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div role="dialog" aria-modal="true" aria-label="Simple Connect is locked" className="fixed inset-0 z-[100] grid place-items-center bg-ink">
      <form
        className="flex w-80 flex-col items-center gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          void unlock();
        }}
      >
        <div className="grid size-14 place-items-center rounded-full bg-raised">
          <Lock size={24} className="text-accent" />
        </div>
        <h1 className="text-lg font-semibold">Simple Connect is locked</h1>
        <input
          autoFocus
          type="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          placeholder="Password"
          aria-label="Password"
          aria-invalid={!!error}
          className={`${inputClass} h-10`}
        />
        {error && <p className="text-bad">{error}</p>}
        <Button type="submit" variant="primary" className="h-10 w-full" disabled={busy || !pw}>
          Unlock
        </Button>
        <p className="text-center text-xs text-faint">Connections stay open while locked; saved passwords are unavailable until you unlock.</p>
      </form>
    </div>
  );
}
