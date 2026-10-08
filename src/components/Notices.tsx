import { Fingerprint } from "lucide-react";
import { useSessions } from "../stores/sessions";

/** Non-blocking notices from OpenSSH, e.g. "touch your security key". */
export function Notices() {
  const notices = useSessions((s) => s.notices);
  if (!notices.length) return null;
  return (
    <div className="fixed bottom-10 right-4 z-50 flex w-80 flex-col gap-2" role="status" aria-live="polite">
      {notices.map((n) => (
        <div key={n.id} className="animate-pop flex items-start gap-3 rounded-panel bg-raised p-3 shadow-pop">
          <Fingerprint size={18} className="mt-0.5 shrink-0 animate-pulse text-accent" />
          <div>
            <p className="font-medium">Touch your security key</p>
            <p className="text-xs text-muted">{n.text}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
