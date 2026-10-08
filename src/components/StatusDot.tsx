import type { SessionStatus } from "../types/ipc";

/** Connection health. Colour is backed by text for screen readers. */
export function StatusDot({ status, className = "" }: { status: SessionStatus; className?: string }) {
  const tone =
    status.state === "connected"
      ? "bg-ok"
      : status.state === "failed"
        ? "bg-bad"
        : status.state === "disconnected"
          ? "bg-faint"
          : "bg-warn animate-pulse";
  return <span aria-hidden className={`inline-block size-2 shrink-0 rounded-full ${tone} ${className}`} />;
}
