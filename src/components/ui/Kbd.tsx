import { formatKeys } from "../../shortcuts";

export function Kbd({ keys, className = "" }: { keys: string; className?: string }) {
  return (
    <kbd className={`rounded-chip border border-line px-1.5 py-px font-sans text-[0.6875rem] text-muted ${className}`}>
      {formatKeys(keys)}
    </kbd>
  );
}
