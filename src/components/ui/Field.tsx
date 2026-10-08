import { useId, type InputHTMLAttributes, type ReactNode } from "react";

export const inputClass =
  "h-8 w-full rounded-control border border-line bg-ink px-2.5 text-text outline-none transition-colors placeholder:text-faint focus:border-accent aria-[invalid=true]:border-bad";

export function Field({
  label,
  hint,
  error,
  mono,
  className = "",
  ...input
}: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode; hint?: ReactNode; error?: string; mono?: boolean }) {
  const id = useId();
  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      <label htmlFor={id} className="font-medium text-muted">
        {label}
      </label>
      <input
        id={id}
        spellCheck={false}
        autoComplete="off"
        aria-invalid={!!error}
        aria-describedby={error || hint ? `${id}-msg` : undefined}
        className={`${inputClass} ${mono ? "font-mono" : ""}`}
        {...input}
      />
      {(error || hint) && (
        <p id={`${id}-msg`} className={`text-xs ${error ? "text-bad" : "text-faint"}`}>
          {error ?? hint}
        </p>
      )}
    </div>
  );
}
