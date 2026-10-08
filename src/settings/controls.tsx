import { useId, type ReactNode } from "react";
import { Switch } from "radix-ui";
import { inputClass } from "../components/ui/Field";

export function Section({ title, description, children }: { title: string; description?: ReactNode; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-1">
      <h2 className="text-base font-semibold">{title}</h2>
      {description && <p className="mb-2 text-muted">{description}</p>}
      <div className="divide-y divide-line rounded-panel border border-line bg-panel">{children}</div>
    </section>
  );
}

export function Row({ label, hint, children, id }: { label: ReactNode; hint?: ReactNode; children: ReactNode; id?: string }) {
  return (
    <div className="flex items-center gap-6 px-4 py-3">
      <div className="min-w-0 flex-1">
        <label htmlFor={id} className="block">
          {label}
        </label>
        {hint && <p className="mt-0.5 text-xs text-muted">{hint}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

export function Toggle({
  label,
  hint,
  checked,
  onChange,
  disabled,
}: {
  label: ReactNode;
  hint?: ReactNode;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <Row label={label} hint={hint} id={id}>
      <Switch.Root
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={onChange}
        className="relative h-5 w-9 rounded-full bg-line-strong transition-colors data-[state=checked]:bg-accent disabled:opacity-60"
      >
        <Switch.Thumb className="block size-4 translate-x-0.5 rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-[18px]" />
      </Switch.Root>
    </Row>
  );
}

export function Choice<T extends string | number>({
  label,
  hint,
  value,
  options,
  onChange,
}: {
  label: ReactNode;
  hint?: ReactNode;
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  const id = useId();
  return (
    <Row label={label} hint={hint} id={id}>
      <select
        id={id}
        className={`${inputClass} w-48`}
        value={String(value)}
        onChange={(e) => onChange(options.find((o) => String(o.value) === e.target.value)!.value)}
      >
        {options.map((o) => (
          <option key={String(o.value)} value={String(o.value)}>
            {o.label}
          </option>
        ))}
      </select>
    </Row>
  );
}

export function NumberRow({
  label,
  hint,
  value,
  min,
  max,
  onChange,
  suffix,
}: {
  label: ReactNode;
  hint?: ReactNode;
  value: number;
  min: number;
  max: number;
  onChange: (v: number) => void;
  suffix?: string;
}) {
  const id = useId();
  return (
    <Row label={label} hint={hint} id={id}>
      <span className="flex items-center gap-2 text-muted">
        <input
          id={id}
          type="number"
          min={min}
          max={max}
          value={value}
          onChange={(e) => {
            const n = Number(e.target.value);
            if (Number.isFinite(n)) onChange(Math.max(min, Math.min(max, n)));
          }}
          className={`${inputClass} w-24 text-right`}
        />
        {suffix}
      </span>
    </Row>
  );
}
