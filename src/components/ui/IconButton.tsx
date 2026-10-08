import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Tooltip } from "radix-ui";
import { Kbd } from "./Kbd";

export function IconButton({
  label,
  shortcut,
  children,
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; shortcut?: string; children: ReactNode }) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <button
          type="button"
          aria-label={label}
          className={`grid size-8 place-items-center rounded-control text-muted transition-colors hover:bg-hover hover:text-text disabled:opacity-45 ${className}`}
          {...props}
        >
          {children}
        </button>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          sideOffset={6}
          className="animate-pop z-50 flex items-center gap-2 rounded-control bg-raised px-2 py-1 text-xs text-text shadow-pop"
        >
          {label}
          {shortcut && <Kbd keys={shortcut} />}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}
