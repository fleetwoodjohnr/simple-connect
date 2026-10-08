import type { ReactNode } from "react";
import { Dialog as D } from "radix-ui";
import { X } from "lucide-react";

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  width = "w-[min(560px,92vw)]",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-black/45" />
        <D.Content
          className={`animate-pop fixed left-1/2 top-1/2 z-50 flex max-h-[88vh] -translate-x-1/2 -translate-y-1/2 flex-col rounded-panel bg-raised shadow-pop ${width}`}
        >
          <div className="flex items-start gap-3 px-5 pt-5">
            <div className="flex-1">
              <D.Title className="text-base font-semibold">{title}</D.Title>
              {description ? (
                <D.Description className="mt-1 text-muted">{description}</D.Description>
              ) : (
                <D.Description className="sr-only">{title}</D.Description>
              )}
            </div>
            <D.Close aria-label="Close" className="grid size-7 place-items-center rounded-control text-muted hover:bg-hover hover:text-text">
              <X size={16} />
            </D.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
          {footer && <div className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</div>}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
