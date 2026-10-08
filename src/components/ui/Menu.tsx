import type { ReactNode } from "react";
import { ContextMenu, DropdownMenu } from "radix-ui";

// Shared styling for context and dropdown menus.
export const menuContent = "animate-pop z-50 min-w-48 rounded-control bg-raised p-1 shadow-pop";
export const menuItem =
  "flex h-8 cursor-default select-none items-center gap-2.5 rounded-[5px] px-2 outline-none data-[disabled]:opacity-45 data-[highlighted]:bg-hover";
export const menuDanger = `${menuItem} text-bad`;
export const menuSeparator = "my-1 h-px bg-line";

export function ContextItem({ onSelect, children, danger }: { onSelect: () => void; children: ReactNode; danger?: boolean }) {
  return (
    <ContextMenu.Item onSelect={onSelect} className={danger ? menuDanger : menuItem}>
      {children}
    </ContextMenu.Item>
  );
}

export function DropdownItem({ onSelect, children }: { onSelect: () => void; children: ReactNode }) {
  return (
    <DropdownMenu.Item onSelect={onSelect} className={menuItem}>
      {children}
    </DropdownMenu.Item>
  );
}
