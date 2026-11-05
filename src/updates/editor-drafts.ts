import { create } from "zustand";

/** Tracks unsaved remote editors even when their connection has gone away. */
export const useEditorDrafts = create<{ dirty: Set<string>; mark: (id: string, dirty: boolean) => void }>((set) => ({
  dirty: new Set(),
  mark: (id, dirty) => set((state) => {
    const next = new Set(state.dirty);
    if (dirty) next.add(id); else next.delete(id);
    return { dirty: next };
  }),
}));
