import { useEffect, useState } from "react";
import { Dialog } from "../components/ui/Dialog";
import { Button } from "../components/ui/Button";

const WHO = ["Owner", "Group", "Others"];
const WHAT = ["Read", "Write", "Execute"];

export function PermissionsDialog({
  target,
  onClose,
  onSave,
}: {
  target: { path: string; mode: number } | null;
  onClose: () => void;
  onSave: (mode: number) => Promise<void>;
}) {
  const [mode, setMode] = useState(0);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setMode(target?.mode ?? 0);
    setError(null);
  }, [target]);
  const bit = (who: number, what: number) => 1 << (8 - (who * 3 + what));

  return (
    <Dialog
      open={target !== null}
      onOpenChange={(o) => !o && onClose()}
      title="Permissions"
      description={<span className="font-mono text-xs">{target?.path}</span>}
      width="w-[min(420px,92vw)]"
      footer={
        <>
          {error && <p className="mr-auto self-center text-bad">{error}</p>}
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            onClick={async () => {
              try {
                await onSave(mode);
                onClose();
              } catch (e) {
                setError((e as { message?: string }).message ?? "Permissions couldn't be changed.");
              }
            }}
          >
            Apply
          </Button>
        </>
      }
    >
      <table className="w-full">
        <thead>
          <tr className="text-muted">
            <th />
            {WHAT.map((w) => (
              <th key={w} scope="col" className="pb-2 font-medium">
                {w}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {WHO.map((who, i) => (
            <tr key={who}>
              <th scope="row" className="py-1.5 text-left font-medium">
                {who}
              </th>
              {WHAT.map((what, j) => (
                <td key={what} className="text-center">
                  <input
                    type="checkbox"
                    aria-label={`${who} ${what.toLowerCase()}`}
                    checked={(mode & bit(i, j)) !== 0}
                    onChange={(e) => setMode((m) => (e.target.checked ? m | bit(i, j) : m & ~bit(i, j)))}
                    className="size-4 accent-[var(--accent)]"
                  />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 text-muted">
        Numeric: <span className="font-mono text-text">{(mode & 0o7777).toString(8).padStart(3, "0")}</span>
      </p>
    </Dialog>
  );
}
