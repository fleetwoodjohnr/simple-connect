import { useEffect, useState, type ReactNode } from "react";
import { Dialog } from "./Dialog";
import { Button } from "./Button";
import { Field } from "./Field";
import { errorMessage } from "../../services/ipc";

export interface PasswordRequest {
  title: string;
  description?: ReactNode;
  /** Field keys and labels. A key named "confirm" must equal "new". */
  fields: { key: string; label: string }[];
  submitLabel: string;
  onSubmit: (values: Record<string, string>) => Promise<void>;
}

export function PasswordDialog({ request, onClose }: { request: PasswordRequest | null; onClose: () => void }) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setValues({});
    setError(null);
  }, [request]);

  const submit = async () => {
    if (!request) return;
    if ("confirm" in values && values.confirm !== values.new) return setError("The passwords don't match.");
    setBusy(true);
    try {
      await request.onSubmit(values);
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={request !== null}
      onOpenChange={(o) => !o && onClose()}
      title={request?.title}
      description={request?.description}
      width="w-[min(440px,92vw)]"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy} onClick={() => void submit()}>
            {request?.submitLabel}
          </Button>
        </>
      }
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        {request?.fields.map((f, i) => (
          <Field
            key={f.key}
            label={f.label}
            type="password"
            autoFocus={i === 0}
            value={values[f.key] ?? ""}
            onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
          />
        ))}
        {error && <p className="text-bad">{error}</p>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
