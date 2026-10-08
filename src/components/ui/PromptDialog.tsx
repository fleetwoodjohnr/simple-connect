import { useEffect, useState } from "react";
import { Dialog } from "./Dialog";
import { Button } from "./Button";
import { Field } from "./Field";
import { isCmdError } from "../../services/ipc";

export interface PromptRequest {
  title: string;
  label: string;
  initial?: string;
  submitLabel: string;
  onSubmit: (value: string) => Promise<void>;
}

export function PromptDialog({ request, onClose }: { request: PromptRequest | null; onClose: () => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string>();
  useEffect(() => {
    setValue(request?.initial ?? "");
    setError(undefined);
  }, [request]);

  const submit = async () => {
    try {
      await request?.onSubmit(value);
      onClose();
    } catch (e) {
      setError(isCmdError(e) ? (e.fields?.[0]?.message ?? e.message) : "That didn't work.");
    }
  };

  return (
    <Dialog
      open={request !== null}
      onOpenChange={(o) => !o && onClose()}
      title={request?.title}
      width="w-[min(400px,92vw)]"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit}>
            {request?.submitLabel}
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label={request?.label} autoFocus value={value} error={error} onChange={(e) => setValue(e.target.value)} />
      </form>
    </Dialog>
  );
}
