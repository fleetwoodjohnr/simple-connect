import { Button } from "../components/ui/Button";
import { useUpdates } from "./store";

export function UpdateNotice({ onReview }: { onReview: () => void }) {
  const { update, state } = useUpdates();
  if (!update || state === "downloading" || state === "installing") return null;
  return (
    <aside className="fixed bottom-10 right-4 z-40 flex items-center gap-3 rounded-panel border border-line bg-raised p-3 shadow-pop" role="status">
      <p>Simple Connect {update.version} is available.</p>
      <Button onClick={onReview}>Review update</Button>
    </aside>
  );
}
