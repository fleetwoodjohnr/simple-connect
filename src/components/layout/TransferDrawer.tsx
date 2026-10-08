import { useState } from "react";
import { ArrowDown, ArrowUp, CheckCircle2, Pause, Play, RotateCcw, X } from "lucide-react";
import { api } from "../../services/ipc";
import { useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import type { JobView } from "../../types/ipc";
import { formatBytes } from "../../file-manager/format";
import { IconButton } from "../ui/IconButton";
import { Button } from "../ui/Button";

const STATE_TEXT: Record<JobView["state"], string> = {
  queued: "Waiting",
  running: "",
  paused: "Paused",
  conflict: "Already exists",
  done: "Complete",
  skipped: "Skipped",
  failed: "Failed",
  cancelled: "Cancelled",
};

function eta(j: JobView) {
  if (!j.bytesPerSec) return "";
  const s = Math.round((j.size - j.done) / j.bytesPerSec);
  return s < 60 ? `${s}s left` : `${Math.round(s / 60)} min left`;
}

function JobRow({ job }: { job: JobView }) {
  const [all, setAll] = useState(false);
  const pct = job.size ? Math.min(100, Math.round((job.done / job.size) * 100)) : job.state === "done" ? 100 : 0;
  const Dir = job.direction === "upload" ? ArrowUp : ArrowDown;
  return (
    <li className="flex flex-col gap-1.5 rounded-control px-3 py-2 hover:bg-hover">
      <div className="flex items-center gap-2">
        <Dir size={14} className="shrink-0 text-faint" aria-label={job.direction === "upload" ? "Upload" : "Download"} />
        <span className="min-w-0 flex-1 truncate" title={job.direction === "upload" ? job.remote : job.local}>
          {job.name}
        </span>
        {job.verified && (
          <span className="flex items-center gap-1 text-xs text-ok" title="The server's SHA-256 checksum matches">
            <CheckCircle2 size={12} /> Verified
          </span>
        )}
        <span className="w-44 text-right text-xs tabular-nums text-muted">
          {job.state === "running" ? `${formatBytes(job.bytesPerSec)}/s · ${eta(job)}` : STATE_TEXT[job.state]}
        </span>
        <span className="flex w-16 justify-end">
          {job.state === "running" && (
            <IconButton label="Pause" className="size-6" onClick={() => void api.transferAction(job.id, "pause")}>
              <Pause size={13} />
            </IconButton>
          )}
          {job.state === "paused" && (
            <IconButton label="Resume" className="size-6" onClick={() => void api.transferAction(job.id, "resume")}>
              <Play size={13} />
            </IconButton>
          )}
          {job.state === "failed" && (
            <IconButton label="Retry" className="size-6" onClick={() => void api.transferAction(job.id, "retry")}>
              <RotateCcw size={13} />
            </IconButton>
          )}
          {["queued", "running", "paused", "conflict", "failed"].includes(job.state) && (
            <IconButton label="Cancel" className="size-6" onClick={() => void api.transferAction(job.id, "cancel")}>
              <X size={13} />
            </IconButton>
          )}
        </span>
      </div>
      {!["conflict", "skipped", "cancelled"].includes(job.state) && (
        <div className="flex items-center gap-2">
          <div
            role="progressbar"
            aria-label={`${job.name} progress`}
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
            className="h-1.5 flex-1 overflow-hidden rounded-full bg-line"
          >
            <div className={`h-full rounded-full transition-[width] ${job.state === "failed" ? "bg-bad" : job.state === "done" ? "bg-ok" : "bg-accent"}`} style={{ width: `${pct}%` }} />
          </div>
          <span className="w-40 text-right text-xs tabular-nums text-faint">
            {formatBytes(job.done)} / {formatBytes(job.size)}
          </span>
        </div>
      )}
      {job.error && <p className="text-xs text-bad">{job.error}</p>}
      {job.state === "conflict" && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted">“{job.name}” already exists at the destination.</span>
          <Button className="h-7" onClick={() => void api.resolveConflict(job.id, "overwrite", all)}>
            Replace
          </Button>
          <Button className="h-7" onClick={() => void api.resolveConflict(job.id, "keepBoth", all)}>
            Keep both
          </Button>
          <Button className="h-7" onClick={() => void api.resolveConflict(job.id, "skip", all)}>
            Skip
          </Button>
          <label className="flex items-center gap-1.5 text-xs text-muted">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> Apply to all
          </label>
        </div>
      )}
    </li>
  );
}

export function TransferDrawer() {
  const open = useUi((s) => s.drawerOpen);
  const jobs = useSessions((s) => s.jobs);
  if (!open) return null;
  const active = jobs.filter((j) => ["queued", "running", "conflict", "paused"].includes(j.state)).length;
  return (
    <section aria-label="Transfer queue" className="flex h-64 shrink-0 flex-col border-t border-line bg-panel">
      <div className="flex h-9 shrink-0 items-center gap-3 px-3">
        <h2 className="font-medium">Transfers</h2>
        <span className="text-xs text-muted">{active ? `${active} in progress` : "Idle"}</span>
        <Button variant="ghost" className="ml-auto h-7" disabled={!jobs.some((j) => ["done", "skipped", "cancelled"].includes(j.state))} onClick={() => void api.clearTransfers()}>
          Clear completed
        </Button>
      </div>
      {jobs.length === 0 ? (
        <p className="px-3 text-muted">Uploads and downloads appear here.</p>
      ) : (
        <ul className="min-h-0 flex-1 overflow-y-auto px-1 pb-2">
          {jobs.map((j) => (
            <JobRow key={j.id} job={j} />
          ))}
        </ul>
      )}
    </section>
  );
}
