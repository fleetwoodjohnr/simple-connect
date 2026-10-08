import { Fragment } from "react";
import { Laptop } from "lucide-react";
import type { JumpHop } from "../types/ipc";

export interface RouteNode {
  user: string | null;
  host: string;
  port: number | null;
}

export function formatDestination({ user, host, port }: RouteNode): string {
  const h = host.includes(":") ? `[${host}]` : host;
  return `${user ? `${user}@` : ""}${h}${port ? `:${port}` : ""}`;
}

/** This computer → jump hosts → target, as a horizontal route. */
export function RoutePreview({ jump, target }: { jump: JumpHop[]; target: RouteNode }) {
  const nodes = [...jump, target];
  return (
    <ol aria-label="Connection route" className="flex flex-wrap items-center gap-y-2 text-xs">
      <li className="flex items-center gap-1.5 text-muted">
        <Laptop size={14} aria-hidden />
        This computer
      </li>
      {nodes.map((n, i) => (
        <Fragment key={i}>
          <li aria-hidden className="mx-2 h-px w-6 bg-line-strong" />
          <li
            className={`rounded-chip border px-2 py-0.5 font-mono ${
              i === nodes.length - 1 ? "border-accent/50 bg-accent-soft text-text" : "border-line text-muted"
            }`}
          >
            {i < nodes.length - 1 && <span className="sr-only">via </span>}
            {formatDestination(n)}
          </li>
        </Fragment>
      ))}
    </ol>
  );
}

export const profileDestination = (p: { username: string | null; host: string; port: number | null }) =>
  formatDestination({ user: p.username, host: p.host, port: p.port });
