import { Cloud, Container, Cpu, Database, HardDrive, Monitor, Router, Server, type LucideIcon } from "lucide-react";

/** Label colours chosen by the user. Kept muted so they never read as trust state. */
export const PROFILE_COLORS: Record<string, string> = {
  gray: "#8a97a6",
  red: "#d9777a",
  orange: "#d99a6c",
  yellow: "#cdb664",
  green: "#79b98f",
  teal: "#6bb7b0",
  blue: "#6e9fd6",
  purple: "#a08ad6",
  pink: "#d084b4",
};

export const PROFILE_ICONS: Record<string, LucideIcon> = {
  server: Server,
  nas: HardDrive,
  pi: Cpu,
  router: Router,
  cloud: Cloud,
  database: Database,
  desktop: Monitor,
  container: Container,
};

export function ProfileIcon({ icon, color, size = 15 }: { icon: string | null; color: string | null; size?: number }) {
  const Icon = PROFILE_ICONS[icon ?? "server"] ?? Server;
  return <Icon size={size} aria-hidden style={{ color: color ? PROFILE_COLORS[color] : undefined }} className="shrink-0 text-faint" />;
}
