// Relative time formatting for operator surfaces.
// "38s ago", "5m ago", "2h ago", "yesterday", "Apr 14".
// Designed for scan-speed reading; full datetime stays in `title` for hover.

const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function relativeTime(input: Date | string | number, now = Date.now()): string {
  const t = typeof input === "string" || typeof input === "number"
    ? new Date(input).getTime()
    : input.getTime();
  const delta = now - t;
  if (!Number.isFinite(delta)) return "—";

  if (delta < 0) return "just now"; // clock skew safety
  if (delta < 5 * SECOND) return "just now";
  if (delta < MINUTE) return `${Math.floor(delta / SECOND)}s ago`;
  if (delta < HOUR) return `${Math.floor(delta / MINUTE)}m ago`;
  if (delta < DAY) return `${Math.floor(delta / HOUR)}h ago`;
  if (delta < 2 * DAY) return "yesterday";
  if (delta < 7 * DAY) return `${Math.floor(delta / DAY)}d ago`;
  return new Date(t).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

export type Bucket = "active" | "today" | "yesterday" | "earlier";

export function bucketFor(input: Date | string, now = new Date()): Bucket {
  const t = new Date(input);
  const sameDay =
    t.getFullYear() === now.getFullYear() &&
    t.getMonth() === now.getMonth() &&
    t.getDate() === now.getDate();
  if (sameDay) return "today";
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  const isYesterday =
    t.getFullYear() === yesterday.getFullYear() &&
    t.getMonth() === yesterday.getMonth() &&
    t.getDate() === yesterday.getDate();
  if (isYesterday) return "yesterday";
  return "earlier";
}

export function absoluteIso(input: Date | string): string {
  return new Date(input).toISOString();
}
