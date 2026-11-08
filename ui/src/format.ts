export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour12: false });
}

export function statusClass(status: number | null): string {
  if (status === null) return "";
  if (status >= 500) return "status-5";
  if (status >= 400) return "status-4";
  if (status >= 300) return "status-3";
  return "status-2";
}

const DISPLAY_LIMIT = 2 * 1024 * 1024;

/** Keeps the editor responsive on very large messages. */
export function clipForDisplay(text: string): string {
  if (text.length <= DISPLAY_LIMIT) return text;
  return `${text.slice(0, DISPLAY_LIMIT)}\n\n[Display limited to 2 MB. The full message is in the project file.]`;
}
