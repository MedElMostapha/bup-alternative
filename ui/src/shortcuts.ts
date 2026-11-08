import { useEffect, useRef } from "react";

/**
 * Runs an action for Ctrl (or Cmd) plus a key while `active`. Listens before
 * the editors do, since they bind some of the same keys.
 */
export function useShortcuts(active: boolean, shortcuts: Record<string, () => void>): void {
  const latest = useRef(shortcuts);
  latest.current = shortcuts;

  useEffect(() => {
    if (!active) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey || event.repeat) return;
      const action = latest.current[event.key.toLowerCase()];
      if (!action) return;
      event.preventDefault();
      event.stopPropagation();
      action();
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [active]);
}
