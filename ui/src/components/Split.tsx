import { type ReactNode, useRef, useState } from "react";

const KEYBOARD_STEP = 0.02;
const storageKey = (id: string) => `sluice.split.${id}`;

function stored(id: string): number | null {
  try {
    const value = Number(localStorage.getItem(storageKey(id)));
    return value > 0 && value < 1 ? value : null;
  } catch {
    return null;
  }
}

interface Props {
  /** Instances with the same id remember the same position. */
  id: string;
  direction: "row" | "column";
  /** Share of the space given to the first child. */
  initial?: number;
  min?: number;
  className?: string;
  /** With no second child, the first simply fills the space. */
  children: [ReactNode, ReactNode];
}

/** Two areas with a draggable divider between them. */
export function Split({ id, direction, initial = 0.5, min = 140, className = "", children }: Props) {
  const [fraction, setFraction] = useState(() => stored(id) ?? initial);
  const root = useRef<HTMLDivElement>(null);
  const [first, second] = children;
  const horizontal = direction === "row";

  const commit = (value: number) => {
    const box = root.current?.getBoundingClientRect();
    if (!box) return;
    const length = horizontal ? box.width : box.height;
    const limit = Math.min(min / length, 0.5);
    const next = Math.min(1 - limit, Math.max(limit, value));
    setFraction(next);
    try {
      localStorage.setItem(storageKey(id), String(next));
    } catch {
      // The position just won't be remembered.
    }
  };

  const drag = (event: React.PointerEvent<HTMLDivElement>) => {
    const box = root.current?.getBoundingClientRect();
    if (!box || !event.currentTarget.hasPointerCapture(event.pointerId)) return;
    commit(horizontal ? (event.clientX - box.left) / box.width : (event.clientY - box.top) / box.height);
  };

  const nudge = (event: React.KeyboardEvent) => {
    const [less, more] = horizontal ? ["ArrowLeft", "ArrowRight"] : ["ArrowUp", "ArrowDown"];
    if (event.key !== less && event.key !== more) return;
    event.preventDefault();
    commit(fraction + (event.key === more ? KEYBOARD_STEP : -KEYBOARD_STEP));
  };

  return (
    <div className={`split ${direction} ${className}`} ref={root}>
      <div className="split-side" style={second ? { flex: `0 0 ${fraction * 100}%` } : { flex: "1 1 0" }}>
        {first}
      </div>
      {second && (
        <>
          <div
            className="split-divider"
            role="separator"
            tabIndex={0}
            aria-orientation={horizontal ? "vertical" : "horizontal"}
            aria-valuenow={Math.round(fraction * 100)}
            title="Drag to resize. Double-click to reset."
            onPointerDown={(event) => {
              event.preventDefault();
              event.currentTarget.setPointerCapture(event.pointerId);
            }}
            onPointerMove={drag}
            onDoubleClick={() => commit(initial)}
            onKeyDown={nudge}
          />
          <div className="split-side" style={{ flex: "1 1 0" }}>
            {second}
          </div>
        </>
      )}
    </div>
  );
}
