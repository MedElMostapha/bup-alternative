import { useEffect, useLayoutEffect, useRef, useState } from "react";

export interface MenuItem {
  label: string;
  hint?: string;
  disabled?: boolean;
  onSelect: () => void;
}

interface OpenMenu {
  x: number;
  y: number;
  items: MenuItem[];
}

const EDGE_GAP = 4;
type Listener = (menu: OpenMenu) => void;
let listener: Listener | null = null;

/** Replaces the browser's own menu with `items` at the pointer. */
export function openMenu(event: React.MouseEvent, items: MenuItem[]): void {
  event.preventDefault();
  listener?.({ x: event.clientX, y: event.clientY, items });
}

/** Rendered once; shows whichever menu was opened last. */
export function MenuHost() {
  const [menu, setMenu] = useState<OpenMenu | null>(null);
  const [position, setPosition] = useState({ left: 0, top: 0 });
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    listener = setMenu;
    return () => {
      listener = null;
    };
  }, []);

  useLayoutEffect(() => {
    if (!menu || !box.current) return;
    const { width, height } = box.current.getBoundingClientRect();
    setPosition({
      left: Math.max(EDGE_GAP, Math.min(menu.x, window.innerWidth - width - EDGE_GAP)),
      top: Math.max(EDGE_GAP, Math.min(menu.y, window.innerHeight - height - EDGE_GAP)),
    });
    box.current.querySelector<HTMLButtonElement>("button:not(:disabled)")?.focus();
  }, [menu]);

  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    const closeOutside = (event: PointerEvent) => {
      if (!box.current?.contains(event.target as Node)) close();
    };
    window.addEventListener("pointerdown", closeOutside, true);
    window.addEventListener("wheel", close, true);
    window.addEventListener("resize", close);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("pointerdown", closeOutside, true);
      window.removeEventListener("wheel", close, true);
      window.removeEventListener("resize", close);
      window.removeEventListener("blur", close);
    };
  }, [menu]);

  if (!menu) return null;

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") return setMenu(null);
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    event.preventDefault();
    const buttons = [...(box.current?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") ?? [])];
    const step = event.key === "ArrowDown" ? 1 : buttons.length - 1;
    buttons[(buttons.indexOf(document.activeElement as HTMLButtonElement) + step) % buttons.length]?.focus();
  };

  return (
    <div className="context-menu" role="menu" ref={box} style={position} onKeyDown={onKeyDown}>
      {menu.items.map((item) => (
        <button
          key={item.label}
          role="menuitem"
          disabled={item.disabled}
          onClick={() => {
            setMenu(null);
            item.onSelect();
          }}
        >
          <span>{item.label}</span>
          {item.hint && <span className="meta">{item.hint}</span>}
        </button>
      ))}
    </div>
  );
}
