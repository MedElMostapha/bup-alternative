import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { call, toast } from "../api";
import { RawEditor } from "../components/RawEditor";
import type { CompareSide, Comparison, ComparisonRow, ComparerDraft, DiffSide, RawText } from "../types";

const RUN_DELAY = 200;
const CONTEXT_LINES = 3;
const ROW_HEIGHT = 22;
const KEEP_UNCHANGED = 160;
const KEEP_CHANGED = 4000;
const emptySide = (label: string): CompareSide => ({ label, raw: { text: "", encoding: "utf8" } });

/** One minified line can be megabytes; only the part near a change matters. */
function elide(text: string, keep: number): string {
  if (text.length <= keep * 2 + 40) return text;
  return `${text.slice(0, keep)} ⋯ ${(text.length - keep * 2).toLocaleString()} characters ⋯ ${text.slice(-keep)}`;
}

function Cell({ side, tone }: { side?: DiffSide; tone: string }) {
  return (
    <>
      <span className={`diff-number ${side ? tone : "blank"}`}>{side?.number ?? ""}</span>
      <span className={`diff-text ${side ? tone : "blank"}`}>
        {side?.spans.map((span, i) =>
          span.changed ? <mark key={i}>{elide(span.text, KEEP_CHANGED)}</mark> : <span key={i}>{elide(span.text, KEEP_UNCHANGED)}</span>,
        )}
      </span>
    </>
  );
}

function RowView({ row }: { row: ComparisonRow }) {
  switch (row.kind) {
    case "gap":
      return (
        <div className="diff-gap">
          ⋯ {row.lines.toLocaleString()} identical line{row.lines === 1 ? "" : "s"}
        </div>
      );
    case "same":
      return (
        <div className="diff-row">
          <Cell side={row.a} tone="" />
          <Cell side={row.b} tone="" />
        </div>
      );
    case "changed":
      return (
        <div className="diff-row">
          <Cell side={row.a} tone="removed" />
          <Cell side={row.b} tone="added" />
        </div>
      );
    case "removed":
      return (
        <div className="diff-row">
          <Cell side={row.a} tone="removed" />
          <Cell tone="" />
        </div>
      );
    case "added":
      return (
        <div className="diff-row">
          <Cell tone="" />
          <Cell side={row.b} tone="added" />
        </div>
      );
  }
}

function summarize({ changed, removed, added }: Comparison): string {
  if (changed + removed + added === 0) return "No differences";
  const parts: Array<[number, string]> = [
    [changed, "changed"],
    [removed, "only in A"],
    [added, "only in B"],
  ];
  return parts
    .filter(([count]) => count > 0)
    .map(([count, label]) => `${count.toLocaleString()} ${label}`)
    .join(" · ");
}

export function Comparer({ draft, onDraftUsed, active }: { draft: ComparerDraft | null; onDraftUsed: () => void; active: boolean }) {
  const [a, setA] = useState(() => emptySide("A"));
  const [b, setB] = useState(() => emptySide("B"));
  const [bodyOnly, setBodyOnly] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [showInputs, setShowInputs] = useState(true);
  const [result, setResult] = useState<Comparison | null>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const ready = a.raw.text !== "" && b.raw.text !== "";
  const rows = result?.rows ?? [];

  useEffect(() => {
    if (!draft) return;
    setA(draft.a);
    setB(draft.b);
    setShowInputs(false);
    onDraftUsed();
    // Each draft is consumed exactly once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft?.nonce]);

  useEffect(() => {
    if (!ready) return setResult(null);
    let current = true;
    const timer = window.setTimeout(() => {
      call<Comparison>("comparer_diff", { a: a.raw, b: b.raw, bodyOnly, context: showAll ? null : CONTEXT_LINES }).then(
        (comparison) => current && setResult(comparison),
        toast,
      );
    }, RUN_DELAY);
    return () => {
      current = false;
      window.clearTimeout(timer);
    };
  }, [a.raw, b.raw, ready, bodyOnly, showAll]);

  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  // Rows measured while this view was hidden all have no height.
  useEffect(() => {
    if (active) virtual.measure();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, result]);

  const edit = (set: typeof setA) => (text: string) =>
    set((side) => (side.raw.text === text ? side : { label: side.label, raw: { ...side.raw, text } as RawText }));

  return (
    <div className="comparer">
      <div className="toolbar">
        <button onClick={() => setShowInputs(!showInputs)}>{showInputs ? "Hide inputs" : "Edit inputs"}</button>
        <label className="check">
          <input type="checkbox" checked={bodyOnly} onChange={(e) => setBodyOnly(e.target.checked)} />
          Body only
        </label>
        <label className="check">
          <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
          Show identical lines
        </label>
        {result && <span className="meta">{summarize(result)}</span>}
        <span className="spacer" />
        <button
          disabled={a.raw.text === "" && b.raw.text === ""}
          onClick={() => {
            setA(emptySide("A"));
            setB(emptySide("B"));
            setShowInputs(true);
          }}
        >
          Clear
        </button>
      </div>
      {result?.clipped && <div className="notes">Only the first 8 MB of each side was compared.</div>}
      {showInputs && (
        <div className="panes comparer-inputs">
          <section className="pane">
            <header className="pane-head">
              <h3>A</h3>
            </header>
            <RawEditor value={a.raw.text} onChange={edit(setA)} plain />
          </section>
          <section className="pane">
            <header className="pane-head">
              <h3>B</h3>
            </header>
            <RawEditor value={b.raw.text} onChange={edit(setB)} plain />
          </section>
        </div>
      )}
      {result ? (
        <div className="diff">
          <div className="diff-head">
            <span className="clip" title={a.label}>
              A · {a.label}
            </span>
            <span className="clip" title={b.label}>
              B · {b.label}
            </span>
          </div>
          <div className="table-body" ref={scroller}>
            <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
              {virtual.getVirtualItems().map((item) => (
                <div
                  key={item.index}
                  ref={virtual.measureElement}
                  data-index={item.index}
                  style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${item.start}px)` }}
                >
                  <RowView row={rows[item.index]} />
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <p className="empty">
          In Fuzzer or History, right-click a response and choose Compare, then do the same on another. You can also paste both
          above.
        </p>
      )}
    </div>
  );
}
