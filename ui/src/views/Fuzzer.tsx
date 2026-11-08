import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { call, dialogs, subscribe, toast } from "../api";
import { FlowPanes } from "../components/FlowPanes";
import { RawEditor, type RawEditorHandle } from "../components/RawEditor";
import { statusClass } from "../format";
import type {
  AttackMode,
  Encoding,
  FlowDetail,
  FuzzConfig,
  FuzzResult,
  FuzzRunInfo,
  PayloadSource,
  RequestDraft,
  RunState,
  Target,
} from "../types";

const MODES: Array<{ value: AttackMode; label: string; help: string }> = [
  { value: "single", label: "One position at a time", help: "Tries each payload in each position; the others keep their original value." },
  { value: "same", label: "Same payload everywhere", help: "Puts the same payload in every position at once." },
  { value: "parallel", label: "Lists side by side", help: "Uses one list per position and advances them together." },
  { value: "combinations", label: "All combinations", help: "Uses one list per position and tries every combination." },
];

type ListDraft =
  | { kind: "list"; text: string }
  | { kind: "numbers"; from: number; to: number; step: number }
  | { kind: "file"; path: string };

type SortKey = "index" | "status" | "length" | "duration_ms" | "matched";

const emptyList = (): ListDraft => ({ kind: "list", text: "" });
const TERMINAL: RunState[] = ["finished", "stopped"];
const ROW_HEIGHT = 26;

function toSource(draft: ListDraft): PayloadSource {
  switch (draft.kind) {
    case "list":
      return { list: draft.text.split("\n").filter((line) => line.length > 0) };
    case "numbers":
      return { numbers: { from: draft.from, to: draft.to, step: draft.step } };
    case "file":
      return { file: draft.path };
  }
}

function PayloadEditor({ draft, onChange, title }: { draft: ListDraft; onChange: (d: ListDraft) => void; title: string }) {
  const switchKind = (kind: ListDraft["kind"]) => {
    if (kind === "list") onChange(emptyList());
    if (kind === "numbers") onChange({ kind, from: 1, to: 100, step: 1 });
    if (kind === "file") onChange({ kind, path: "" });
  };
  const pickFile = async () => {
    const path = await dialogs.file();
    if (path) onChange({ kind: "file", path });
  };
  return (
    <div className="payload">
      <div className="field-row">
        <strong>{title}</strong>
        <select aria-label={`${title} type`} value={draft.kind} onChange={(e) => switchKind(e.target.value as ListDraft["kind"])}>
          <option value="list">Typed list</option>
          <option value="numbers">Number range</option>
          <option value="file">File</option>
        </select>
      </div>
      {draft.kind === "list" && (
        <textarea
          aria-label={`${title} values, one per line`}
          placeholder="One payload per line"
          rows={4}
          value={draft.text}
          onChange={(e) => onChange({ kind: "list", text: e.target.value })}
        />
      )}
      {draft.kind === "numbers" && (
        <div className="field-row">
          {(["from", "to", "step"] as const).map((key) => (
            <label key={key} className="stacked">
              {key[0].toUpperCase() + key.slice(1)}
              <input
                type="number"
                value={draft[key]}
                onChange={(e) => onChange({ ...draft, [key]: Number(e.target.value) })}
              />
            </label>
          ))}
        </div>
      )}
      {draft.kind === "file" && (
        <div className="field-row">
          <button onClick={pickFile}>Choose file</button>
          <span className="clip dim">{draft.path || "No file chosen"}</span>
        </div>
      )}
    </div>
  );
}

function ResultsTable({
  results,
  selected,
  onSelect,
  hasGrep,
}: {
  results: FuzzResult[];
  selected: number | null;
  onSelect: (result: FuzzResult) => void;
  hasGrep: boolean;
}) {
  const [sort, setSort] = useState<{ key: SortKey; descending: boolean }>({ key: "index", descending: false });
  const scroller = useRef<HTMLDivElement>(null);
  const sorted = useMemo(() => {
    const value = (r: FuzzResult) => (sort.key === "matched" ? Number(r.matched) : (r[sort.key] ?? -1));
    const direction = sort.descending ? -1 : 1;
    return [...results].sort((a, b) => (value(a) - value(b)) * direction || a.index - b.index);
  }, [results, sort]);
  const virtual = useVirtualizer({
    count: sorted.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });
  const header = (key: SortKey, label: string) => (
    <button
      className="sort"
      onClick={() => setSort((s) => ({ key, descending: s.key === key ? !s.descending : key !== "index" }))}
    >
      {label}
      {sort.key === key ? (sort.descending ? " ↓" : " ↑") : ""}
    </button>
  );
  return (
    <div className="table-wrap">
      <div className="table-row fuzz-row table-head">
        {header("index", "#")}
        <span>Payload</span>
        {header("status", "Status")}
        {header("length", "Length")}
        {header("duration_ms", "ms")}
        {hasGrep ? header("matched", "Match") : <span />}
      </div>
      <div className="table-body" ref={scroller}>
        <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
          {virtual.getVirtualItems().map((item) => {
            const row = sorted[item.index];
            return (
              <div
                key={row.index}
                className={`table-row fuzz-row${row.index === selected ? " selected" : ""}${row.error ? " failed" : ""}`}
                style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${item.start}px)` }}
                onClick={() => onSelect(row)}
              >
                <span className="num">{row.index + 1}</span>
                <span className="clip" title={row.error ?? row.payloads.join(", ")}>
                  {row.payloads.join(" · ")}
                </span>
                <span className={statusClass(row.status)}>{row.status ?? "—"}</span>
                <span className="num">{row.length}</span>
                <span className="num">{row.duration_ms}</span>
                <span>{row.matched ? <span className="tag alt">match</span> : ""}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function Fuzzer({ draft, onDraftUsed, active }: { draft: RequestDraft | null; onDraftUsed: () => void; active: boolean }) {
  const [target, setTarget] = useState<Target>({ host: "localhost", port: 80, tls: false });
  const [template, setTemplate] = useState("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
  const [encoding, setEncoding] = useState<Encoding>("utf8");
  const [mode, setMode] = useState<AttackMode>("single");
  const [lists, setLists] = useState<ListDraft[]>([emptyList()]);
  const [concurrency, setConcurrency] = useState(2);
  const [delay, setDelay] = useState(100);
  const [grep, setGrep] = useState("");
  const [preview, setPreview] = useState<{ total?: number; error?: string }>({});
  const [runs, setRuns] = useState<FuzzRunInfo[]>([]);
  const [runId, setRunId] = useState<number | null>(null);
  const [results, setResults] = useState<FuzzResult[]>([]);
  const [selected, setSelected] = useState<FuzzResult | null>(null);
  const [detail, setDetail] = useState<FlowDetail | null>(null);
  const [hiddenStatuses, setHiddenStatuses] = useState<Set<number | null>>(new Set());
  const editor = useRef<RawEditorHandle | null>(null);
  const currentRun = useRef<number | null>(null);
  currentRun.current = runId;

  const positions = Math.floor((template.match(/§/g)?.length ?? 0) / 2);
  const needed = mode === "parallel" || mode === "combinations" ? Math.max(positions, 1) : 1;
  const run = runs.find((item) => item.id === runId) ?? null;
  const running = run !== null && !TERMINAL.includes(run.state);

  useEffect(() => {
    setLists((current) => {
      if (current.length === needed) return current;
      return Array.from({ length: needed }, (_, i) => current[i] ?? emptyList());
    });
  }, [needed]);

  useEffect(() => {
    if (!draft) return;
    setTarget(draft.target);
    setTemplate(draft.request.text);
    setEncoding(draft.request.encoding);
    onDraftUsed();
    // Each draft is consumed exactly once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft?.nonce]);

  const config = useMemo<FuzzConfig>(
    () => ({
      target,
      template,
      encoding,
      mode,
      payloads: lists.map(toSource),
      concurrency,
      delay_ms: delay,
      grep: grep || null,
      normalize: true,
      timeout_ms: 30000,
    }),
    [target, template, encoding, mode, lists, concurrency, delay, grep],
  );

  // Rechecked when the view is shown, since scope is edited in Settings.
  useEffect(() => {
    if (!active) return;
    const timer = window.setTimeout(() => {
      call<number>("fuzz_preview", { config }).then(
        (total) => setPreview({ total }),
        (error) => setPreview({ error: String(error) }),
      );
    }, 300);
    return () => window.clearTimeout(timer);
  }, [config, active]);

  useEffect(() => {
    call<FuzzRunInfo[]>("list_fuzz_runs").then(setRuns, toast);
  }, []);

  useEffect(() => {
    setSelected(null);
    setHiddenStatuses(new Set());
    if (runId === null) return setResults([]);
    call<FuzzResult[]>("fuzz_results", { runId }).then(setResults, toast);
  }, [runId]);

  useEffect(
    () =>
      subscribe((events) => {
        const fresh: FuzzResult[] = [];
        for (const event of events) {
          if (event.kind === "fuzz_result" && event.run_id === currentRun.current) fresh.push(event);
          if (event.kind === "fuzz_state") {
            setRuns((items) => items.map((r) => (r.id === event.run_id ? { ...r, state: event.state } : r)));
          }
        }
        if (fresh.length > 0) {
          setResults((items) => {
            const seen = new Set(items.map((r) => r.index));
            return [...items, ...fresh.filter((r) => !seen.has(r.index))];
          });
        }
      }),
    [],
  );

  useEffect(() => {
    if (!selected) return setDetail(null);
    call<FlowDetail>("flow_detail", { id: selected.flow_id }).then(setDetail, toast);
  }, [selected]);

  const start = async () => {
    try {
      const info = await call<FuzzRunInfo>("fuzz_start", { config });
      setRuns((items) => [info, ...items]);
      setResults([]);
      setRunId(info.id);
    } catch (error) {
      toast(error);
    }
  };

  const control = (state: RunState) => {
    if (runId !== null) call("fuzz_control", { runId, runState: state }).catch(toast);
  };

  const statusCounts = useMemo(() => {
    const counts = new Map<number | null, number>();
    results.forEach((r) => counts.set(r.status, (counts.get(r.status) ?? 0) + 1));
    return [...counts].sort((a, b) => (a[0] ?? -1) - (b[0] ?? -1));
  }, [results]);

  const visibleResults = useMemo(() => results.filter((r) => !hiddenStatuses.has(r.status)), [results, hiddenStatuses]);

  const toggleStatus = (status: number | null) => {
    setHiddenStatuses((current) => {
      const next = new Set(current);
      if (!next.delete(status)) next.add(status);
      return next;
    });
  };

  const help = MODES.find((m) => m.value === mode)?.help;

  return (
    <div className="fuzzer">
      <div className="fuzz-config">
        <div className="field-row">
          <input
            className="grow"
            aria-label="Target host"
            placeholder="Host"
            value={target.host}
            onChange={(e) => setTarget({ ...target, host: e.target.value })}
          />
          <input
            className="port"
            aria-label="Target port"
            type="number"
            value={target.port}
            onChange={(e) => setTarget({ ...target, port: Number(e.target.value) })}
          />
          <label className="check">
            <input type="checkbox" checked={target.tls} onChange={(e) => setTarget({ ...target, tls: e.target.checked })} />
            TLS
          </label>
        </div>
        <div className="field-row">
          <button onClick={() => editor.current?.markSelection()}>Mark selection</button>
          <button onClick={() => setTemplate(template.replaceAll("§", ""))}>Clear marks</button>
          <span className="meta">
            {positions} position{positions === 1 ? "" : "s"}
          </span>
        </div>
        <div className="fuzz-template">
          <RawEditor value={template} onChange={setTemplate} handleRef={editor} />
        </div>
        <label className="stacked">
          Attack type
          <select value={mode} onChange={(e) => setMode(e.target.value as AttackMode)}>
            {MODES.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
        </label>
        <p className="meta">{help}</p>
        {lists.map((list, i) => (
          <PayloadEditor
            key={i}
            title={lists.length > 1 ? `Payloads for position ${i + 1}` : "Payloads"}
            draft={list}
            onChange={(next) => setLists(lists.map((item, j) => (j === i ? next : item)))}
          />
        ))}
        <div className="field-row">
          <label className="stacked">
            Parallel requests
            <input type="number" min={1} max={100} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} />
          </label>
          <label className="stacked">
            Delay (ms)
            <input type="number" min={0} value={delay} onChange={(e) => setDelay(Number(e.target.value))} />
          </label>
        </div>
        <label className="stacked">
          Highlight responses matching (regex)
          <input value={grep} onChange={(e) => setGrep(e.target.value)} />
        </label>
        {preview.error && <div className="notes">{preview.error}</div>}
        <div className="fuzz-start">
          <span className="clip meta" title={target.host}>
            {preview.total === undefined
              ? "Not ready yet"
              : `${preview.total.toLocaleString()} request${preview.total === 1 ? "" : "s"} to ${target.host}`}
          </span>
          <button className="primary" disabled={preview.total === undefined || running} onClick={start}>
            {running ? "Running…" : "Start"}
          </button>
        </div>
      </div>

      <div className="fuzz-results">
        <div className="toolbar">
          <select
            aria-label="Attack run"
            value={runId ?? ""}
            onChange={(e) => setRunId(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">Choose a run</option>
            {runs.map((item) => (
              <option key={item.id} value={item.id}>
                Run {item.id} · {item.config.target.host} · {item.state}
              </option>
            ))}
          </select>
          {run && (
            <span className="meta">
              {results.length.toLocaleString()} of {run.total.toLocaleString()} · {run.state}
            </span>
          )}
          <span className="spacer" />
          {run?.state === "running" && <button onClick={() => control("paused")}>Pause</button>}
          {run?.state === "paused" && <button onClick={() => control("running")}>Resume</button>}
          {running && <button onClick={() => control("stopped")}>Stop</button>}
        </div>
        {statusCounts.length > 0 && (
          <div className="toolbar compact">
            <span className="meta">Status</span>
            {statusCounts.map(([status, count]) => (
              <button
                key={status ?? "none"}
                className={`filter-chip ${statusClass(status)}${hiddenStatuses.has(status) ? " off" : ""}`}
                aria-pressed={!hiddenStatuses.has(status)}
                onClick={() => toggleStatus(status)}
              >
                {status ?? "No response"} · {count.toLocaleString()}
              </button>
            ))}
            {hiddenStatuses.size > 0 && (
              <>
                <button className="link" onClick={() => setHiddenStatuses(new Set())}>
                  Show all
                </button>
                <span className="meta">{visibleResults.length.toLocaleString()} shown</span>
              </>
            )}
          </div>
        )}
        {run ? (
          <ResultsTable
            results={visibleResults}
            selected={selected?.index ?? null}
            onSelect={setSelected}
            hasGrep={Boolean(run.config.grep)}
          />
        ) : (
          <p className="empty">
            Mark at least one position, add payloads, and make sure the target is in scope. Results appear here.
          </p>
        )}
        {detail && (
          <div className="detail">
            <FlowPanes detail={detail} />
          </div>
        )}
      </div>
    </div>
  );
}
