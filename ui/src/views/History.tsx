import { useCallback, useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { call, subscribe, toast } from "../api";
import { FlowPanes } from "../components/FlowPanes";
import { Split } from "../components/Split";
import { formatBytes, formatTime, statusClass } from "../format";
import { useShortcuts } from "../shortcuts";
import type { FlowActions, FlowDetail, FlowFilter, FlowSummary, SortColumn } from "../types";

const PAGE = 1000;
const MAX_PAGE = 10_000;
const ROW_HEIGHT = 26;

const COLUMNS: Array<{ column: SortColumn; label: string; biggestFirst?: boolean }> = [
  { column: "id", label: "#" },
  { column: "started_ms", label: "Time", biggestFirst: true },
  { column: "method", label: "Method" },
  { column: "host", label: "Host" },
  { column: "path", label: "Path" },
  { column: "status", label: "Status", biggestFirst: true },
  { column: "response_len", label: "Size", biggestFirst: true },
  { column: "duration_ms", label: "ms", biggestFirst: true },
  { column: "mime", label: "Type" },
];

interface Props {
  active: boolean;
  flows: FlowActions;
}

function hasFilter(filter: FlowFilter): boolean {
  return Boolean(
    filter.host || filter.method || filter.status_class || filter.mime || filter.text || filter.in_scope_only,
  );
}

export function History({ active, flows }: Props) {
  const [rows, setRows] = useState<FlowSummary[]>([]);
  const [filter, setFilter] = useState<FlowFilter>({ source: "proxy" });
  const [selected, setSelected] = useState<number | null>(null);
  const [detail, setDetail] = useState<FlowDetail | null>(null);
  const [wsRefresh, setWsRefresh] = useState(0);
  const [mayHaveMore, setMayHaveMore] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);
  const reloadTimer = useRef<number | undefined>(undefined);

  const rowCount = useRef(0);
  rowCount.current = rows.length;

  const load = useCallback(() => {
    // Reloading for new traffic should not throw away pages already fetched.
    const limit = Math.min(Math.max(PAGE, rowCount.current), MAX_PAGE);
    call<FlowSummary[]>("list_flows", { filter: { ...filter, limit } }).then((items) => {
      setRows(items);
      setMayHaveMore(items.length === limit);
    }, toast);
  }, [filter]);

  useEffect(() => {
    const timer = window.setTimeout(load, 200);
    return () => window.clearTimeout(timer);
  }, [load]);

  useEffect(
    () =>
      subscribe((events) => {
        const flows = events.filter((e): e is Extract<typeof e, { kind: "flow" }> => e.kind === "flow");
        if (events.some((e) => e.kind === "ws_frame")) setWsRefresh((n) => n + 1);
        if (flows.length === 0) return;
        if (hasFilter(filter) || filter.sort) {
          // Only the backend can evaluate text and scope filters, and sort.
          window.clearTimeout(reloadTimer.current);
          reloadTimer.current = window.setTimeout(load, 500);
          return;
        }
        setRows((current) => {
          const updates = new Map(flows.map((flow) => [flow.id, flow]));
          const merged = current.map((row) => {
            const update = updates.get(row.id);
            if (update) updates.delete(row.id);
            return update ?? row;
          });
          return [...[...updates.values()].sort((a, b) => b.id - a.id), ...merged];
        });
        if (selected !== null && flows.some((flow) => flow.id === selected)) {
          call<FlowDetail>("flow_detail", { id: selected }).then(setDetail, toast);
        }
      }),
    [filter, load, selected],
  );

  useEffect(() => {
    if (selected === null) {
      setDetail(null);
      return;
    }
    call<FlowDetail>("flow_detail", { id: selected }).then(setDetail, toast);
  }, [selected]);

  const loadOlder = () => {
    const page = filter.sort ? { offset: rows.length } : { before_id: rows[rows.length - 1]?.id };
    call<FlowSummary[]>("list_flows", { filter: { ...filter, ...page, limit: PAGE } }).then((items) => {
      setRows((current) => [...current, ...items]);
      setMayHaveMore(items.length === PAGE);
    }, toast);
  };

  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const update = (patch: Partial<FlowFilter>) => setFilter((current) => ({ ...current, ...patch }));

  useShortcuts(active, {
    r: () => selected !== null && flows.send(selected, "repeater"),
    i: () => selected !== null && flows.send(selected, "fuzzer"),
  });

  const sortBy = ({ column, biggestFirst }: (typeof COLUMNS)[number]) => {
    const current = filter.sort ?? "id";
    if (current !== column) return update({ sort: column, ascending: !biggestFirst });
    // Back on # after a full cycle is the default, newest-first order.
    if (column === "id" && filter.sort) return update({ sort: undefined, ascending: undefined });
    if (column === "id") return update({ sort: "id", ascending: true });
    update({ ascending: !filter.ascending });
  };

  const sortMark = (column: SortColumn) => {
    if ((filter.sort ?? "id") !== column) return "";
    return filter.sort && filter.ascending ? " ↑" : " ↓";
  };

  const clearAll = async () => {
    if (!window.confirm("Delete all captured proxy history from this project? This cannot be undone.")) return;
    try {
      await call("clear_history");
      setSelected(null);
      load();
    } catch (error) {
      toast(error);
    }
  };

  return (
    <div className="history">
      <div className="toolbar">
        <input
          placeholder="Host"
          aria-label="Filter by host"
          value={filter.host ?? ""}
          onChange={(e) => update({ host: e.target.value || undefined })}
        />
        <select
          aria-label="Filter by method"
          value={filter.method ?? ""}
          onChange={(e) => update({ method: e.target.value || undefined })}
        >
          <option value="">Any method</option>
          {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <select
          aria-label="Filter by status"
          value={filter.status_class ?? ""}
          onChange={(e) => update({ status_class: e.target.value ? Number(e.target.value) : undefined })}
        >
          <option value="">Any status</option>
          {[1, 2, 3, 4, 5].map((c) => (
            <option key={c} value={c}>
              {c}xx
            </option>
          ))}
        </select>
        <input
          placeholder="Content type"
          aria-label="Filter by content type"
          value={filter.mime ?? ""}
          onChange={(e) => update({ mime: e.target.value || undefined })}
        />
        <input
          className="grow"
          placeholder="Search raw requests and responses"
          aria-label="Search raw messages"
          value={filter.text ?? ""}
          onChange={(e) => update({ text: e.target.value || undefined })}
        />
        <label className="check">
          <input
            type="checkbox"
            checked={filter.in_scope_only ?? false}
            onChange={(e) => update({ in_scope_only: e.target.checked })}
          />
          In scope
        </label>
        <button onClick={clearAll}>Clear</button>
      </div>

      <Split id="history" direction="column" initial={0.45} min={100}>
        <div className="table-wrap">
          <div className="table-row table-head" role="row">
            {COLUMNS.map((entry) => (
              <button key={entry.column} className="sort" onClick={() => sortBy(entry)}>
                {entry.label}
                {sortMark(entry.column)}
              </button>
            ))}
          </div>
          <div className="table-body" ref={scroller}>
            {rows.length === 0 ? (
              <p className="empty">
                No traffic yet. Point your browser at the proxy address shown above and install the certificate from
                Settings.
              </p>
            ) : (
              <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
                {virtual.getVirtualItems().map((item) => {
                  const row = rows[item.index];
                  return (
                    <div
                      key={row.id}
                      role="row"
                      className={`table-row${row.id === selected ? " selected" : ""}${row.error ? " failed" : ""}`}
                      style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${item.start}px)` }}
                      onClick={() => setSelected(row.id)}
                      onContextMenu={(event) => {
                        setSelected(row.id);
                        flows.menu(event, row.id, `#${row.id}`);
                      }}
                    >
                      <span className="num">{row.id}</span>
                      <span className="dim">{formatTime(row.started_ms)}</span>
                      <span className="method">{row.method}</span>
                      <span className="clip" title={`${row.tls ? "https" : "http"}://${row.host}:${row.port}`}>
                        {row.tls && <span className="lock">TLS </span>}
                        {row.host}
                      </span>
                      <span className="clip" title={row.path}>
                        {row.edited && <span className="tag">edited</span>}
                        {row.tls_error && <span className="tag warn">cert</span>}
                        {row.path}
                      </span>
                      <span className={statusClass(row.status)}>{row.status ?? (row.complete ? "—" : "…")}</span>
                      <span className="num">{formatBytes(row.response_len)}</span>
                      <span className="num">{row.duration_ms ?? ""}</span>
                      <span className="clip dim">{row.mime}</span>
                    </div>
                  );
                })}
              </div>
            )}
            {mayHaveMore && (
              <button className="load-more" onClick={loadOlder}>
                Load older
              </button>
            )}
          </div>
        </div>

        {detail ? (
          <div className="detail">
            <FlowPanes detail={detail} flows={flows} label={`#${detail.summary.id}`} wsRefresh={wsRefresh} />
          </div>
        ) : (
          <div className="detail placeholder">Select a row to see the request and response.</div>
        )}
      </Split>
    </div>
  );
}
