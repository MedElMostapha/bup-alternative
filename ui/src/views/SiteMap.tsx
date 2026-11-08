import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { call, subscribe, toast } from "../api";
import { type MenuItem, openMenu } from "../components/ContextMenu";
import { FlowPanes } from "../components/FlowPanes";
import { Split } from "../components/Split";
import { formatBytes, statusClass } from "../format";
import { useShortcuts } from "../shortcuts";
import type { FlowActions, FlowDetail, FlowFilter, FlowSummary, SiteNode, SiteTree, Target } from "../types";

const PAGE = 1000;
const MAX_PAGE = 10_000;
const ROW_HEIGHT = 26;
const INDENT = 14;
const REFRESH_DELAY = 1000;

interface Place {
  key: string;
  target: Target;
  path: string;
}

interface Line extends Place {
  node: SiteNode;
  depth: number;
  parent: string | null;
}

const keyOf = ({ tls, host, port }: Target, path: string) => `${tls ? "https" : "http"}|${host}|${port}|${path}`;

function originOf({ tls, host, port }: Target): string {
  const name = host.includes(":") ? `[${host}]` : host;
  return `${tls ? "https" : "http"}://${name}${port === (tls ? 443 : 80) ? "" : `:${port}`}`;
}

/** The rows on screen: what is expanded, or everything that matches `query`. */
function visibleLines(trees: SiteTree[], expanded: Set<string>, query: string): Line[] {
  const lines: Line[] = [];
  const wanted = query.trim().toLowerCase();
  for (const { target, root } of trees) {
    const origin = originOf(target);
    const matches = (node: SiteNode): boolean =>
      !wanted || `${origin}${node.path}`.toLowerCase().includes(wanted) || node.children.some(matches);
    const walk = (node: SiteNode, depth: number, parent: string | null) => {
      if (!matches(node)) return;
      const key = keyOf(target, node.path);
      lines.push({ key, target, path: node.path, node, depth, parent });
      if (wanted || expanded.has(key)) node.children.forEach((child) => walk(child, depth + 1, key));
    };
    walk(root, 0, null);
  }
  return lines;
}

function keysBelow(target: Target, node: SiteNode): string[] {
  return [keyOf(target, node.path), ...node.children.flatMap((child) => keysBelow(target, child))];
}

interface Props {
  active: boolean;
  flows: FlowActions;
  /** Changes whenever a rule is added from a right-click menu. */
  scopeGeneration: number;
}

export function SiteMap({ active, flows, scopeGeneration }: Props) {
  const [trees, setTrees] = useState<SiteTree[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [inScopeOnly, setInScopeOnly] = useState(false);
  const [place, setPlace] = useState<Place | null>(null);
  const [requests, setRequests] = useState<FlowSummary[]>([]);
  const [mayHaveMore, setMayHaveMore] = useState(false);
  const [selectedFlow, setSelectedFlow] = useState<number | null>(null);
  const [detail, setDetail] = useState<FlowDetail | null>(null);
  const [refresh, setRefresh] = useState(0);
  const treeScroller = useRef<HTMLDivElement>(null);
  const tableScroller = useRef<HTMLDivElement>(null);
  const refreshTimer = useRef<number | undefined>(undefined);
  const requestCount = useRef(0);
  requestCount.current = requests.length;

  useEffect(() => {
    if (!active) return;
    let stale = false;
    call<SiteTree[]>("site_map", { inScopeOnly }).then((items) => {
      if (stale) return;
      setTrees(items);
      // History was cleared, so the selection no longer exists.
      if (items.length === 0) {
        setPlace(null);
        setSelectedFlow(null);
      }
    }, toast);
    return () => {
      stale = true;
    };
  }, [active, inScopeOnly, refresh, scopeGeneration]);

  const filterFor = (current: Place): FlowFilter => ({
    source: "proxy",
    site: { target: current.target, path: current.path },
    in_scope_only: inScopeOnly,
  });

  useEffect(() => {
    if (!active || !place) {
      setRequests([]);
      return;
    }
    let stale = false;
    // Reloading for new traffic should not throw away pages already fetched.
    const limit = Math.min(Math.max(PAGE, requestCount.current), MAX_PAGE);
    call<FlowSummary[]>("list_flows", { filter: { ...filterFor(place), limit } }).then((items) => {
      if (stale) return;
      setRequests(items);
      setMayHaveMore(items.length === limit);
    }, toast);
    return () => {
      stale = true;
    };
    // The filter is rebuilt from these on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, place, inScopeOnly, refresh, scopeGeneration]);

  useEffect(() => {
    if (selectedFlow === null) {
      setDetail(null);
      return;
    }
    call<FlowDetail>("flow_detail", { id: selectedFlow }).then(setDetail, toast);
  }, [selectedFlow]);

  useEffect(
    () =>
      subscribe((events) => {
        const changed = events.filter((e): e is Extract<typeof e, { kind: "flow" }> => e.kind === "flow");
        if (changed.length === 0) return;
        if (selectedFlow !== null && changed.some((flow) => flow.id === selectedFlow)) {
          call<FlowDetail>("flow_detail", { id: selectedFlow }).then(setDetail, toast);
        }
        // Not restarted by later events, or steady traffic would hold it off forever.
        if (refreshTimer.current !== undefined) return;
        refreshTimer.current = window.setTimeout(() => {
          refreshTimer.current = undefined;
          setRefresh((n) => n + 1);
        }, REFRESH_DELAY);
      }),
    [selectedFlow],
  );

  useEffect(() => () => window.clearTimeout(refreshTimer.current), []);

  const lines = useMemo(() => visibleLines(trees, expanded, query), [trees, expanded, query]);
  const selectedIndex = place ? lines.findIndex((line) => line.key === place.key) : -1;

  const tree = useVirtualizer({
    count: lines.length,
    getScrollElement: () => treeScroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const table = useVirtualizer({
    count: requests.length,
    getScrollElement: () => tableScroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const select = ({ key, target, path, node }: Line) => {
    setPlace({ key, target, path });
    setSelectedFlow(node.flow_id);
  };

  const setOpen = (keys: string[], open: boolean) =>
    setExpanded((current) => {
      const next = new Set(current);
      keys.forEach((key) => (open ? next.add(key) : next.delete(key)));
      return next;
    });

  const toggle = (line: Line) => setOpen([line.key], !expanded.has(line.key));

  const moveTo = (index: number) => {
    const line = lines[index];
    if (!line) return;
    select(line);
    tree.scrollToIndex(index);
  };

  const onTreeKey = (event: React.KeyboardEvent) => {
    const line = lines[selectedIndex];
    const isOpen = line && (expanded.has(line.key) || query.trim() !== "");
    const hasChildren = line && line.node.children.length > 0;
    if (event.key === "ArrowDown") moveTo(selectedIndex + 1);
    else if (event.key === "ArrowUp") moveTo(Math.max(selectedIndex - 1, 0));
    else if (event.key === "ArrowRight" && hasChildren) {
      if (isOpen) moveTo(selectedIndex + 1);
      else toggle(line);
    } else if (event.key === "ArrowLeft" && line) {
      if (isOpen && hasChildren) toggle(line);
      else moveTo(lines.findIndex((other) => other.key === line.parent));
    } else return;
    event.preventDefault();
  };

  const loadOlder = () => {
    if (!place) return;
    const before_id = requests[requests.length - 1]?.id;
    call<FlowSummary[]>("list_flows", { filter: { ...filterFor(place), before_id, limit: PAGE } }).then((items) => {
      setRequests((current) => [...current, ...items]);
      setMayHaveMore(items.length === PAGE);
    }, toast);
  };

  useShortcuts(active, {
    r: () => selectedFlow !== null && flows.send(selectedFlow, "repeater"),
    i: () => selectedFlow !== null && flows.send(selectedFlow, "fuzzer"),
  });

  const nodeMenu = (event: React.MouseEvent, line: Line) => {
    select(line);
    const { target, path, node } = line;
    const url = `${originOf(target)}${path || "/"}`;
    const copyUrl = () => void navigator.clipboard.writeText(url).then(() => toast("Copied URL"), toast);
    const requestItems: MenuItem[] =
      node.flow_id !== null
        ? flows.items(node.flow_id, path || originOf(target))
        : [
            { label: "Send to Repeater", hint: "Ctrl+R", disabled: true, onSelect: () => {} },
            { label: "Send to Fuzzer", hint: "Ctrl+I", disabled: true, onSelect: () => {} },
            { label: "Add host to scope", onSelect: () => flows.addScopeRule("include", target.host) },
            { label: "Copy URL", onSelect: copyUrl },
          ];
    const below = keysBelow(target, node);
    openMenu(event, [
      ...requestItems,
      ...(path ? [{ label: "Add this path to scope", onSelect: () => flows.addScopeRule("include", target.host, path) }] : []),
      {
        label: path ? "Exclude this path from scope" : "Exclude host from scope",
        onSelect: () => flows.addScopeRule("exclude", target.host, path),
      },
      ...(node.children.length > 0
        ? [
            { label: "Expand all below", onSelect: () => setOpen(below, true) },
            { label: "Collapse all below", onSelect: () => setOpen(below, false) },
          ]
        : []),
    ]);
  };

  const treeBody = () => {
    if (trees.length === 0) {
      return (
        <p className="empty">
          {inScopeOnly ? "Nothing in scope has been recorded yet." : "No traffic yet. Browse through the proxy and sites appear here."}
        </p>
      );
    }
    if (lines.length === 0) return <p className="empty">No paths match this filter.</p>;
    return (
      <div style={{ height: tree.getTotalSize(), position: "relative" }}>
        {tree.getVirtualItems().map((item) => {
          const line = lines[item.index];
          const { node, depth, key, target } = line;
          const isOpen = expanded.has(key) || query.trim() !== "";
          const hasChildren = node.children.length > 0;
          return (
            <div
              key={key}
              role="treeitem"
              aria-level={depth + 1}
              aria-selected={key === place?.key}
              aria-expanded={hasChildren ? isOpen : undefined}
              className={`site-node${key === place?.key ? " selected" : ""}${node.in_scope ? "" : " out-of-scope"}`}
              style={{ transform: `translateY(${item.start}px)`, paddingLeft: 6 + depth * INDENT }}
              onClick={() => select(line)}
              onDoubleClick={() => hasChildren && toggle(line)}
              onContextMenu={(event) => nodeMenu(event, line)}
            >
              <button
                className="site-toggle"
                tabIndex={-1}
                aria-label={isOpen ? "Collapse" : "Expand"}
                style={{ visibility: hasChildren ? undefined : "hidden" }}
                onClick={(event) => {
                  event.stopPropagation();
                  toggle(line);
                }}
                onDoubleClick={(event) => event.stopPropagation()}
              >
                {isOpen ? "▾" : "▸"}
              </button>
              <span className="clip site-name" title={`${originOf(target)}${node.path || "/"}`}>
                {depth === 0 ? originOf(target) : node.name || "(empty)"}
              </span>
              {node.status !== null && <span className={statusClass(node.status)}>{node.status}</span>}
              <span className="meta">{node.requests.toLocaleString()}</span>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <Split id="site-map" direction="row" initial={0.3} min={220} className="site-map">
      <div className="site-tree">
        <div className="toolbar">
          <input
            className="grow"
            placeholder="Filter hosts and paths"
            aria-label="Filter hosts and paths"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <label className="check">
            <input type="checkbox" checked={inScopeOnly} onChange={(e) => setInScopeOnly(e.target.checked)} />
            In scope
          </label>
        </div>
        <div className="site-scroll" role="tree" aria-label="Site map" tabIndex={0} ref={treeScroller} onKeyDown={onTreeKey}>
          {treeBody()}
        </div>
      </div>

      <Split id="site-requests" direction="column" initial={0.4} min={100}>
        {place ? (
          <div className="table-wrap">
            <div className="table-row site-row table-head" role="row">
              {["#", "Method", "Path", "Status", "Size", "ms", "Type"].map((label) => (
                <span key={label}>{label}</span>
              ))}
            </div>
            <div className="table-body" ref={tableScroller}>
              {requests.length === 0 ? (
                <p className="empty">No requests here.</p>
              ) : (
                <div style={{ height: table.getTotalSize(), position: "relative" }}>
                  {table.getVirtualItems().map((item) => {
                    const row = requests[item.index];
                    return (
                      <div
                        key={row.id}
                        role="row"
                        className={`table-row site-row${row.id === selectedFlow ? " selected" : ""}${row.error ? " failed" : ""}`}
                        style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${item.start}px)` }}
                        onClick={() => setSelectedFlow(row.id)}
                        onContextMenu={(event) => {
                          setSelectedFlow(row.id);
                          flows.menu(event, row.id, `#${row.id}`);
                        }}
                      >
                        <span className="num">{row.id}</span>
                        <span className="method">{row.method}</span>
                        <span className="clip" title={row.path}>
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
        ) : (
          <div className="detail placeholder">Select a host or path to see its requests.</div>
        )}
        {place && detail && (
          <div className="detail">
            <FlowPanes detail={detail} flows={flows} label={`#${detail.summary.id}`} />
          </div>
        )}
      </Split>
    </Split>
  );
}
