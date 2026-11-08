import { useEffect, useRef, useState } from "react";
import { call, toast } from "../api";
import { RawEditor } from "../components/RawEditor";
import { clipForDisplay, formatBytes, statusClass } from "../format";
import type { FlowDetail, FlowSummary, RepeaterTab, RequestDraft, Target } from "../types";

const BLANK_REQUEST = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
const SAVE_DELAY = 400;

export function Repeater({ draft, onDraftUsed }: { draft: RequestDraft | null; onDraftUsed: () => void }) {
  const [tabs, setTabs] = useState<RepeaterTab[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [results, setResults] = useState<Record<number, FlowDetail>>({});
  const [sending, setSending] = useState<Record<number, boolean>>({});
  const [sends, setSends] = useState<FlowSummary[]>([]);
  const [normalize, setNormalize] = useState(true);
  const saveTimer = useRef<number | undefined>(undefined);

  const active = tabs.find((tab) => tab.id === activeId) ?? null;
  const result = active ? results[active.id] : undefined;

  useEffect(() => {
    call<RepeaterTab[]>("list_tabs").then((items) => {
      setTabs(items);
      setActiveId((current) => current ?? items[0]?.id ?? null);
    }, toast);
  }, []);

  const addTab = async (name: string, target: Target, request: RequestDraft["request"]) => {
    try {
      const tab = await call<RepeaterTab>("create_tab", { name, target, request });
      setTabs((current) => [...current, tab]);
      setActiveId(tab.id);
    } catch (error) {
      toast(error);
    }
  };

  useEffect(() => {
    if (!draft) return;
    void addTab(draft.label, draft.target, draft.request);
    onDraftUsed();
    // Each draft is consumed exactly once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft?.nonce]);

  useEffect(() => {
    if (activeId === null) return setSends([]);
    call<FlowSummary[]>("tab_sends", { tabId: activeId }).then(setSends, toast);
  }, [activeId, result]);

  const change = (patch: Partial<RepeaterTab>) => {
    if (!active) return;
    const next = { ...active, ...patch };
    setTabs((current) => current.map((tab) => (tab.id === next.id ? next : tab)));
    window.clearTimeout(saveTimer.current);
    saveTimer.current = window.setTimeout(() => call("update_tab", { tab: next }).catch(toast), SAVE_DELAY);
  };

  const changeTarget = (patch: Partial<Target>) => active && change({ target: { ...active.target, ...patch } });

  const closeTab = (id: number) => {
    call("delete_tab", { id }).catch(toast);
    const remaining = tabs.filter((tab) => tab.id !== id);
    setTabs(remaining);
    if (activeId === id) setActiveId(remaining[0]?.id ?? null);
  };

  const send = async () => {
    if (!active) return;
    const id = active.id;
    setSending((current) => ({ ...current, [id]: true }));
    try {
      const detail = await call<FlowDetail>("repeater_send", {
        send: { tab_id: id, target: active.target, request: active.request, normalize, timeout_ms: 30000 },
      });
      setResults((current) => ({ ...current, [id]: detail }));
    } catch (error) {
      toast(error);
    } finally {
      setSending((current) => ({ ...current, [id]: false }));
    }
  };

  const openPrevious = (flowId: number) => {
    if (!active) return;
    const id = active.id;
    call<FlowDetail>("flow_detail", { id: flowId }).then(
      (detail) => setResults((current) => ({ ...current, [id]: detail })),
      toast,
    );
  };

  const response = result?.decoded_response ?? result?.response;
  const busy = active ? sending[active.id] : false;

  return (
    <div className="repeater">
      <div className="tab-strip" role="tablist">
        {tabs.map((tab) => (
          <div key={tab.id} className={`tab${tab.id === activeId ? " selected" : ""}`}>
            <button role="tab" aria-selected={tab.id === activeId} onClick={() => setActiveId(tab.id)}>
              {tab.name}
            </button>
            <button className="close" aria-label={`Close ${tab.name}`} onClick={() => closeTab(tab.id)}>
              ×
            </button>
          </div>
        ))}
        <button
          className="add"
          aria-label="New tab"
          onClick={() =>
            void addTab("New request", { host: "localhost", port: 80, tls: false }, { text: BLANK_REQUEST, encoding: "utf8" })
          }
        >
          +
        </button>
      </div>

      {active ? (
        <>
          <div className="toolbar">
            <button className="primary" disabled={busy} onClick={send}>
              {busy ? "Sending…" : "Send"}
            </button>
            <button disabled={!busy} onClick={() => call("repeater_cancel", { tabId: active.id }).catch(toast)}>
              Cancel
            </button>
            <input
              className="grow"
              aria-label="Target host"
              placeholder="Host"
              value={active.target.host}
              onChange={(e) => changeTarget({ host: e.target.value })}
            />
            <input
              className="port"
              aria-label="Target port"
              type="number"
              min={1}
              max={65535}
              value={active.target.port}
              onChange={(e) => changeTarget({ port: Number(e.target.value) })}
            />
            <label className="check">
              <input type="checkbox" checked={active.target.tls} onChange={(e) => changeTarget({ tls: e.target.checked })} />
              TLS
            </label>
            <label className="check" title="Converts line endings in the headers to CRLF and updates Content-Length">
              <input type="checkbox" checked={normalize} onChange={(e) => setNormalize(e.target.checked)} />
              Fix line endings and length
            </label>
            <select
              aria-label="Earlier sends"
              value=""
              onChange={(e) => e.target.value && openPrevious(Number(e.target.value))}
            >
              <option value="">{sends.length} earlier sends</option>
              {sends.map((item) => (
                <option key={item.id} value={item.id}>
                  #{item.id} · {item.status ?? item.error ?? "no response"} · {item.path.slice(0, 40)}
                </option>
              ))}
            </select>
          </div>
          <div className="panes">
            <section className="pane">
              <header className="pane-head">
                <h3>Request</h3>
              </header>
              <RawEditor
                value={active.request.text}
                onChange={(text) => change({ request: { ...active.request, text } })}
              />
            </section>
            <section className="pane">
              <header className="pane-head">
                <h3>Response</h3>
                {result?.summary.status != null && (
                  <span className={`badge ${statusClass(result.summary.status)}`}>{result.summary.status}</span>
                )}
                {result && (
                  <span className="meta">
                    {formatBytes(result.summary.response_len)} · {result.summary.duration_ms ?? 0} ms
                  </span>
                )}
              </header>
              {result?.summary.error && <div className="notes">Error: {result.summary.error}</div>}
              {response ? (
                <RawEditor value={clipForDisplay(response.text)} readOnly />
              ) : (
                <p className="empty">Send the request to see the response.</p>
              )}
            </section>
          </div>
        </>
      ) : (
        <p className="empty">Use + to start a request, or send one here from Proxy history.</p>
      )}
    </div>
  );
}
