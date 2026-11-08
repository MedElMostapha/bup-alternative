import { useCallback, useEffect, useState } from "react";
import { call, subscribe, subscribeToasts, toast } from "./api";
import { MenuHost, openMenu } from "./components/ContextMenu";
import { draftOf } from "./format";
import { useShortcuts } from "./shortcuts";
import type { BrowserInfo, BrowserKind, CompareSide, ComparerDraft, FlowActions, FlowDetail, PendingView, ProxyStatus, RequestDraft, Scope } from "./types";
import { Comparer } from "./views/Comparer";
import { Decoder } from "./views/Decoder";
import { Findings } from "./views/Findings";
import { Fuzzer } from "./views/Fuzzer";
import { History } from "./views/History";
import { Intercept } from "./views/Intercept";
import { MatchReplace } from "./views/MatchReplace";
import { Repeater } from "./views/Repeater";
import { Settings } from "./views/Settings";
import { SiteMap } from "./views/SiteMap";

type View = "intercept" | "history" | "sitemap" | "repeater" | "fuzzer" | "decoder" | "comparer" | "match" | "findings" | "settings";

const VIEWS: Array<{ id: View; label: string }> = [
  { id: "intercept", label: "Intercept" },
  { id: "history", label: "History" },
  { id: "sitemap", label: "Site map" },
  { id: "repeater", label: "Repeater" },
  { id: "fuzzer", label: "Fuzzer" },
  { id: "decoder", label: "Decoder" },
  { id: "comparer", label: "Comparer" },
  { id: "match", label: "Match & Replace" },
  { id: "findings", label: "Findings" },
  { id: "settings", label: "Settings" },
];

const TOAST_DURATION = 6000;
const BROWSER_NAMES: Record<BrowserKind, string> = { chrome: "Chrome", firefox: "Firefox" };

export function App() {
  const [view, setView] = useState<View>("history");
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [queue, setQueue] = useState<PendingView[]>([]);
  const [repeaterDraft, setRepeaterDraft] = useState<RequestDraft | null>(null);
  const [fuzzerDraft, setFuzzerDraft] = useState<RequestDraft | null>(null);
  const [compareFirst, setCompareFirst] = useState<CompareSide | null>(null);
  const [comparerDraft, setComparerDraft] = useState<ComparerDraft | null>(null);
  const [activeRules, setActiveRules] = useState(0);
  const [scopeGeneration, setScopeGeneration] = useState(0);
  const [message, setMessage] = useState<string | null>(null);
  const [browsers, setBrowsers] = useState<BrowserInfo[]>([]);
  const [opening, setOpening] = useState<BrowserKind | null>(null);
  // Remounting the views is how they pick up a newly opened project.
  const [projectGeneration, setProjectGeneration] = useState(0);

  useEffect(() => {
    call<ProxyStatus>("proxy_status").then(setStatus, toast);
    call<PendingView[]>("queued_intercepts").then(setQueue, toast);
  }, [projectGeneration]);

  useEffect(() => {
    call<BrowserInfo[]>("available_browsers").then(setBrowsers, toast);
  }, []);

  const openBrowser = (kind: BrowserKind) => {
    setOpening(kind);
    call("launch_browser", { kind })
      .catch(toast)
      .finally(() => setOpening(null));
  };

  useEffect(
    () =>
      subscribe((events) => {
        setQueue((current) => {
          let next = current;
          for (const event of events) {
            if (event.kind === "intercept_queued" && !next.some((p) => p.id === event.id)) next = [...next, event];
            if (event.kind === "intercept_cleared") next = next.filter((p) => p.id !== event.id);
          }
          return next;
        });
      }),
    [],
  );

  useEffect(() => {
    let timer: number | undefined;
    return subscribeToasts((text) => {
      setMessage(text);
      window.clearTimeout(timer);
      timer = window.setTimeout(() => setMessage(null), TOAST_DURATION);
    });
  }, []);

  const handleDraft = useCallback((destination: "repeater" | "fuzzer", draft: RequestDraft) => {
    if (destination === "repeater") setRepeaterDraft(draft);
    else setFuzzerDraft(draft);
    setView(destination);
  }, []);

  const handleCompare = useCallback(
    (side: CompareSide) => {
      if (!compareFirst) {
        setCompareFirst(side);
        toast(`${side.label} is ready. Right-click another response and choose Compare.`);
        return;
      }
      setComparerDraft({ a: compareFirst, b: side, nonce: Date.now() });
      setCompareFirst(null);
      setView("comparer");
    },
    [compareFirst],
  );

  const sendFlow = useCallback<FlowActions["send"]>(
    (id, destination) => {
      call<FlowDetail>("flow_detail", { id }).then((detail) => handleDraft(destination, draftOf(detail)), toast);
    },
    [handleDraft],
  );

  const compareFlow = (id: number, label: string) => {
    call<FlowDetail>("flow_detail", { id }).then((detail) => {
      const raw = detail.decoded_response ?? detail.response;
      if (raw) handleCompare({ flowId: id, label, raw });
      else toast("No response was recorded for this row");
    }, toast);
  };

  const copyUrl = (id: number) => {
    call<FlowDetail>("flow_detail", { id })
      .then(({ target: { tls, host, port }, summary: { path } }) => {
        const defaultPort = tls ? 443 : 80;
        return navigator.clipboard.writeText(`${tls ? "https" : "http"}://${host}${port === defaultPort ? "" : `:${port}`}${path}`);
      })
      .then(() => toast("Copied URL"), toast);
  };

  const addScopeRule: FlowActions["addScopeRule"] = async (list, host, path_prefix = "") => {
    const place = `${host}${path_prefix}`;
    try {
      const scope = await call<Scope>("get_scope");
      if (scope[list].some((rule) => rule.host === host && rule.path_prefix === path_prefix)) {
        toast(`${place} is already ${list === "include" ? "in scope" : "excluded"}`);
        return;
      }
      scope[list].push({ host, path_prefix });
      await call("set_scope", { scope });
      toast(list === "include" ? `Added ${place} to scope` : `Excluded ${place} from scope`);
      setScopeGeneration((n) => n + 1);
    } catch (error) {
      toast(error);
    }
  };

  const addHostToScope = (id: number) => {
    call<FlowDetail>("flow_detail", { id }).then(({ target: { host } }) => addScopeRule("include", host), toast);
  };

  const flowItems: FlowActions["items"] = (id, label, selection) => [
    ...(selection ? [{ label: "Copy", hint: "Ctrl+C", onSelect: () => void navigator.clipboard.writeText(selection).catch(toast) }] : []),
    { label: "Send to Repeater", hint: "Ctrl+R", onSelect: () => sendFlow(id, "repeater") },
    { label: "Send to Fuzzer", hint: "Ctrl+I", onSelect: () => sendFlow(id, "fuzzer") },
    {
      label: compareFirst ? `Compare with ${compareFirst.label}` : "Compare",
      disabled: compareFirst?.flowId === id,
      onSelect: () => compareFlow(id, label),
    },
    ...(compareFirst ? [{ label: "Cancel compare", onSelect: () => setCompareFirst(null) }] : []),
    { label: "Add host to scope", onSelect: () => addHostToScope(id) },
    { label: "Copy URL", onSelect: () => copyUrl(id) },
  ];

  const flows: FlowActions = {
    send: sendFlow,
    menu: (event, id, label, selection) => openMenu(event, flowItems(id, label, selection)),
    items: flowItems,
    addScopeRule,
  };

  const viewShortcuts = Object.fromEntries(VIEWS.map(({ id }, i) => [String(i + 1), () => setView(id)]));
  // Ctrl+R would otherwise reload the window and lose whatever is unsaved.
  useShortcuts(true, { r: () => {}, ...viewShortcuts });

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">Sluice</span>
        <nav aria-label="Main">
          {VIEWS.map(({ id, label }, i) => (
            <button
              key={id}
              className={view === id ? "nav selected" : "nav"}
              aria-current={view === id}
              title={i < 9 ? `Ctrl+${i + 1}` : undefined}
              onClick={() => setView(id)}
            >
              {label}
              {id === "intercept" && queue.length > 0 && <span className="count">{queue.length}</span>}
              {id === "match" && activeRules > 0 && (
                <span className="count" title={`${activeRules} active rule${activeRules === 1 ? "" : "s"}`}>
                  {activeRules}
                </span>
              )}
            </button>
          ))}
        </nav>
        <span className="spacer" />
        {browsers.map(({ kind }) => (
          <button
            key={kind}
            disabled={opening !== null || !status?.running}
            title={status?.running ? "Opens a separate profile already set up for this proxy" : "Start the proxy first"}
            onClick={() => openBrowser(kind)}
          >
            {opening === kind ? "Opening…" : `Open ${BROWSER_NAMES[kind]}`}
          </button>
        ))}
        <button className="listener" onClick={() => setView("settings")} title={status?.running ? `Listening on ${status.address}` : "Proxy listener settings"}>
          <span className={status?.running ? "dot on" : "dot"} />
          {status?.running ? status.address : status?.error ? "Proxy failed to start" : "Proxy stopped"}
        </button>
      </header>

      <main key={projectGeneration}>
        <div className="view" hidden={view !== "intercept"}>
          <Intercept queue={queue} onQueueChange={setQueue} active={view === "intercept"} onDraft={handleDraft} />
        </div>
        <div className="view" hidden={view !== "history"}>
          <History active={view === "history"} flows={flows} />
        </div>
        <div className="view" hidden={view !== "sitemap"}>
          <SiteMap active={view === "sitemap"} flows={flows} scopeGeneration={scopeGeneration} />
        </div>
        <div className="view" hidden={view !== "repeater"}>
          <Repeater draft={repeaterDraft} onDraftUsed={() => setRepeaterDraft(null)} active={view === "repeater"} />
        </div>
        <div className="view" hidden={view !== "fuzzer"}>
          <Fuzzer draft={fuzzerDraft} onDraftUsed={() => setFuzzerDraft(null)} active={view === "fuzzer"} flows={flows} />
        </div>
        <div className="view" hidden={view !== "decoder"}>
          <Decoder />
        </div>
        <div className="view" hidden={view !== "comparer"}>
          <Comparer draft={comparerDraft} onDraftUsed={() => setComparerDraft(null)} active={view === "comparer"} />
        </div>
        <div className="view" hidden={view !== "match"}>
          <MatchReplace onActiveCount={setActiveRules} />
        </div>
        <div className="view" hidden={view !== "findings"}>
          <Findings active={view === "findings"} flows={flows} />
        </div>
        <div className="view" hidden={view !== "settings"}>
          <Settings
            active={view === "settings"}
            status={status}
            onStatus={setStatus}
            onProjectChange={() => setProjectGeneration((n) => n + 1)}
          />
        </div>
      </main>

      <MenuHost />

      {message && (
        <div className="toast" role="status">
          {message}
        </div>
      )}
    </div>
  );
}
