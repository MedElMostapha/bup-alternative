import { useCallback, useEffect, useState } from "react";
import { call, subscribe, subscribeToasts, toast } from "./api";
import type { BrowserInfo, BrowserKind, PendingView, ProxyStatus, RequestDraft } from "./types";
import { Findings } from "./views/Findings";
import { Fuzzer } from "./views/Fuzzer";
import { History } from "./views/History";
import { Intercept } from "./views/Intercept";
import { Repeater } from "./views/Repeater";
import { Settings } from "./views/Settings";

type View = "intercept" | "history" | "repeater" | "fuzzer" | "findings" | "settings";

const VIEWS: Array<{ id: View; label: string }> = [
  { id: "intercept", label: "Intercept" },
  { id: "history", label: "History" },
  { id: "repeater", label: "Repeater" },
  { id: "fuzzer", label: "Fuzzer" },
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

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">Sluice</span>
        <nav aria-label="Main">
          {VIEWS.map(({ id, label }) => (
            <button key={id} className={view === id ? "nav selected" : "nav"} aria-current={view === id} onClick={() => setView(id)}>
              {label}
              {id === "intercept" && queue.length > 0 && <span className="count">{queue.length}</span>}
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
          <Intercept queue={queue} onQueueChange={setQueue} />
        </div>
        <div className="view" hidden={view !== "history"}>
          <History onDraft={handleDraft} />
        </div>
        <div className="view" hidden={view !== "repeater"}>
          <Repeater draft={repeaterDraft} onDraftUsed={() => setRepeaterDraft(null)} />
        </div>
        <div className="view" hidden={view !== "fuzzer"}>
          <Fuzzer draft={fuzzerDraft} onDraftUsed={() => setFuzzerDraft(null)} active={view === "fuzzer"} />
        </div>
        <div className="view" hidden={view !== "findings"}>
          <Findings />
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

      {message && (
        <div className="toast" role="status">
          {message}
        </div>
      )}
    </div>
  );
}
