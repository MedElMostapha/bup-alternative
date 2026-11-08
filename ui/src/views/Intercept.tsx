import { useEffect, useState } from "react";
import { call, toast } from "../api";
import { RawEditor } from "../components/RawEditor";
import type { Decision, PendingView } from "../types";

interface Props {
  queue: PendingView[];
  onQueueChange: (queue: PendingView[]) => void;
}

export function Intercept({ queue, onQueueChange }: Props) {
  const [requests, setRequests] = useState(false);
  const [responses, setResponses] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [text, setText] = useState("");

  const selected = queue.find((item) => item.id === selectedId) ?? queue[0] ?? null;

  useEffect(() => {
    setSelectedId(selected?.id ?? null);
    setText(selected?.raw.text ?? "");
    // Only a change of message should reset the editor, not each keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  const configure = (nextRequests: boolean, nextResponses: boolean) => {
    setRequests(nextRequests);
    setResponses(nextResponses);
    call("configure_intercept", { requests: nextRequests, responses: nextResponses })
      .then(() => call<PendingView[]>("queued_intercepts"))
      .then(onQueueChange, toast);
  };

  const decide = async (decision: Decision) => {
    if (!selected) return;
    try {
      await call("resolve_intercept", { id: selected.id, decision });
      onQueueChange(queue.filter((item) => item.id !== selected.id));
    } catch (error) {
      toast(error);
    }
  };

  const forward = () => {
    if (!selected) return;
    const unchanged = text === selected.raw.text;
    void decide(unchanged ? { action: "forward" } : { action: "edited", raw: { text, encoding: selected.raw.encoding } });
  };

  return (
    <div className="intercept">
      <div className="toolbar">
        <label className="check">
          <input type="checkbox" checked={requests} onChange={(e) => configure(e.target.checked, responses)} />
          Pause requests
        </label>
        <label className="check">
          <input type="checkbox" checked={responses} onChange={(e) => configure(requests, e.target.checked)} />
          Pause responses
        </label>
        <span className="meta">Applies to in-scope traffic. Turning a switch off releases anything waiting.</span>
        <span className="spacer" />
        <button className="primary" disabled={!selected} onClick={forward}>
          {selected && text !== selected.raw.text ? "Forward edited" : "Forward"}
        </button>
        <button disabled={!selected} onClick={() => void decide({ action: "drop" })}>
          Drop
        </button>
      </div>
      <div className="intercept-body">
        <aside className="queue">
          {queue.length === 0 && <p className="empty">Nothing is waiting.</p>}
          {queue.map((item) => (
            <button
              key={item.id}
              className={`queue-item${item.id === selected?.id ? " selected" : ""}`}
              onClick={() => setSelectedId(item.id)}
            >
              <span className={`tag ${item.direction === "response" ? "alt" : ""}`}>{item.direction}</span>
              <span className="clip">{item.target.host}</span>
              <span className="clip dim">{item.raw.text.split("\n", 1)[0]}</span>
            </button>
          ))}
        </aside>
        <section className="pane">
          {selected ? (
            <RawEditor value={text} onChange={setText} />
          ) : (
            <p className="empty">Turn on pausing, then browse through the proxy. Held messages appear here to edit.</p>
          )}
        </section>
      </div>
    </div>
  );
}
