import { useEffect, useState } from "react";
import { call, toast } from "../api";
import { clipForDisplay, formatBytes, statusClass } from "../format";
import type { FlowDetail, WsFrameView } from "../types";
import { RawEditor } from "./RawEditor";

function FlowNotes({ detail }: { detail: FlowDetail }) {
  const { summary } = detail;
  const notes = [
    summary.error && `Error: ${summary.error}`,
    summary.tls_error && `Server certificate problem: ${summary.tls_error}`,
    summary.truncated && "Message was larger than the recording limit, so the stored copy is incomplete.",
    summary.edited && "This message was edited before sending.",
  ].filter(Boolean);
  if (notes.length === 0) return null;
  return (
    <div className="notes">
      {notes.map((note) => (
        <div key={note as string}>{note}</div>
      ))}
    </div>
  );
}

function FrameList({ flowId, refresh }: { flowId: number; refresh: number }) {
  const [frames, setFrames] = useState<WsFrameView[]>([]);
  useEffect(() => {
    call<WsFrameView[]>("ws_frames", { flowId }).then(setFrames, toast);
  }, [flowId, refresh]);
  if (frames.length === 0) return <p className="empty">No frames recorded yet.</p>;
  return (
    <div className="frames">
      {frames.map((frame, i) => (
        <div key={i} className={frame.from_client ? "frame out" : "frame in"}>
          <span className="frame-dir">{frame.from_client ? "Sent" : "Received"}</span>
          <code>{clipForDisplay(frame.payload.text) || `(opcode ${frame.opcode}, empty)`}</code>
        </div>
      ))}
    </div>
  );
}

/** Side-by-side read-only view of one request and its response. */
export function FlowPanes({ detail, wsRefresh = 0 }: { detail: FlowDetail; wsRefresh?: number }) {
  const [decoded, setDecoded] = useState(true);
  const [showFrames, setShowFrames] = useState(false);
  const isUpgrade = detail.summary.status === 101;
  const response = (decoded && detail.decoded_response) || detail.response;

  useEffect(() => setShowFrames(isUpgrade), [detail.summary.id, isUpgrade]);

  return (
    <div className="flow-panes">
      <FlowNotes detail={detail} />
      <div className="panes">
        <section className="pane">
          <header className="pane-head">
            <h3>Request</h3>
            <span className="meta">{formatBytes(detail.summary.request_len)}</span>
          </header>
          <RawEditor value={clipForDisplay(detail.request.text)} readOnly />
        </section>
        <section className="pane">
          <header className="pane-head">
            <h3>Response</h3>
            {detail.summary.status !== null && (
              <span className={`badge ${statusClass(detail.summary.status)}`}>{detail.summary.status}</span>
            )}
            <span className="meta">{formatBytes(detail.summary.response_len)}</span>
            <span className="spacer" />
            {isUpgrade && (
              <button className="link" onClick={() => setShowFrames(!showFrames)}>
                {showFrames ? "Show handshake" : "Show frames"}
              </button>
            )}
            {detail.decoded_response && (
              <label className="check">
                <input type="checkbox" checked={decoded} onChange={(e) => setDecoded(e.target.checked)} />
                Decompress
              </label>
            )}
          </header>
          {showFrames ? (
            <FrameList flowId={detail.summary.id} refresh={wsRefresh} />
          ) : response ? (
            <RawEditor value={clipForDisplay(response.text)} readOnly />
          ) : (
            <p className="empty">No response recorded.</p>
          )}
        </section>
      </div>
    </div>
  );
}
