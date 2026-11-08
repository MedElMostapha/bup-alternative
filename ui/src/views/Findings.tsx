import { useEffect, useMemo, useState } from "react";
import { call, subscribe, toast } from "../api";
import { FlowPanes } from "../components/FlowPanes";
import { Split } from "../components/Split";
import { useShortcuts } from "../shortcuts";
import type { Finding, FlowActions, FlowDetail, Severity } from "../types";

const ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const LEVELS: Severity[] = ["high", "medium", "low", "info"];

export function Findings({ active, flows }: { active: boolean; flows: FlowActions }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [hidden, setHidden] = useState<Set<Severity>>(new Set());
  const [selected, setSelected] = useState<Finding | null>(null);
  const [detail, setDetail] = useState<FlowDetail | null>(null);

  useEffect(() => {
    call<Finding[]>("list_findings").then(setFindings, toast);
  }, []);

  useEffect(
    () =>
      subscribe((events) => {
        const fresh = events.filter((e): e is Extract<typeof e, { kind: "finding" }> => e.kind === "finding");
        if (fresh.length > 0) setFindings((current) => [...fresh, ...current]);
      }),
    [],
  );

  useEffect(() => {
    if (!selected) return setDetail(null);
    call<FlowDetail>("flow_detail", { id: selected.flow_id }).then(setDetail, toast);
  }, [selected]);

  const counts = useMemo(() => {
    const totals: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((finding) => (totals[finding.severity] += 1));
    return totals;
  }, [findings]);

  const visible = useMemo(
    () =>
      findings
        .filter((finding) => !hidden.has(finding.severity))
        .sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || a.host.localeCompare(b.host)),
    [findings, hidden],
  );

  useShortcuts(active, {
    r: () => selected && flows.send(selected.flow_id, "repeater"),
    i: () => selected && flows.send(selected.flow_id, "fuzzer"),
  });

  const toggle = (level: Severity) => {
    setHidden((current) => {
      const next = new Set(current);
      if (!next.delete(level)) next.add(level);
      return next;
    });
  };

  return (
    <Split id="findings" direction="row" initial={0.28} min={220} className="findings">
      <aside className="finding-list">
        <div className="toolbar">
          {LEVELS.map((level) => (
            <button
              key={level}
              className={`filter-chip sev-${level}${hidden.has(level) ? " off" : ""}`}
              aria-pressed={!hidden.has(level)}
              onClick={() => toggle(level)}
            >
              {level} {counts[level]}
            </button>
          ))}
        </div>
        <div className="finding-scroll">
          {visible.length === 0 && (
            <p className="empty">Nothing to report yet. Findings appear as traffic passes through the proxy.</p>
          )}
          {visible.map((finding) => (
            <button
              key={`${finding.rule}|${finding.host}|${finding.dedupe}`}
              className={`finding${finding === selected ? " selected" : ""}`}
              onClick={() => setSelected(finding)}
              onContextMenu={(event) => {
                setSelected(finding);
                flows.menu(event, finding.flow_id, finding.title.slice(0, 32));
              }}
            >
              <span className={`dot sev-${finding.severity}`} aria-label={finding.severity} />
              <span className="finding-text">
                <span className="clip">{finding.title}</span>
                <span className="clip dim">
                  {finding.host}
                  {finding.path}
                </span>
              </span>
            </button>
          ))}
        </div>
      </aside>
      <section className="finding-detail">
        {selected ? (
          <>
            <div className="finding-summary">
              <h2>{selected.title}</h2>
              <p>{selected.detail}</p>
              <p className="evidence">
                <span className={`badge sev-${selected.severity}`}>{selected.severity}</span>
                <code>{selected.evidence}</code>
              </p>
              <p className="meta">Reported by passive inspection only. Confirm it before relying on it.</p>
            </div>
            {detail && <FlowPanes detail={detail} flows={flows} label={selected.title.slice(0, 32)} />}
          </>
        ) : (
          <p className="empty">Select a finding to see the evidence.</p>
        )}
      </section>
    </Split>
  );
}
