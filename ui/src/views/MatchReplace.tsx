import { useEffect, useRef, useState } from "react";
import { call, toast } from "../api";
import type { MatchRule, MatchRules, RuleKind } from "../types";

const KINDS: Array<{ value: RuleKind; label: string; pattern: string; replacement: string | null }> = [
  { value: "set_header", label: "Set header", pattern: "Header name", replacement: "Value" },
  { value: "remove_header", label: "Remove header", pattern: "Header name", replacement: null },
  { value: "replace_headers", label: "Replace in headers", pattern: "Find", replacement: "Replace with" },
  { value: "replace_first_line", label: "Replace in first line", pattern: "Find", replacement: "Replace with" },
  { value: "replace_body", label: "Replace in body", pattern: "Find", replacement: "Replace with" },
];

const SAVE_DELAY = 250;
const newRule = (): MatchRule => ({
  enabled: true,
  direction: "request",
  kind: "set_header",
  pattern: "",
  replacement: "",
  regex: false,
});

const activeCount = ({ rules, errors }: MatchRules) => rules.filter((rule, i) => rule.enabled && !errors[i]).length;

export function MatchReplace({ onActiveCount }: { onActiveCount: (count: number) => void }) {
  const [rules, setRules] = useState<MatchRule[]>([]);
  const [errors, setErrors] = useState<Array<string | null>>([]);
  const timer = useRef<number | undefined>(undefined);
  const latestSave = useRef(0);

  useEffect(() => {
    call<MatchRules>("get_match_rules").then((saved) => {
      setRules(saved.rules);
      setErrors(saved.errors);
      onActiveCount(activeCount(saved));
    }, toast);
    // The parent's callback never changes what is loaded.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const change = (next: MatchRule[]) => {
    setRules(next);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      const save = ++latestSave.current;
      call<MatchRules>("set_match_rules", { rules: next }).then((saved) => {
        if (save !== latestSave.current) return;
        setErrors(saved.errors);
        onActiveCount(activeCount(saved));
      }, toast);
    }, SAVE_DELAY);
  };

  const edit = (index: number, patch: Partial<MatchRule>) => change(rules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));

  return (
    <div className="settings">
      <section className="card match-replace">
        <h2>Match &amp; Replace</h2>
        <p>
          These rules rewrite traffic passing through the proxy, in order from top to bottom, before it reaches Intercept.
          They only touch targets in scope; until you add a scope rule, that means all traffic. Repeater and Fuzzer always
          send exactly what you wrote.
        </p>
        {rules.map((rule, i) => {
          const kind = KINDS.find((k) => k.value === rule.kind) ?? KINDS[0];
          const isHeaderRule = rule.kind === "set_header" || rule.kind === "remove_header";
          return (
            <div className="match-rule" key={i}>
              <div className="field-row">
                <input
                  type="checkbox"
                  aria-label={`Rule ${i + 1} enabled`}
                  checked={rule.enabled}
                  onChange={(e) => edit(i, { enabled: e.target.checked })}
                />
                <select
                  aria-label={`Rule ${i + 1} direction`}
                  value={rule.direction}
                  onChange={(e) => edit(i, { direction: e.target.value as MatchRule["direction"] })}
                >
                  <option value="request">Request</option>
                  <option value="response">Response</option>
                </select>
                <select
                  aria-label={`Rule ${i + 1} action`}
                  value={rule.kind}
                  onChange={(e) => edit(i, { kind: e.target.value as RuleKind })}
                >
                  {KINDS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
                {!isHeaderRule && (
                  <label className="check">
                    <input type="checkbox" checked={rule.regex} onChange={(e) => edit(i, { regex: e.target.checked })} />
                    Regex
                  </label>
                )}
                <span className="spacer" />
                <button className="link" onClick={() => change(rules.filter((_, j) => j !== i))}>
                  Remove
                </button>
              </div>
              <div className="field-row">
                <input
                  className="grow"
                  aria-label={`Rule ${i + 1} ${kind.pattern}`}
                  placeholder={kind.pattern}
                  value={rule.pattern}
                  onChange={(e) => edit(i, { pattern: e.target.value })}
                />
                {kind.replacement && (
                  <input
                    className="grow"
                    aria-label={`Rule ${i + 1} ${kind.replacement}`}
                    placeholder={kind.replacement}
                    value={rule.replacement}
                    onChange={(e) => edit(i, { replacement: e.target.value })}
                  />
                )}
              </div>
              {/* A rule still being filled in is inactive, not a mistake. */}
              {rule.pattern !== "" && errors[i] && <div className="notes">{errors[i]}</div>}
            </div>
          );
        })}
        {rules.length === 0 && <p className="dim">No rules yet.</p>}
        <button onClick={() => change([...rules, newRule()])}>Add rule</button>
      </section>
    </div>
  );
}
