import { useEffect, useRef, useState } from "react";
import { call, toast } from "../api";
import { RawEditor } from "../components/RawEditor";
import { clipForDisplay, formatBytes } from "../format";
import type { DecoderRun, StepOutput, Transform } from "../types";

const GROUPS: Array<{ label: string; options: Array<{ value: Transform; label: string }> }> = [
  {
    label: "Decode",
    options: [
      { value: "url_decode", label: "URL decode" },
      { value: "form_decode", label: "URL decode (+ as space)" },
      { value: "html_decode", label: "HTML decode" },
      { value: "base64_decode", label: "Base64 decode" },
      { value: "hex_decode", label: "Hex decode" },
      { value: "gzip_decode", label: "Gzip decompress" },
    ],
  },
  {
    label: "Encode",
    options: [
      { value: "url_encode", label: "URL encode" },
      { value: "url_encode_all", label: "URL encode (every byte)" },
      { value: "html_encode", label: "HTML encode" },
      { value: "base64_encode", label: "Base64 encode" },
      { value: "base64_url_encode", label: "Base64 encode (URL-safe)" },
      { value: "hex_encode", label: "Hex encode" },
      { value: "gzip_encode", label: "Gzip compress" },
    ],
  },
  { label: "Hash", options: [{ value: "sha256", label: "SHA-256" }] },
];

const RUN_DELAY = 150;
const NO_RESULT: DecoderRun = { outputs: [], error: null };

interface Step {
  id: number;
  transform: Transform;
}

function StepPane({
  step,
  output,
  error,
  onChange,
  onRemove,
}: {
  step: Step;
  output: StepOutput | undefined;
  error: string | null;
  onChange: (transform: Transform) => void;
  onRemove: () => void;
}) {
  const copy = () => {
    if (output) navigator.clipboard.writeText(output.raw.text).then(() => toast("Copied"), toast);
  };
  return (
    <section className="pane decoder-pane">
      <header className="pane-head">
        <select aria-label="Conversion" value={step.transform} onChange={(e) => onChange(e.target.value as Transform)}>
          {GROUPS.map((group) => (
            <optgroup key={group.label} label={group.label}>
              {group.options.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        {output && <span className="meta">{formatBytes(output.length)}</span>}
        {output?.raw.encoding === "latin1" && (
          <span className="tag alt" title="Not valid text, so each byte is shown as one character">
            binary
          </span>
        )}
        <span className="spacer" />
        <button className="link" disabled={!output} onClick={copy}>
          Copy
        </button>
        <button className="link" onClick={onRemove}>
          Remove
        </button>
      </header>
      {error && <div className="notes">{error}</div>}
      {output ? (
        <RawEditor value={clipForDisplay(output.raw.text, "Copy still gives the full output.")} readOnly plain />
      ) : (
        !error && <p className="empty">Waiting for the step above.</p>
      )}
    </section>
  );
}

export function Decoder() {
  const [input, setInput] = useState("");
  const [steps, setSteps] = useState<Step[]>([]);
  const [result, setResult] = useState<DecoderRun>(NO_RESULT);
  const nextId = useRef(1);

  const withIds = (transforms: Transform[]) => transforms.map((transform) => ({ id: nextId.current++, transform }));

  useEffect(() => {
    if (input === "" || steps.length === 0) return setResult(NO_RESULT);
    let current = true;
    const timer = window.setTimeout(() => {
      call<DecoderRun>("decoder_run", { input, steps: steps.map((s) => s.transform) }).then(
        (run) => current && setResult(run),
        toast,
      );
    }, RUN_DELAY);
    return () => {
      current = false;
      window.clearTimeout(timer);
    };
  }, [input, steps]);

  const autoDecode = async () => {
    try {
      const found = await call<Transform[]>("decoder_smart", { input });
      if (found.length === 0) toast("No encoding recognized; add a step to choose one");
      else setSteps(withIds(found));
    } catch (error) {
      toast(error);
    }
  };

  const failedAt = result.error === null ? -1 : result.outputs.length;

  return (
    <div className="decoder">
      <div className="toolbar">
        <button onClick={() => setSteps([...steps, ...withIds(["url_decode"])])}>Add step</button>
        <button disabled={input === ""} onClick={autoDecode}>
          Auto-decode
        </button>
        <span className="spacer" />
        <button
          disabled={input === "" && steps.length === 0}
          onClick={() => {
            setInput("");
            setSteps([]);
          }}
        >
          Clear
        </button>
      </div>
      <div className="decoder-steps">
        <section className="pane decoder-pane">
          <header className="pane-head">
            <h3>Input</h3>
          </header>
          <RawEditor value={input} onChange={setInput} plain />
        </section>
        {steps.map((step, i) => (
          <StepPane
            key={step.id}
            step={step}
            output={result.outputs[i]}
            error={i === failedAt ? result.error : null}
            onChange={(transform) => setSteps(steps.map((s) => (s.id === step.id ? { ...s, transform } : s)))}
            onRemove={() => setSteps(steps.filter((s) => s.id !== step.id))}
          />
        ))}
        {steps.length === 0 && (
          <p className="empty">Paste a value above, then choose Auto-decode or add steps to convert it one layer at a time.</p>
        )}
      </div>
    </div>
  );
}
