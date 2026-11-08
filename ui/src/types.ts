export type Encoding = "utf8" | "latin1";
export interface RawText {
  text: string;
  encoding: Encoding;
}

export interface Target {
  host: string;
  port: number;
  tls: boolean;
}

export type Source = "proxy" | "repeater" | "fuzzer";

export interface FlowSummary {
  id: number;
  source: Source;
  host: string;
  port: number;
  tls: boolean;
  method: string;
  path: string;
  status: number | null;
  request_len: number;
  response_len: number;
  mime: string;
  started_ms: number;
  duration_ms: number | null;
  edited: boolean;
  truncated: boolean;
  tls_error: string | null;
  error: string | null;
  complete: boolean;
}

export interface FlowDetail {
  summary: FlowSummary;
  target: Target;
  request: RawText;
  response: RawText | null;
  decoded_response: RawText | null;
}

export interface FlowFilter {
  source?: Source;
  host?: string;
  method?: string;
  status_class?: number;
  mime?: string;
  text?: string;
  in_scope_only?: boolean;
  before_id?: number;
  limit?: number;
}

export interface WsFrameView {
  from_client: boolean;
  opcode: number;
  payload: RawText;
  truncated: boolean;
  at_ms: number;
}

export interface PendingView {
  id: number;
  flow_id: number;
  direction: "request" | "response";
  target: Target;
  raw: RawText;
}

export type Decision = { action: "forward" } | { action: "drop" } | { action: "edited"; raw: RawText };

export interface ScopeRule {
  host: string;
  path_prefix: string;
}

export interface Scope {
  include: ScopeRule[];
  exclude: ScopeRule[];
}

export interface ProxySettings {
  body_cap: number;
  tls_passthrough: string[];
}

export interface ProxyStatus {
  running: boolean;
  address: string;
  error?: string | null;
}

export type BrowserKind = "chrome" | "firefox";

export interface BrowserInfo {
  kind: BrowserKind;
  path: string;
}

export interface RepeaterTab {
  id: number;
  name: string;
  target: Target;
  request: RawText;
}

export type AttackMode = "single" | "same" | "parallel" | "combinations";
export type PayloadSource =
  | { list: string[] }
  | { file: string }
  | { numbers: { from: number; to: number; step: number } };
export type RunState = "running" | "paused" | "stopped" | "finished";

export interface FuzzConfig {
  target: Target;
  template: string;
  encoding: Encoding;
  mode: AttackMode;
  payloads: PayloadSource[];
  concurrency: number;
  delay_ms: number;
  grep: string | null;
  normalize: boolean;
  timeout_ms: number;
}

export interface FuzzRunInfo {
  id: number;
  config: FuzzConfig;
  total: number;
  state: RunState;
  created_ms: number;
}

export interface FuzzResult {
  run_id: number;
  index: number;
  payloads: string[];
  flow_id: number;
  status: number | null;
  length: number;
  duration_ms: number;
  matched: boolean;
  error: string | null;
}

export type Severity = "info" | "low" | "medium" | "high";

export interface Finding {
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence: string;
  host: string;
  path: string;
  dedupe: string;
  flow_id: number;
  found_ms: number;
}

export type UiEvent =
  | ({ kind: "flow" } & FlowSummary)
  | { kind: "ws_frame"; flow_id: number }
  | ({ kind: "intercept_queued" } & PendingView)
  | { kind: "intercept_cleared"; id: number }
  | ({ kind: "finding" } & Finding)
  | ({ kind: "fuzz_result" } & FuzzResult)
  | { kind: "fuzz_state"; run_id: number; state: RunState };

/** A request handed from one view to another. */
export interface RequestDraft {
  target: Target;
  request: RawText;
  label: string;
  nonce: number;
}
