// Sample data so the interface can be viewed in a plain browser during
// development. Vite leaves this file out of production builds.
import type { Finding, FlowDetail, FlowFilter, FlowSummary, MatchRule, PendingView, RawText, SiteNode, SiteTree, UiEvent } from "./types";

const raw = (text: string): RawText => ({ text, encoding: "utf8" });

const flows: FlowSummary[] = Array.from({ length: 60 }, (_, i) => ({
  id: 60 - i,
  source: "proxy",
  host: i % 3 ? "shop.example.test" : "api.example.test",
  port: 443,
  tls: true,
  method: i % 5 ? "GET" : "POST",
  path: i % 3 ? `/products/${i}?ref=home` : `/v1/orders/${i}`,
  status: i % 11 === 0 ? 500 : i % 7 === 0 ? 404 : 200,
  request_len: 320 + i,
  response_len: 2048 + i * 40,
  mime: i % 3 ? "text/html" : "application/json",
  started_ms: Date.now() - i * 4000,
  duration_ms: 40 + i * 3,
  edited: i === 4,
  truncated: false,
  tls_error: i === 2 ? "invalid peer certificate: UnknownIssuer" : null,
  error: null,
  complete: true,
}));

const request = raw(
  "POST /v1/orders HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: curl/8.5\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"item\":§42§,\"n\":1}",
);
const sampleResponse = (order: number) =>
  raw(
    `HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: application/json\r\nSet-Cookie: sid=…; Path=/\r\n\r\n{\n  "ok": true,\n  "order": ${order}\n}\n`,
  );
const response = sampleResponse(981);

const detail = (id: number): FlowDetail => ({
  summary: flows.find((f) => f.id === id) ?? flows[0],
  target: { host: "api.example.test", port: 443, tls: true },
  request,
  response: sampleResponse(id),
  decoded_response: null,
});

const queued: PendingView[] = [
  { id: 1, flow_id: 61, direction: "request", target: { host: "api.example.test", port: 443, tls: true }, raw: request },
  { id: 2, flow_id: 62, direction: "response", target: { host: "shop.example.test", port: 443, tls: true }, raw: response },
];

const findings: Finding[] = [
  ["high", "permissive-cors", "CORS policy reflects the origin and allows credentials"],
  ["medium", "secret-in-url", "Parameter access_token may carry a secret in the URL"],
  ["low", "missing-hsts", "Strict-Transport-Security header is missing"],
  ["low", "cookie-no-httponly", "Cookie sid is missing HttpOnly"],
  ["info", "version-disclosure", "server header discloses a software version"],
].map(([severity, rule, title], i) => ({
  rule: rule as string,
  severity: severity as Finding["severity"],
  title: title as string,
  detail: "A sample explanation of why this matters and what to check next.",
  evidence: "Server: nginx/1.25.3",
  host: "api.example.test",
  path: "/v1/orders",
  dedupe: "",
  flow_id: 60 - i,
  found_ms: Date.now(),
}));

const answers: Record<string, unknown> = {
  project_path: "/home/user/default.sluice",
  proxy_status: { running: true, address: "127.0.0.1:8080" },
  available_browsers: [
    { kind: "chrome", path: "/usr/bin/google-chrome" },
    { kind: "firefox", path: "/usr/bin/firefox" },
  ],
  get_scope: { include: [{ host: "*.example.test", path_prefix: "" }], exclude: [] },
  get_settings: { body_cap: 33554432, tls_passthrough: [] },
  ca_pem: "-----BEGIN CERTIFICATE-----\nSAMPLE\n-----END CERTIFICATE-----\n",
  list_flows: flows,
  queued_intercepts: queued,
  list_tabs: [
    { id: 1, name: "POST /v1/orders", target: { host: "api.example.test", port: 443, tls: true }, request },
  ],
  tab_sends: flows.slice(0, 3),
  repeater_send: detail(60),
  fuzz_preview: 12,
  list_fuzz_runs: [
    {
      id: 2,
      config: { target: { host: "lab.web-security-academy.test", port: 443, tls: true }, grep: null },
      total: 4752,
      state: "stopped",
      created_ms: Date.now(),
    },
  ],
  fuzz_results: [200, 200, 302, 400, 404, 404, 404, 404, 404, null].map((status, index) => ({
    run_id: 2,
    index,
    payloads: [`path-${index}`],
    flow_id: 60 - index,
    status,
    length: status === 404 ? 196 : 1187,
    duration_ms: 350,
    matched: false,
    error: status === null ? "request timed out" : null,
  })),
  list_findings: findings,
  ws_frames: [],
};

const MOCK_CONVERSIONS: Record<string, (text: string) => string> = {
  url_decode: decodeURIComponent,
  url_encode: encodeURIComponent,
  base64_decode: atob,
  base64_encode: btoa,
};

function mockDecoder(input: string, steps: string[]) {
  const outputs = [];
  let current = input;
  for (const step of steps) {
    try {
      current = (MOCK_CONVERSIONS[step] ?? ((text: string) => text))(current);
    } catch {
      return { outputs, error: `sample data cannot run ${step} on this input` };
    }
    outputs.push({ raw: { text: current, encoding: "utf8" }, length: current.length });
  }
  return { outputs, error: null };
}

function mockCompare(a: RawText, b: RawText) {
  const [left, right] = [a.text.split("\n"), b.text.split("\n")];
  let changed = 0;
  const rows = left.map((line, i) => {
    const same = line === right[i];
    if (!same) changed += 1;
    const side = (text: string) => ({ number: i + 1, spans: [{ text, changed: !same }] });
    return { kind: same ? "same" : "changed", a: side(line), b: side(right[i] ?? "") };
  });
  return { rows, changed, removed: 0, added: 0, clipped: false };
}

function mockSiteMap(): SiteTree[] {
  const node = (name: string, path: string): SiteNode => ({ name, path, requests: 0, flow_id: null, status: null, in_scope: true, children: [] });
  const roots = new Map<string, SiteTree>();
  for (const flow of [...flows].reverse()) {
    if (!roots.has(flow.host)) {
      roots.set(flow.host, { target: { host: flow.host, port: flow.port, tls: flow.tls }, root: node("", "") });
    }
    let at = roots.get(flow.host)!.root;
    at.requests += 1;
    for (const name of flow.path.split("?")[0].split("/").filter(Boolean)) {
      let next = at.children.find((child) => child.name === name);
      if (!next) at.children.push((next = node(name, `${at.path}/${name}`)));
      at = next;
      at.requests += 1;
    }
    at.flow_id = flow.id;
    at.status = flow.status;
  }
  return [...roots.values()].sort((a, b) => a.target.host.localeCompare(b.target.host));
}

function mockFlows({ sort, ascending, offset = 0, site, before_id }: FlowFilter) {
  const key = sort ?? "id";
  const direction = sort && ascending ? 1 : -1;
  const placed = flows.filter(
    ({ host, path, id }) =>
      (!site || (host === site.target.host && (!site.path || path === site.path || path.startsWith(`${site.path}/`) || path.startsWith(`${site.path}?`)))) &&
      (before_id === undefined || id < before_id),
  );
  const sorted = placed.sort((a, b) => {
    const [x, y] = [a[key] ?? 0, b[key] ?? 0];
    return (typeof x === "string" ? x.localeCompare(y as string) : (x as number) - (y as number)) * direction || b.id - a.id;
  });
  return sorted.slice(offset);
}

function checkRule(rule: MatchRule): string | null {
  if (rule.pattern === "") return "Enter the text to find.";
  if (rule.kind.endsWith("_header") && /\s/.test(rule.pattern)) return `"${rule.pattern}" is not a valid header name.`;
  try {
    if (rule.regex) new RegExp(rule.pattern);
  } catch {
    return "Invalid regex: sample data could not compile this";
  }
  return null;
}

let mockRules: MatchRule[] = [
  { enabled: true, direction: "request", kind: "set_header", pattern: "X-Sample", replacement: "1", regex: false },
];
const mockRulesView = () => ({ rules: mockRules, errors: mockRules.map(checkRule) });

export async function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (command === "list_flows") return mockFlows(args?.filter as FlowFilter) as T;
  if (command === "site_map") return mockSiteMap() as T;
  if (command === "create_tab") return { id: Date.now(), name: args?.name, target: args?.target, request: args?.request } as T;
  if (command === "get_match_rules") return mockRulesView() as T;
  if (command === "set_match_rules") {
    mockRules = args?.rules as MatchRule[];
    return mockRulesView() as T;
  }
  if (command === "comparer_diff") return mockCompare(args?.a as RawText, args?.b as RawText) as T;
  if (command === "decoder_run") return mockDecoder(args?.input as string, args?.steps as string[]) as T;
  if (command === "decoder_smart") return ["url_decode", "base64_decode"] as T;
  if (command === "flow_detail") return detail(args?.id as number) as T;
  return (answers[command] ?? null) as T;
}

export async function listen(_handler: (events: UiEvent[]) => void): Promise<void> {}
export const chooseFile = async (): Promise<string | null> => null;
export const chooseProject = async (): Promise<string | null> => null;
export const chooseNewProject = async (): Promise<string | null> => null;
export const chooseCertPath = async (): Promise<string | null> => null;
