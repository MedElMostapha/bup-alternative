// Sample data so the interface can be viewed in a plain browser during
// development. Vite leaves this file out of production builds.
import type { Finding, FlowDetail, FlowSummary, PendingView, RawText, UiEvent } from "./types";

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
const response = raw(
  'HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: application/json\r\nSet-Cookie: sid=…; Path=/\r\n\r\n{\n  "ok": true,\n  "order": 981\n}\n',
);

const detail = (id: number): FlowDetail => ({
  summary: flows.find((f) => f.id === id) ?? flows[0],
  target: { host: "api.example.test", port: 443, tls: true },
  request,
  response,
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

export async function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (command === "flow_detail") return detail(args?.id as number) as T;
  return (answers[command] ?? null) as T;
}

export async function listen(_handler: (events: UiEvent[]) => void): Promise<void> {}
export const chooseFile = async (): Promise<string | null> => null;
export const chooseProject = async (): Promise<string | null> => null;
export const chooseNewProject = async (): Promise<string | null> => null;
export const chooseCertPath = async (): Promise<string | null> => null;
