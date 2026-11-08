import { useEffect, useState } from "react";
import { call, dialogs, toast } from "../api";
import type { ProxySettings, ProxyStatus, Scope, ScopeRule } from "../types";

const MEGABYTE = 1024 * 1024;

function RuleList({ title, rules, onChange }: { title: string; rules: ScopeRule[]; onChange: (rules: ScopeRule[]) => void }) {
  const edit = (index: number, patch: Partial<ScopeRule>) =>
    onChange(rules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));
  return (
    <div className="rules">
      <h3>{title}</h3>
      {rules.map((rule, i) => (
        <div className="field-row" key={i}>
          <input
            className="grow"
            aria-label={`${title} host pattern`}
            placeholder="example.test or *.example.test"
            value={rule.host}
            onChange={(e) => edit(i, { host: e.target.value })}
          />
          <input
            className="grow"
            aria-label={`${title} path prefix`}
            placeholder="/optional/path"
            value={rule.path_prefix}
            onChange={(e) => edit(i, { path_prefix: e.target.value })}
          />
          <button aria-label="Remove rule" onClick={() => onChange(rules.filter((_, j) => j !== i))}>
            Remove
          </button>
        </div>
      ))}
      <button onClick={() => onChange([...rules, { host: "", path_prefix: "" }])}>Add rule</button>
    </div>
  );
}

interface Props {
  active: boolean;
  status: ProxyStatus | null;
  onStatus: (status: ProxyStatus) => void;
  onProjectChange: () => void;
}

export function Settings({ active, status, onStatus, onProjectChange }: Props) {
  const [address, setAddress] = useState("127.0.0.1:8080");
  const [allowExternal, setAllowExternal] = useState(false);
  const [scope, setScope] = useState<Scope>({ include: [], exclude: [] });
  const [settings, setSettings] = useState<ProxySettings>({ body_cap: 32 * MEGABYTE, tls_passthrough: [] });
  const [passthrough, setPassthrough] = useState("");
  const [project, setProject] = useState("");

  useEffect(() => {
    if (status) setAddress(status.address);
  }, [status?.address]);

  useEffect(() => {
    if (!active) return;
    call<Scope>("get_scope").then(setScope, toast);
    call<string>("project_path").then(setProject, toast);
    call<ProxySettings>("get_settings").then((value) => {
      setSettings(value);
      setPassthrough(value.tls_passthrough.join("\n"));
    }, toast);
  }, [active]);

  const startProxy = () => {
    // A failed restart has already closed the old listener, so ask for the
    // real state rather than keeping what was shown before.
    call<ProxyStatus>("start_proxy", { address, allowExternal })
      .catch(() => call<ProxyStatus>("proxy_status"))
      .then(onStatus, toast);
  };

  const stopProxy = async () => {
    try {
      await call("stop_proxy");
      onStatus(await call<ProxyStatus>("proxy_status"));
    } catch (error) {
      toast(error);
    }
  };

  const changeScope = (next: Scope) => {
    setScope(next);
    const usable = {
      include: next.include.filter((rule) => rule.host.trim()),
      exclude: next.exclude.filter((rule) => rule.host.trim()),
    };
    call("set_scope", { scope: usable }).catch(toast);
  };

  const saveSettings = (next: ProxySettings) => {
    setSettings(next);
    call("set_settings", { settings: next }).catch(toast);
  };

  const exportCertificate = async () => {
    const path = await dialogs.certPath();
    if (!path) return;
    call("export_ca", { path }).then(() => toast(`Saved certificate to ${path}`), toast);
  };

  const switchProject = async (path: string | null) => {
    if (!path) return;
    try {
      await call("open_project", { path });
      setProject(path);
      onProjectChange();
    } catch (error) {
      toast(error);
    }
  };

  const external = !/^(127\.|\[::1\]|localhost)/.test(address);

  return (
    <div className="settings">
      <section className="card">
        <h2>Proxy listener</h2>
        <div className="field-row">
          <input className="grow" aria-label="Listen address" value={address} onChange={(e) => setAddress(e.target.value)} />
          <button className="primary" onClick={startProxy}>
            {status?.running ? "Restart" : "Start"}
          </button>
          <button disabled={!status?.running} onClick={stopProxy}>
            Stop
          </button>
        </div>
        {status?.error && <div className="notes">Could not start the listener. {status.error}</div>}
        {external && (
          <label className="check warn-box">
            <input type="checkbox" checked={allowExternal} onChange={(e) => setAllowExternal(e.target.checked)} />
            Allow other machines on this network to use the proxy. Anyone who can reach this address can send traffic
            through it.
          </label>
        )}
      </section>

      <section className="card">
        <h2>HTTPS certificate</h2>
        <p>
          Sluice creates a certificate authority unique to this computer, and its private key never leaves this machine.
          The easiest way to inspect HTTPS traffic is the Open Chrome or Open Firefox button at the top of the window,
          which needs no setup. To use another browser or profile, import the certificate by hand:
        </p>
        <ol>
          <li>Save the certificate below.</li>
          <li>In Firefox, open Settings, Privacy &amp; Security, View Certificates, then Authorities, and import it.</li>
          <li>Select “Trust this CA to identify websites”, and set the browser's proxy to the listener address.</li>
        </ol>
        <button onClick={exportCertificate}>Save certificate</button>
      </section>

      <section className="card">
        <h2>Scope</h2>
        <p>
          Scope lists the targets you are authorized to test. The fuzzer only sends to hosts listed here. Until you add a
          rule, Intercept and passive findings cover all traffic.
        </p>
        <RuleList title="Include" rules={scope.include} onChange={(include) => changeScope({ ...scope, include })} />
        <RuleList title="Exclude" rules={scope.exclude} onChange={(exclude) => changeScope({ ...scope, exclude })} />
      </section>

      <section className="card">
        <h2>Capture</h2>
        <label className="stacked">
          Recording limit per message (MB)
          <input
            type="number"
            min={1}
            value={Math.round(settings.body_cap / MEGABYTE)}
            onChange={(e) => saveSettings({ ...settings, body_cap: Math.max(1, Number(e.target.value)) * MEGABYTE })}
          />
        </label>
        <label className="stacked">
          Hosts to tunnel without HTTPS inspection, one pattern per line
          <textarea
            rows={3}
            value={passthrough}
            onChange={(e) => {
              setPassthrough(e.target.value);
              saveSettings({ ...settings, tls_passthrough: e.target.value.split("\n").filter((line) => line.trim()) });
            }}
          />
        </label>
      </section>

      <section className="card">
        <h2>Project</h2>
        <p className="clip dim">{project}</p>
        <div className="field-row">
          <button onClick={async () => switchProject(await dialogs.project())}>Open project</button>
          <button onClick={async () => switchProject(await dialogs.newProject())}>New project</button>
        </div>
      </section>
    </div>
  );
}
