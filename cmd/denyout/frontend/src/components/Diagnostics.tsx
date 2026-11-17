import { useCallback, useEffect, useState } from "react";
import { api, DiagCheck, DiagReport } from "../wails";

function statusLabel(s: DiagCheck["status"]): string {
  switch (s) {
    case "ok":
      return "OK";
    case "warn":
      return "Check";
    case "fail":
      return "Problem";
    default:
      return "Skipped";
  }
}

function statusClass(s: DiagCheck["status"]): string {
  return s === "ok" ? "ok" : s === "fail" ? "bad" : "muted";
}

function CheckRow({
  c,
  busy,
  onFix,
}: {
  c: DiagCheck;
  busy: boolean;
  onFix: (c: DiagCheck) => void;
}) {
  return (
    <li style={{ marginBottom: "0.5rem" }}>
      <span className={statusClass(c.status)}>[{statusLabel(c.status)}]</span> <strong>{c.name}</strong>
      {c.detail ? <div className="muted">{c.detail}</div> : null}
      {c.fix && c.status !== "ok" && c.status !== "skip" ? (
        <div className="row-actions" style={{ marginTop: "0.25rem" }}>
          <button className="btn" type="button" disabled={busy} onClick={() => onFix(c)}>
            {c.fix_label || "Fix"}
          </button>
        </div>
      ) : null}
    </li>
  );
}

/**
 * First-run verification: checks the CA is installed and that interception
 * works (in-process, no network changes). Problems carry a Fix button that
 * runs an existing consent-gated action.
 */
export function SelfCheckPanel({ autoRun = false, onDone }: { autoRun?: boolean; onDone?: () => void }) {
  const [checks, setChecks] = useState<DiagCheck[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const run = useCallback(async () => {
    setBusy(true);
    setErr("");
    try {
      setChecks(await api.runSelfCheck());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (autoRun) void run();
  }, [autoRun, run]);

  async function fix(c: DiagCheck) {
    if (!c.fix) return;
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      setMsg(await api.fixCheck(c.fix));
      onDone?.();
      setChecks(await api.runSelfCheck());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const failed = (checks ?? []).some((c) => c.status === "fail");
  const warned = (checks ?? []).some((c) => c.status === "warn");
  const verified = checks !== null && !failed && !warned;

  return (
    <section className="card" aria-label="Verify protection">
      <h3>Verify it works</h3>
      {checks === null ? (
        <p className="muted">
          {busy
            ? "Checking the DenyOut certificate and interception..."
            : "Checks that the DenyOut certificate is ready and that HTTPS interception works. Nothing on your network is changed."}
        </p>
      ) : (
        <>
          {verified ? <p className="ok">Verified. The certificate works and interception is ready.</p> : null}
          {failed ? <p className="warn-box">Something needs fixing before protection can work.</p> : null}
          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {checks.map((c) => (
              <CheckRow key={c.id + c.name} c={c} busy={busy} onFix={(x) => void fix(x)} />
            ))}
          </ul>
        </>
      )}
      {msg && !err ? <p className="muted">{msg}</p> : null}
      {err ? <p className="warn-box">{err}</p> : null}
      <div className="row-actions">
        <button className="btn subtle" type="button" disabled={busy} onClick={() => void run()}>
          {checks === null ? "Run check" : "Run again"}
        </button>
      </div>
    </section>
  );
}

/** Diagnostics view: the redacted report that `denyout-cli doctor` prints. */
export function DiagnosticsPanel() {
  const [report, setReport] = useState<DiagReport | null>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    setErr("");
    try {
      const [r, t] = await Promise.all([api.diagnostics(), api.diagnosticsText()]);
      setReport(r);
      setText(t);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <details className="card" open>
      <summary>
        <strong>Diagnostics</strong>
      </summary>
      <p className="muted">
        A redacted status report for bug reports. Secrets are masked. You can also run
        denyout-cli doctor.
      </p>
      {err ? <p className="warn-box">{err}</p> : null}
      {report ? (
        <>
          <p className="muted">
            {report.version} on {report.os}/{report.arch}
            {report.status ? `, status: ${report.status}` : ""}
            {report.status_reason ? ` (${report.status_reason})` : ""}
          </p>
          <pre className="mono" style={{ whiteSpace: "pre-wrap", margin: 0, maxHeight: 280, overflow: "auto" }}>
            {text}
          </pre>
        </>
      ) : (
        <p className="muted">{busy ? "Collecting..." : "No report yet."}</p>
      )}
      <div className="row-actions">
        <button className="btn primary" type="button" disabled={!text} onClick={() => void copy()}>
          {copied ? "Copied" : "Copy report"}
        </button>
        <button className="btn subtle" type="button" disabled={busy} onClick={() => void load()}>
          Refresh
        </button>
      </div>
    </details>
  );
}
