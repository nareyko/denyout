import { useEffect, useState } from "react";
import { api, ProblemsView } from "../wails";

export function Problems({ onOpenActivity }: { onOpenActivity?: () => void }) {
  const [p, setP] = useState<ProblemsView | null>(null);
  const [msg, setMsg] = useState("");

  async function reload() {
    setP(await api.problems());
  }

  useEffect(() => {
    void reload().catch((e) => setMsg(String(e)));
  }, []);

  if (!p) {
    return <p className="muted">{msg || "Loading…"}</p>;
  }

  const hasError = !!(p.last_error && !p.last_error.includes("(no recent"));
  const unhealthy = !p.control_ok || !p.proxyd_running || !p.ca_present || hasError;

  let summary = "Everything looks fine.";
  let support = "If Protect failed earlier, you can still retry below.";
  if (unhealthy) {
    if (hasError) {
      summary = "Something went wrong turning protection on.";
      support =
        "A password window may have been cancelled, or a setup step failed. Try Protect again, or copy the error for support.";
    } else if (!p.ca_present) {
      summary = "Protection needs a certificate setup step.";
      support = "Try Protect computer again. If it keeps failing, open diagnostics.";
    } else if (!p.control_ok || !p.proxyd_running) {
      summary = "Protection parts are not running.";
      support = "Try Protect computer again from here or Home.";
    } else {
      summary = "Needs your attention.";
      support = "Try Protect computer again, or open diagnostics.";
    }
  }

  return (
    <div className="stack">
      {msg && <p className="muted">{msg}</p>}
      <section className={`card ${unhealthy ? "home-hero-alert" : ""}`}>
        <h2>{summary}</h2>
        <p className="muted">{support}</p>
        {unhealthy ? (
          <div className="row-actions">
            <button
              className="btn primary"
              onClick={() => void api.retryProtect().then(reload).catch((e) => setMsg(String(e)))}
            >
              Retry Protect computer
            </button>
            {hasError && (
              <button
                className="btn"
                onClick={() =>
                  void api
                    .copyLastError()
                    .then(() => setMsg("Copied last error."))
                    .catch((e) => setMsg(String(e)))
                }
              >
                Copy last error
              </button>
            )}
            <button className="btn subtle" onClick={() => void api.openLogs().catch((e) => setMsg(String(e)))}>
              Open diagnostics
            </button>
          </div>
        ) : null}
        {hasError && (
          <pre className="mono" style={{ whiteSpace: "pre-wrap", marginTop: "0.75rem" }}>
            {p.last_error}
          </pre>
        )}
      </section>

      {p.update_available && (
        <section className="card">
          <h2>Update available</h2>
          <p className="muted">
            DenyOut {p.update_version || "newer"} is ready. No sign-in needed — open the release when
            you want.
          </p>
          <button
            className="btn"
            onClick={() => void api.openUpdateURL().catch((e) => setMsg(String(e)))}
          >
            Open release
          </button>
        </section>
      )}

      {(p.last_deny_host || unhealthy) && (
        <section className="card">
          <h2>Last blocked</h2>
          {p.last_deny_host ? (
            <>
              <p>
                <strong>{p.last_deny_host}</strong>
              </p>
              {p.last_deny_url && <p className="url">{p.last_deny_url}</p>}
              <p className="muted">{p.last_deny_summary}</p>
              <button className="btn" onClick={() => onOpenActivity?.()}>
                Open in History
              </button>
            </>
          ) : (
            <p className="muted">No recent denial recorded.</p>
          )}
        </section>
      )}

      <details className="card tech-details">
        <summary>Details</summary>
        <div className="health" style={{ marginTop: "0.65rem" }}>
          <div>
            Mode: <strong>{p.mode_label}</strong> — {p.status}
          </div>
          <div>
            Control IPC:{" "}
            <span className={p.control_ok ? "ok" : "bad"}>{p.control_ok ? "ok" : "down"}</span>
          </div>
          <div>
            Proxyd:{" "}
            <span className={p.proxyd_running ? "ok" : "bad"}>
              {p.proxyd_running ? "running" : "stopped"}
            </span>
          </div>
          <div>
            Session proxy:{" "}
            <span className={p.session_running ? "ok" : "muted"}>
              {p.session_running ? "running" : "off"}
            </span>
          </div>
          <div>
            CA: <span className={p.ca_present ? "ok" : "bad"}>{p.ca_present ? "present" : "missing"}</span>
          </div>
          <div>
            Clipboard tools:{" "}
            <span className={p.clipboard_ok ? "ok" : "muted"}>
              {p.clipboard_ok ? "available" : "missing (wl-copy/xclip)"}
            </span>
          </div>
          <div className="mono muted">{p.log_dir}</div>
          {!unhealthy && (
            <div className="row-actions" style={{ marginTop: "0.55rem" }}>
              <button className="btn" onClick={() => void api.retryProtect().then(reload).catch((e) => setMsg(String(e)))}>
                Retry Protect computer
              </button>
              <button className="btn subtle" onClick={() => void api.openLogs().catch((e) => setMsg(String(e)))}>
                Open diagnostics
              </button>
            </div>
          )}
        </div>
      </details>
    </div>
  );
}
