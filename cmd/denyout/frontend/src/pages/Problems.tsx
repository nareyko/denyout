import { useEffect, useState } from "react";
import { ConfirmModal } from "../components/ConfirmModal";
import { DiagnosticsPanel, SelfCheckPanel } from "../components/Diagnostics";
import { PauseModal } from "../components/PauseModal";
import { api, ProblemsView } from "../wails";

export function Problems({
  pauseBlocked = false,
  pauseCloseReq = 0,
  onPauseOpenChange,
  onOpenActivity,
  onOpenThreatSettings,
}: {
  pauseBlocked?: boolean;
  pauseCloseReq?: number;
  onPauseOpenChange?: (open: boolean) => void;
  onOpenActivity?: () => void;
  onOpenThreatSettings?: () => void;
}) {
  const [p, setP] = useState<ProblemsView | null>(null);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const note = (m: string) => {
    setErr("");
    setMsg(m);
  };
  const fail = (e: unknown) => {
    setMsg("");
    setErr(String(e));
  };
  const [pauseOpen, setPauseOpen] = useState(false);
  const [pauseBusy, setPauseBusy] = useState(false);
  const [protectOpen, setProtectOpen] = useState(false);
  const [protectBusy, setProtectBusy] = useState(false);
  const [protectAction, setProtectAction] = useState<"retry" | "enable" | "switch">("retry");

  async function reload() {
    setP(await api.problems());
  }

  useEffect(() => {
    void reload().catch((e) => fail(e));
    const poll = window.setInterval(() => {
      void reload().catch(() => undefined);
    }, 2500);
    return () => window.clearInterval(poll);
  }, []);

  useEffect(() => {
    if (!pauseBlocked) return;
    setPauseOpen(false);
    setProtectOpen(false);
  }, [pauseBlocked]);

  useEffect(() => {
    if (pauseCloseReq > 0) setPauseOpen(false);
  }, [pauseCloseReq]);

  useEffect(() => {
    onPauseOpenChange?.(pauseOpen);
    return () => onPauseOpenChange?.(false);
  }, [pauseOpen, onPauseOpenChange]);

  if (!p) {
    return <p className="muted">{err || msg || "Loading..."}</p>;
  }

  const hasError = !!(
    p.last_error &&
    !p.last_error.toLowerCase().includes("no errors recorded") &&
    !p.last_error.includes("(no recent")
  );
  // Prefer backend unhealthy (Protect intended on but broken). Never treat Off as a failure.
  const unhealthy =
    typeof p.unhealthy === "boolean"
      ? p.unhealthy
      : !!(p.protection_on && (!p.proxyd_running || !p.ca_present || hasError));

  const mode = (p.mode || "").toLowerCase();
  const agentsOnly = mode === "agents" || (p.mode_label || "").toLowerCase().includes("agents");
  const sessionOn = mode === "session" || !!p.session_running;
  const intentAgents = (p.policy_profile || "").toLowerCase() === "agent";
  const retryLabel = intentAgents ? "Try Agents only again" : "Retry Protect computer";
  const pausedUntil = (p.protect_paused_until || "").trim();
  const foreverOff = (p.protect_pause_last || "") === "forever";
  // Broken leave-on: alert with no live proxyd/session (not live+CA/error).
  const brokenIntent = unhealthy && !p.proxyd_running && !p.session_running;
  const canChangePause =
    !unhealthy &&
    !brokenIntent &&
    !p.proxyd_running &&
    !p.session_running &&
    (!!pausedUntil || foreverOff);
  const agentsRunning = p.agents_running || 0;
  let summary = p.protection_on
    ? agentsOnly
      ? p.threat_lists_warn
        ? "Agents only is on; threat lists need attention."
        : "Agents only is on."
      : sessionOn
        ? p.threat_lists_warn
          ? "Session protection is on; threat lists need attention."
          : "Session protection is on."
        : p.threat_lists_warn
          ? "Protect is on; threat lists need attention."
          : "Everything looks fine."
    : pausedUntil
      ? intentAgents
        ? "Agents only is paused."
        : "Protection is paused."
      : foreverOff
        ? intentAgents
          ? "Agents only is off until you turn it on."
          : "Protection is off until you turn it on."
        : p.computer_available === false
          ? agentsRunning > 0
            ? "Protection is off (unavailable) — My agents still running."
            : "Protection is off (unavailable)."
          : agentsRunning > 0
            ? "Protection is off — My agents still running."
            : p.threat_lists_warn
              ? "Threat lists need a refresh."
              : "Protection is off — that is OK.";
  const pauseNoun = intentAgents ? "Agents only" : "Protect";
  let support = p.protection_on
    ? agentsOnly
      ? p.threat_lists_warn
        ? "Whole-PC allowlist mode. Everyday browsing is not covered. Threat lists need a refresh (below)."
        : "Whole-PC allowlist mode. Everyday browsing is not covered — turn on Protect computer from Home for that."
      : sessionOn
        ? p.threat_lists_warn
          ? "Limited session proxy — prefer Protect computer for everyday browsing. Threat lists need a refresh (below)."
          : "This is a limited session proxy — prefer Protect computer for everyday browsing."
        : p.threat_lists_warn
          ? "Protect is running; threat lists need a refresh (below)."
          : "Protect is running. Open History if something was blocked."
    : pausedUntil
      ? `${pauseNoun} stays off for now. Turn on anytime, or change how long.`
      : foreverOff
        ? `You chose to leave ${pauseNoun} off. Turn on anytime from here or Home.`
        : p.computer_available === false
          ? intentAgents
            ? agentsRunning > 0
              ? "Agents only was unavailable last time (password cancelled or setup failed). My agents are still running — try Agents only again when ready, or switch to Protect computer from Settings."
              : "Agents only was unavailable last time (password cancelled or setup failed). Try Agents only again when ready, or switch to Protect computer from Settings."
            : agentsRunning > 0
              ? "Protect computer was unavailable last time (password cancelled or setup failed). My agents are still running — try Protect again when ready."
              : "Protect computer was unavailable last time (password cancelled or setup failed). Try again when ready."
          : agentsRunning > 0
            ? intentAgents
              ? "Wrapped agents are running. Last mode was Agents only — turn it on again from here, or switch to Protect computer from Settings."
              : "Wrapped agents are running, but everyday browsing is not protected. Turn on Protect computer when you want that."
            : intentAgents
              ? "Last mode was Agents only. Turn it on again from here, or switch to Protect computer from Settings."
              : p.threat_lists_warn
                ? "Protect is off; phishing/malware lists still need a refresh (below)."
                : "Turn on Protect computer from Home when you want browsing protection.";
  if (unhealthy) {
    if (hasError) {
      summary = "Something went wrong turning protection on.";
      support = intentAgents
        ? "A password window may have been cancelled, or a setup step failed. Try Agents only again, or copy the error for support."
        : "A password window may have been cancelled, or a setup step failed. Try Protect again, or copy the error for support.";
    } else if (!p.ca_present) {
      summary = "Protection needs a certificate setup step.";
      support = `${retryLabel}. If it keeps failing, open diagnostics.`;
    } else if (!p.proxyd_running && !p.session_running) {
      summary = "Protection parts are not running.";
      support = `${retryLabel} from here or Home.`;
    } else {
      summary = "Needs your attention.";
      support = `${retryLabel}, or open diagnostics.`;
    }
  }

  const protectTitle =
    protectAction === "switch"
      ? "Switch to Protect computer?"
      : intentAgents
        ? "Turn on Agents only?"
        : p.protect_confirm_title || "Turn on Protect computer?";
  const protectBody =
    protectAction === "switch"
      ? p.protect_confirm_body ||
        "Your system may ask for a password so DenyOut can set network rules. Continue?"
      : intentAgents
        ? p.helper_ok
          ? "DenyOut will set system network rules. Everyday browsing stays unprotected.\n\nYour system should not ask for a password (helper already installed).\n\nContinue?"
          : "Your system may ask for a password so DenyOut can set network rules. Everyday browsing stays unprotected. Continue?"
        : p.protect_confirm_body ||
          "Your system may ask for a password so DenyOut can set network rules. Continue?";

  return (
    <div className="stack">
      {err ? <p className="warn-box">{err}</p> : msg ? <p className="muted">{msg}</p> : null}
      <section className={`card ${unhealthy ? "home-hero-alert" : ""}`}>
        <h2>{summary}</h2>
        <p className="muted">{support}</p>
        {unhealthy ? (
          <div className="row-actions">
            <button
              className="btn primary"
              onClick={() => {
                setProtectAction("retry");
                setProtectOpen(true);
              }}
            >
              {retryLabel}
            </button>
            <button
              className="btn danger"
              disabled={pauseBusy || pauseBlocked}
              title={
                pauseBlocked
                  ? "Finish the open Ask/block or tray pause first."
                  : undefined
              }
              onClick={() => setPauseOpen(true)}
            >
              {brokenIntent ? "Clear intent / turn off…" : "Pause / turn off…"}
            </button>
            {hasError && (
              <button
                className="btn"
                onClick={() =>
                  void api
                    .copyLastError()
                    .then(() => note("Copied last error."))
                    .catch((e) => fail(e))
                }
              >
                Copy last error
              </button>
            )}
            <button className="btn subtle" onClick={() => void api.openLogs().catch((e) => fail(e))}>
              Open diagnostics
            </button>
          </div>
        ) : !p.protection_on ? (
          <div className="row-actions">
            <button
              className="btn primary"
              onClick={() => {
                setProtectAction(intentAgents ? "retry" : "enable");
                setProtectOpen(true);
              }}
            >
              {intentAgents ? "Turn on Agents only" : "Turn on Protect computer"}
            </button>
            {canChangePause ? (
              <button
                className="btn"
                disabled={pauseBusy || pauseBlocked}
                title={
                  pauseBlocked
                    ? "Finish the open Ask/block or tray pause first."
                    : undefined
                }
                onClick={() => setPauseOpen(true)}
              >
                Change pause…
              </button>
            ) : null}
            {p.threat_lists_warn && onOpenThreatSettings ? (
              <button className="btn" onClick={() => onOpenThreatSettings()}>
                Open Threat lists
              </button>
            ) : null}
          </div>
        ) : agentsOnly || sessionOn ? (
          <div className="row-actions">
            <button
              className="btn primary"
              onClick={() => {
                setProtectAction("switch");
                setProtectOpen(true);
              }}
            >
              Switch to Protect computer
            </button>
            <button
              className="btn danger"
              disabled={pauseBusy || pauseBlocked}
              title={
                pauseBlocked
                  ? "Finish the open Ask/block or tray pause first."
                  : undefined
              }
              onClick={() => setPauseOpen(true)}
            >
              Pause / turn off…
            </button>
            {p.threat_lists_warn && onOpenThreatSettings ? (
              <button className="btn" onClick={() => onOpenThreatSettings()}>
                Open Threat lists
              </button>
            ) : null}
          </div>
        ) : (
          <div className="row-actions">
            {p.threat_lists_warn && onOpenThreatSettings ? (
              <button className="btn" onClick={() => onOpenThreatSettings()}>
                Open Threat lists
              </button>
            ) : null}
            <button
              className="btn danger"
              disabled={pauseBusy || pauseBlocked}
              title={
                pauseBlocked
                  ? "Finish the open Ask/block or tray pause first."
                  : undefined
              }
              onClick={() => setPauseOpen(true)}
            >
              Pause / turn off…
            </button>
          </div>
        )}
        {pauseBlocked ? (
          <p className="muted" style={{ marginTop: "0.35rem" }}>
            Pause is busy — finish the open Ask/block or tray pause first.
          </p>
        ) : null}
        {unhealthy && hasError && (
          <pre className="mono" style={{ whiteSpace: "pre-wrap", marginTop: "0.75rem" }}>
            {p.last_error}
          </pre>
        )}
      </section>

      {p.update_available && (
        <section className="card">
          <h2>Update available</h2>
          <p className="muted">
            DenyOut {p.update_version || "newer"} is ready. No sign-in needed - open the release when
            you want.
          </p>
          <button
            className="btn"
            onClick={() => void api.openUpdateURL().catch((e) => fail(e))}
          >
            Open release
          </button>
        </section>
      )}

      {p.threat_lists_warn ? (
        <section className="card">
          <h2>Threat lists need a refresh</h2>
          <p className="muted">
            Phishing/malware lists are on but missing or outdated. Protect still works for secrets.
            Use Refresh now in Settings — DenyOut also retries in the background while running.
          </p>
          {onOpenThreatSettings ? (
            <button className="btn" onClick={() => onOpenThreatSettings()}>
              Open Threat lists
            </button>
          ) : (
            <p className="muted">Open Settings → Threat lists and use Refresh now.</p>
          )}
        </section>
      ) : null}

      {p.last_deny_host ? (
        <section className="card">
          <h2>Last blocked</h2>
          <p>
            <strong>{p.last_deny_host}</strong>
          </p>
          {p.last_deny_url && <p className="url">{p.last_deny_url}</p>}
          <p className="muted">{p.last_deny_summary}</p>
          <button className="btn" onClick={() => onOpenActivity?.()}>
            Open in History
          </button>
        </section>
      ) : null}

      {protectOpen ? (
        <ConfirmModal
          title={protectTitle}
          body={protectBody}
          busy={protectBusy}
          error={err}
          onCancel={() => setProtectOpen(false)}
          onConfirm={() => {
            setProtectBusy(true);
            setErr("");
            void (protectAction === "switch"
              ? api.switchSafe()
              : protectAction === "enable"
                ? api.enableSafe()
                : api.retryProtect())
              .then(() => {
                setProtectOpen(false);
                return reload();
              })
              .catch((e) => fail(e))
              .finally(() => setProtectBusy(false));
          }}
        />
      ) : null}

      {pauseOpen ? (
        <PauseModal
          busy={pauseBusy}
          mode={mode}
          intentAgents={intentAgents}
          alreadyOff={canChangePause}
          brokenIntent={brokenIntent}
          error={err}
          onCancel={() => setPauseOpen(false)}
          onChoose={(choice) => {
            setPauseBusy(true);
            setErr("");
            void api
              .stopProtectionWithChoice(choice)
              .then(() => {
                setPauseOpen(false);
                return reload();
              })
              .catch((e) => fail(e))
              .finally(() => setPauseBusy(false));
          }}
        />
      ) : null}

      <details className="card tech-details">
        <summary>Details</summary>
        <div className="health" style={{ marginTop: "0.65rem" }}>
          <div>
            Mode: <strong>{p.mode_label}</strong> - {p.status}
          </div>
          <div>
            Protection:{" "}
            <span className={p.proxyd_running || p.session_running ? "ok" : "muted"}>
              {p.proxyd_running || p.session_running
                ? "running"
                : p.protection_on
                  ? "intended on (not running)"
                  : "off"}
            </span>
          </div>
          <div>
            Control IPC:{" "}
            <span className={p.control_ok ? "ok" : "muted"}>{p.control_ok ? "ok" : "down"}</span>
          </div>
          <div>
            Proxyd:{" "}
            <span className={p.proxyd_running ? "ok" : "muted"}>
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
            CA:{" "}
            <span className={p.ca_present ? "ok" : p.protection_on ? "bad" : "muted"}>
              {p.ca_present ? "present" : "missing"}
            </span>
          </div>
          <div>
            Clipboard tools:{" "}
            <span className={p.clipboard_ok ? "ok" : "muted"}>
              {p.clipboard_ok ? "available" : "missing (wl-copy/xclip)"}
            </span>
          </div>
          <div>
            Helper:{" "}
            <span className={p.helper_ok ? "ok" : "muted"}>
              {p.helper_ok
                ? p.proxyd_running || p.session_running
                  ? "ready (no password next time)"
                  : "installed (used when Protect turns on)"
                : "not installed"}
            </span>
          </div>
          <div className="mono muted">{p.log_dir}</div>
          {!unhealthy && hasError ? (
            <div style={{ marginTop: "0.55rem" }}>
              <p className="muted" style={{ marginBottom: "0.35rem" }}>
                Last recorded error (Protect is fine now — for support only):
              </p>
              <pre className="mono" style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                {p.last_error}
              </pre>
            </div>
          ) : null}
          {!unhealthy && p.protection_on && (
            <div className="row-actions" style={{ marginTop: "0.55rem" }}>
              <button className="btn subtle" onClick={() => void api.openLogs().catch((e) => fail(e))}>
                Open diagnostics
              </button>
            </div>
          )}
        </div>
      </details>
      <SelfCheckPanel />
      <DiagnosticsPanel />
    </div>
  );
}
