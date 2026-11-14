import { useState } from "react";
import { api, UISnapshot } from "../wails";

export function Home({
  snap,
  onChanged,
  onSeeHistory,
  onOpenProblems,
  onOpenSettings,
  onOpenAgents,
}: {
  snap: UISnapshot | null;
  onChanged?: () => void;
  onSeeHistory?: () => void;
  onOpenProblems?: () => void;
  onOpenSettings?: () => void;
  onOpenAgents?: () => void;
}) {
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  const protectedOn = !!snap?.protection_on && snap?.mode === "safe";
  const needsHelp = !!snap?.problems_alert;
  const agentsOnly = snap?.mode === "agents";
  const isOff = !snap?.protection_on || snap?.mode === "off";

  let headline = "Protection is off";
  let support =
    "Turn on Protect computer to block secret-looking links and clear threats while you browse.";
  if (needsHelp) {
    headline = "Needs your help";
    support = "Something went wrong with protection. Try again, or open Problems.";
  } else if (protectedOn) {
    headline = "You are protected";
    support = "Browse as usual. We’ll only interrupt for clear risks.";
  } else if (agentsOnly) {
    headline = "Protection isn’t set for everyday browsing";
    support =
      "Turn on Protect computer for normal web use. AI tools belong under My agents.";
  }

  const showTurnOn = needsHelp || isOff || agentsOnly;
  const blockedToday = snap?.blocked_today ?? 0;

  async function turnOn() {
    setBusy(true);
    setMsg("");
    try {
      await api.enableSafe();
      onChanged?.();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function turnOff() {
    setBusy(true);
    setMsg("");
    try {
      await api.stopProtection();
      onChanged?.();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function allowLast() {
    if (!snap?.last_deny_host) return;
    setBusy(true);
    setMsg("");
    try {
      await api.alwaysAllow(snap.last_deny_host, "");
      setMsg("Allowed " + snap.last_deny_host);
      onChanged?.();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack home">
      <section className={`home-hero card ${needsHelp ? "home-hero-alert" : ""}`}>
        <h1 className="home-headline">{headline}</h1>
        <p className="muted">{support}</p>
        <div className="row-actions">
          {needsHelp ? (
            <>
              <button className="btn primary" disabled={busy} onClick={() => void turnOn()}>
                Try Protect computer again
              </button>
              <button className="btn" onClick={() => onOpenProblems?.()}>
                Open Problems
              </button>
            </>
          ) : showTurnOn ? (
            <button className="btn primary" disabled={busy} onClick={() => void turnOn()}>
              Turn on Protect computer
            </button>
          ) : (
            <button className="btn danger" disabled={busy} onClick={() => void turnOff()}>
              Turn off
            </button>
          )}
        </div>
        {msg && (
          <p className="muted" style={{ marginTop: "0.65rem" }}>
            {msg}
          </p>
        )}
      </section>

      {snap?.last_deny_host ? (
        <section className="card">
          <h2>Last blocked</h2>
          <p>
            <strong>{snap.last_deny_host}</strong>
          </p>
          {snap.last_deny_summary && <p className="muted">{snap.last_deny_summary}</p>}
          {snap.last_deny_url && <p className="url muted">{snap.last_deny_url}</p>}
          <div className="row-actions">
            <button className="btn primary" disabled={busy} onClick={() => void allowLast()}>
              Allow this site
            </button>
            <button className="btn" onClick={() => onSeeHistory?.()}>
              See history
            </button>
          </div>
        </section>
      ) : (
        <section className="card">
          <h2>Nothing blocked yet — that is OK.</h2>
          <p className="muted">
            When DenyOut blocks something, you’ll get a short toast — and it will show up here.
          </p>
          <button className="btn" onClick={() => onSeeHistory?.()}>
            See history
          </button>
        </section>
      )}

      {blockedToday > 0 && (
        <p className="home-quiet muted">
          Blocked today: {blockedToday}
          {!snap?.last_deny_host && (
            <>
              {" · "}
              <button type="button" className="linkish" onClick={() => onSeeHistory?.()}>
                See history
              </button>
            </>
          )}
        </p>
      )}

      <nav className="home-doors" aria-label="More">
        <button type="button" className="linkish" onClick={() => onOpenSettings?.()}>
          Settings
        </button>
        <span className="muted" aria-hidden>
          ·
        </span>
        <button type="button" className="linkish" onClick={() => onOpenAgents?.()}>
          For AI tools
        </button>
      </nav>
    </div>
  );
}
