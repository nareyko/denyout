import { useEffect, useRef, useState } from "react";

export type DecisionPayload = {
  id: string;
  host: string;
  reason: string;
  why: string;
  url: string;
  timeout: number;
  taught: boolean;
  kind?: string;
  profile_name?: string;
  /** Set for My agents wrap hard-blocks (no timed Allow — session-only). */
  profile_id?: string;
  /** Multi-host void: one choice applies to every listed site. */
  batch?: boolean;
  /** Batch spans more than one wrap profile. */
  multi_agent?: boolean;
};

type Props = {
  payload: DecisionPayload;
  onResolve: (action: string) => void | Promise<void>;
  error?: string;
};

/** Mounted Ask/block count — Confirm Esc must not dismiss buried confirms. */
let openDecisionCount = 0;

export function decisionModalOpen(): boolean {
  return openDecisionCount > 0;
}

function looksLikeIP(host: string): boolean {
  const h = (host || "").trim();
  if (!h) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(":")) return true;
  return false;
}

export function DecisionModal({ payload, onResolve, error }: Props) {
  const [left, setLeft] = useState(Math.max(1, payload.timeout || 15));
  const done = useRef(false);
  const resolveRef = useRef(onResolve);
  resolveRef.current = onResolve;
  const ipHost = looksLikeIP(payload.host);
  const isAsk = (payload.kind || "hard") === "ask";
  const isWrapHard = !isAsk && !!(payload.profile_id || "").trim();
  const isBatch = !isAsk && !!payload.batch;
  const isMultiAgent = !!payload.multi_agent;
  // Whole-PC Agents only Ask has no wrap profile_id (name alone is not enough).
  const isWrapAsk = isAsk && !!(payload.profile_id || "").trim();
  const defaultTimeoutAction = isAsk ? "deny" : "later";
  const expired = left <= 0;

  function choose(action: string) {
    if (done.current) return;
    done.current = true;
    void Promise.resolve(resolveRef.current(action)).catch(() => {
      // Keep modal open so the user can retry after a bridge failure.
      done.current = false;
    });
  }

  useEffect(() => {
    openDecisionCount += 1;
    return () => {
      openDecisionCount = Math.max(0, openDecisionCount - 1);
    };
  }, [payload.id]);

  useEffect(() => {
    done.current = false;
    const secs = Math.max(1, payload.timeout || 15);
    // Wall-clock deadline survives background-tab interval throttling.
    const deadline = Date.now() + secs * 1000;
    setLeft(secs);
    const tick = window.setInterval(() => {
      if (done.current) return;
      const rem = Math.ceil((deadline - Date.now()) / 1000);
      if (rem <= 0) {
        window.clearInterval(tick);
        setLeft(0);
        choose(defaultTimeoutAction);
        return;
      }
      setLeft(rem);
    }, 250);
    return () => window.clearInterval(tick);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- timer only; choose uses refs
  }, [payload.id, payload.timeout, defaultTimeoutAction]);

  if (isAsk) {
    return (
      <div className="modal-backdrop decision-backdrop">
        <div className="modal decision-modal" role="dialog" aria-labelledby="decision-title">
          <h2 id="decision-title">
            {isWrapAsk
              ? payload.profile_name
                ? `${payload.profile_name} wants a new site`
                : "An agent wants a new site"
              : "New site under Agents only"}
          </h2>
          <p className="decision-host">{payload.host}</p>
          <p style={{ whiteSpace: "pre-wrap" }}>
            {payload.why ||
              (isWrapAsk
                ? "Not on this agent’s allowlist yet."
                : "Not on the whole-PC allowlist yet.")}
          </p>
          <p className="muted">
            {isWrapAsk
              ? "Allow once for this run, always for this agent, or keep blocked."
              : "Allow for 1 hour, always allow, or keep blocked."}
          </p>
          <p className="muted">
            {expired ? "Timed out — Keep blocked applied." : `Auto Keep blocked in ${left}s`}
          </p>
          {error ? <p className="warn-box">{error}</p> : null}
          <div className="decision-actions">
            <button type="button" className="btn primary" onClick={() => choose("deny")}>
              Keep blocked
            </button>
            {ipHost ? (
              <p className="muted" style={{ margin: 0, gridColumn: "1 / -1" }}>
                Raw IPs cannot be always-allowed.
              </p>
            ) : (
              <>
                <button type="button" className="btn" onClick={() => choose("once")}>
                  {isWrapAsk ? "Allow once" : "Allow for 1 hour"}
                </button>
                <button type="button" className="btn" onClick={() => choose("always")}>
                  Always allow
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="modal-backdrop decision-backdrop">
      <div className="modal decision-modal" role="dialog" aria-labelledby="decision-title">
        <h2 id="decision-title">
          {isBatch ? "DenyOut blocked several sites" : "DenyOut blocked something"}
        </h2>
        <p className="decision-host">{payload.host}</p>
        <p style={{ whiteSpace: "pre-wrap" }}>{payload.why}</p>
        {payload.url ? <p className="muted mono">{payload.url}</p> : null}
        <p className="muted">
          {isBatch
            ? "Your choice applies to every site in the list."
            : isWrapHard
              ? "Keep blocked, allow for this agent, or decide later."
              : payload.taught
                ? "Keep blocked, allow this site, or decide later."
                : "This is how DenyOut protects you. Choose Keep blocked, Allow this site, or Decide later."}
        </p>
        <p className="muted">
          {expired ? "Timed out — Decide later applied." : `Auto Decide later in ${left}s`}
        </p>
        {error ? <p className="warn-box">{error}</p> : null}
        <div className="decision-actions">
          <button type="button" className="btn primary" onClick={() => choose("keep")}>
            {isBatch ? "Keep all blocked" : "Keep blocked"}
          </button>
          <button type="button" className="btn" onClick={() => choose("keep_timed:15m")}>
            {isBatch ? "Keep all 15 minutes" : "Keep 15 minutes"}
          </button>
          <button type="button" className="btn" onClick={() => choose("keep_timed:1h")}>
            {isBatch ? "Keep all 1 hour" : "Keep 1 hour"}
          </button>
          {ipHost ? (
            <p className="muted" style={{ margin: 0, gridColumn: "1 / -1" }}>
              Raw IPs cannot be always-allowed.
            </p>
          ) : (
            <>
              <button type="button" className="btn" onClick={() => choose("allow")}>
                {isWrapHard
                  ? isBatch
                    ? isMultiAgent
                      ? "Always allow listed sites for these agents"
                      : "Always allow listed sites for this agent"
                    : "Always allow for this agent"
                  : isBatch
                    ? "Allow all listed sites"
                    : "Allow this site"}
              </button>
              {isWrapHard ? (
                <button type="button" className="btn" onClick={() => choose("allow_timed:15m")}>
                  {isBatch
                    ? isMultiAgent
                      ? "Allow listed sites for this run (all agents)"
                      : "Allow listed sites for this run"
                    : "Allow for this run"}
                </button>
              ) : (
                <>
                  <button type="button" className="btn" onClick={() => choose("allow_timed:15m")}>
                    {isBatch ? "Allow all 15 minutes" : "Allow 15 minutes"}
                  </button>
                  <button type="button" className="btn" onClick={() => choose("allow_timed:1h")}>
                    {isBatch ? "Allow all 1 hour" : "Allow 1 hour"}
                  </button>
                </>
              )}
            </>
          )}
          <button type="button" className="btn" onClick={() => choose("later")}>
            Decide later
          </button>
          <button type="button" className="btn subtle" onClick={() => choose("open")}>
            Open History
          </button>
        </div>
      </div>
    </div>
  );
}
