import type { ReactNode } from "react";

type Props = {
  blocks: number;
  waiting: number;
  /** Hosts for auto-kept / block quiet items. */
  hosts?: string[];
  /** Hosts for waiting decisions (Decide later). */
  waitingHosts?: string[];
  /** Mode-honest line: Protect computer / Agents only / My agents / generic. */
  keptRunningLine?: string;
  onReview: () => void;
  onDismiss: () => void;
};

function hostSpan(hosts: string[]): ReactNode {
  const top = (hosts || []).filter(Boolean).slice(0, 5);
  if (top.length === 0) return null;
  return (
    <>
      {" "}
      <span className="muted">
        ({top.join(", ")}
        {hosts.length > top.length ? ", …" : ""})
      </span>
    </>
  );
}

/** One-shot return card after Away (Phase C). Not an OS toast wall. */
export function AwayDigestModal({
  blocks,
  waiting,
  hosts,
  waitingHosts,
  keptRunningLine,
  onReview,
  onDismiss,
}: Props) {
  const blockHosts = hosts || [];
  const waitHosts = waitingHosts || [];
  const hasWaiting = waiting > 0;
  const hasBlocks = blocks > 0;
  const kept =
    (keptRunningLine || "").trim() ||
    "Protection was already off.";

  return (
    <div className="modal-backdrop" style={{ zIndex: 50 }} role="presentation">
      <div
        className="modal"
        role="dialog"
        aria-labelledby="away-digest-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="away-digest-title">Quiet items waiting</h2>
        {hasBlocks ? (
          <p>
            {blocks === 1 ? "1 site blocked" : `${blocks} sites blocked`}
            {hostSpan(blockHosts)}.
          </p>
        ) : null}
        {hasWaiting ? (
          <p>
            {waiting === 1
              ? "1 decision was waiting"
              : `${waiting} decisions were waiting`}
            {hostSpan(waitHosts)}. Review History to Allow or Keep blocked.
          </p>
        ) : null}
        {!hasBlocks && !hasWaiting ? (
          <p className="muted">
            Something waited while DenyOut stayed quiet (locked, idle, or fullscreen).
          </p>
        ) : null}
        <p className="muted">{kept}</p>
        <div className="decision-actions" style={{ marginTop: "0.85rem" }}>
          <button type="button" className="btn primary" onClick={onReview}>
            Review History
          </button>
          <button type="button" className="btn" onClick={onDismiss}>
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
