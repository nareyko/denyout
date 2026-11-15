type Props = {
  blocks: number;
  waiting: number;
  hosts: string[];
  /** Mode-honest line: Protect computer / Agents only / My agents / generic. */
  keptRunningLine?: string;
  onReview: () => void;
  onDismiss: () => void;
};

/** One-shot return card after Away (Phase C). Not an OS toast wall. */
export function AwayDigestModal({
  blocks,
  waiting,
  hosts,
  keptRunningLine,
  onReview,
  onDismiss,
}: Props) {
  const top = (hosts || []).filter(Boolean).slice(0, 5);
  const hasWaiting = waiting > 0;
  const hasBlocks = blocks > 0;
  const kept =
    (keptRunningLine || "").trim() ||
    "Away did not turn protection off by itself.";

  return (
    <div className="modal-backdrop" style={{ zIndex: 50 }} role="presentation">
      <div
        className="modal"
        role="dialog"
        aria-labelledby="away-digest-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="away-digest-title">While you were away</h2>
        {hasBlocks ? (
          <p>
            {blocks === 1 ? "1 site blocked" : `${blocks} sites blocked`}
            {top.length > 0 ? (
              <>
                {" "}
                <span className="muted">
                  (
                  {top.join(", ")}
                  {hosts.length > top.length ? ", …" : ""})
                </span>
              </>
            ) : null}
            . {kept}
          </p>
        ) : null}
        {hasWaiting ? (
          <p>
            {waiting === 1
              ? "1 decision was waiting"
              : `${waiting} decisions were waiting`}
            . Review History to Allow or Keep blocked.
          </p>
        ) : null}
        {!hasBlocks && !hasWaiting ? (
          <p className="muted">Something waited while you were away.</p>
        ) : null}
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
