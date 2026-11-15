import { useEffect } from "react";
import { decisionModalOpen } from "./DecisionModal";

type Props = {
  busy?: boolean;
  /** True when Protect is already off (paused / forever) — change duration only. */
  alreadyOff?: boolean;
  /** Intent on but protector dead (Needs attention) — Cancel does not keep live Protect. */
  brokenIntent?: boolean;
  /** Shown inside the modal — page err behind the backdrop is invisible. */
  error?: string;
  onChoose: (choice: string) => void;
  onCancel: () => void;
};

const CHOICES: { id: string; label: string; hint: string }[] = [
  { id: "15m", label: "15 minutes", hint: "Short break" },
  { id: "1h", label: "1 hour", hint: "Default" },
  { id: "tomorrow", label: "About 24 hours", hint: "Rolling day — not calendar tomorrow morning" },
  { id: "forever", label: "Until I turn it on", hint: "Stay off" },
];

/** In-app pause / turn-off picker. */
export function PauseModal({
  busy,
  alreadyOff,
  brokenIntent,
  error,
  onChoose,
  onCancel,
}: Props) {
  const title = brokenIntent
    ? "Clear Protect intent?"
    : alreadyOff
      ? "Change pause?"
      : "Pause / turn off Protect?";
  const body = brokenIntent
    ? "Protect is not running right now. Choosing a duration clears restore intent so DenyOut stops trying to turn Protect back on. Cancel leaves intent as-is."
    : alreadyOff
      ? "How long should Protect stay off? Cancel leaves the current pause as-is."
      : "How long should Protect stay off? Cancel keeps protection on.";

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== "Escape" || busy) return;
      if (decisionModalOpen()) return;
      e.preventDefault();
      e.stopPropagation();
      onCancel();
    }
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [busy, onCancel]);

  return (
    <div
      className="modal-backdrop"
      style={{ zIndex: 55 }}
      onClick={() => !busy && onCancel()}
    >
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        <p className="muted">{body}</p>
        {error ? <p className="warn-box">{error}</p> : null}
        <div className="stack" style={{ gap: "0.5rem", marginTop: "0.85rem" }}>
          {CHOICES.map((c) => (
            <button
              key={c.id}
              type="button"
              className={c.id === "1h" ? "btn primary" : "btn"}
              disabled={busy}
              style={{ width: "100%", textAlign: "left" }}
              onClick={() => onChoose(c.id)}
            >
              <strong>{c.label}</strong>
              <div className="muted" style={{ fontWeight: 400, marginTop: "0.15rem" }}>
                {c.hint}
              </div>
            </button>
          ))}
          <button type="button" className="btn" disabled={busy} onClick={onCancel}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
