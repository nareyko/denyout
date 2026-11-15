import { useEffect } from "react";
import { decisionModalOpen } from "./DecisionModal";

type Props = {
  title: string;
  body: string;
  confirmLabel?: string;
  cancelLabel?: string;
  busy?: boolean;
  danger?: boolean;
  /** Shown inside the modal — page err behind the backdrop is invisible. */
  error?: string;
  onConfirm: () => void;
  onCancel: () => void;
};

/** Count of mounted confirms — App blocks Jump (Ctrl+K) while any are open. */
let openConfirmCount = 0;

export function confirmModalOpen(): boolean {
  return openConfirmCount > 0;
}

/** In-app confirm (same chrome as tray Protect / Pause — not window.confirm). */
export function ConfirmModal({
  title,
  body,
  confirmLabel = "Continue",
  cancelLabel = "Cancel",
  busy,
  danger,
  error,
  onConfirm,
  onCancel,
}: Props) {
  useEffect(() => {
    openConfirmCount += 1;
    function onKey(e: KeyboardEvent) {
      if (e.key !== "Escape" || busy) return;
      // Ask/block owns Esc — do not cancel buried Profiles/Activity confirms.
      if (decisionModalOpen()) return;
      e.preventDefault();
      e.stopPropagation();
      onCancel();
    }
    // Capture so Esc cancels confirm before App opens Jump / dismisses setup.
    window.addEventListener("keydown", onKey, true);
    return () => {
      openConfirmCount = Math.max(0, openConfirmCount - 1);
      window.removeEventListener("keydown", onKey, true);
    };
  }, [busy, onCancel]);

  return (
    <div className="modal-backdrop" style={{ zIndex: 55 }} onClick={() => !busy && onCancel()}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        <p className="muted" style={{ whiteSpace: "pre-wrap" }}>
          {body}
        </p>
        {error ? <p className="warn-box">{error}</p> : null}
        <div className="row-actions" style={{ marginTop: "1rem" }}>
          <button
            type="button"
            className={danger ? "btn danger" : "btn primary"}
            disabled={busy}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
          <button type="button" className="btn" disabled={busy} onClick={onCancel}>
            {cancelLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
