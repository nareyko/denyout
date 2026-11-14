import type { ReactNode } from "react";
import { api } from "../wails";

/** Dismissible on-screen tip; persists forever via desktop.json. */
export function Tip({
 id,
 dismissed,
 children,
 onDismiss,
}: {
 id: string;
 dismissed: boolean;
 children: ReactNode;
 onDismiss?: () => void;
}) {
 if (dismissed) return null;
 return (
 <div className="tip" role="note">
 <div className="tip-body">{children}</div>
 <button
 className="btn tip-dismiss"
 type="button"
 onClick={() => {
 void api.dismissTip(id).then(() => onDismiss?.());
 }}
 >
 Got it
 </button>
 </div>
 );
}

export function tipGone(dismissed: string[] | undefined, id: string): boolean {
 return (dismissed || []).includes(id);
}
