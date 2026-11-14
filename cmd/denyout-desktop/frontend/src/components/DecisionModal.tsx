import { useEffect, useRef, useState } from "react";

export type DecisionPayload = {
 id: string;
 host: string;
 reason: string;
 why: string;
 url: string;
 timeout: number;
 taught: boolean;
};

type Props = {
 payload: DecisionPayload;
 onResolve: (action: string) => void;
};

export function DecisionModal({ payload, onResolve }: Props) {
 const [left, setLeft] = useState(Math.max(1, payload.timeout || 15));
 const done = useRef(false);
 const resolveRef = useRef(onResolve);
 resolveRef.current = onResolve;

 function choose(action: string) {
 if (done.current) return;
 done.current = true;
 resolveRef.current(action);
 }

 useEffect(() => {
 done.current = false;
 setLeft(Math.max(1, payload.timeout || 15));
 const tick = window.setInterval(() => {
 setLeft((n) => {
 if (n <= 1) {
 window.clearInterval(tick);
 choose("later");
 return 0;
 }
 return n - 1;
 });
 }, 1000);
 return () => window.clearInterval(tick);
 // eslint-disable-next-line react-hooks/exhaustive-deps -- only reset on new decision id
 }, [payload.id, payload.timeout]);

 return (
 <div className="modal-backdrop decision-backdrop">
 <div className="modal decision-modal" role="dialog" aria-labelledby="decision-title">
 <h2 id="decision-title">DenyOut blocked something</h2>
 <p className="decision-host">{payload.host}</p>
 <p>{payload.why}</p>
 {payload.url ? <p className="muted mono">{payload.url}</p> : null}
 <p className="muted">
 {payload.taught
 ? "Keep blocked, allow this site, or decide later."
 : "This is how DenyOut protects you. Choose Keep blocked, Allow this site, or Decide later."}
 </p>
 <p className="muted">Auto Decide later in {left}s</p>
 <div className="decision-actions">
 <button type="button" className="btn primary" onClick={() => choose("keep")}>
 Keep blocked
 </button>
 <button type="button" className="btn" onClick={() => choose("keep_timed:15m")}>
 Keep 15 minutes
 </button>
 <button type="button" className="btn" onClick={() => choose("keep_timed:1h")}>
 Keep 1 hour
 </button>
 <button type="button" className="btn" onClick={() => choose("allow")}>
 Allow this site
 </button>
 <button type="button" className="btn" onClick={() => choose("allow_timed:15m")}>
 Allow 15 minutes
 </button>
 <button type="button" className="btn" onClick={() => choose("allow_timed:1h")}>
 Allow 1 hour
 </button>
 <button type="button" className="btn" onClick={() => choose("later")}>
 Decide later
 </button>
 <button type="button" className="btn subtle" onClick={() => choose("open")}>
 Open DenyOut
 </button>
 </div>
 </div>
 </div>
 );
}
