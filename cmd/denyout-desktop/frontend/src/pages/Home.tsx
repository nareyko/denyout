import { useEffect, useState } from "react";
import { ConfirmModal } from "../components/ConfirmModal";
import { PauseModal } from "../components/PauseModal";
import { api, UISnapshot } from "../wails";

export function Home({
 snap,
 pauseBlocked = false,
 pauseCloseReq = 0,
 onPauseOpenChange,
 onChanged,
 onSeeHistory,
 onOpenProblems,
 onOpenSettings,
 onOpenThreatSettings,
 onOpenAgents,
 onOpenSettingsDiagnostics,
 onOpenSystemBanners,
 onBeforeProtect,
}: {
 snap: UISnapshot | null;
 pauseBlocked?: boolean;
 pauseCloseReq?: number;
 onPauseOpenChange?: (open: boolean) => void;
 /** First-run: apply Quiet / A bit more before Protect turns on from Home peek. */
 onBeforeProtect?: () => void | Promise<void>;
 onChanged?: () => void;
 onSeeHistory?: () => void;
 onOpenProblems?: () => void;
 onOpenSettings?: () => void;
 onOpenThreatSettings?: () => void;
 onOpenAgents?: () => void;
 onOpenSettingsDiagnostics?: () => void;
 /** Advanced → System banners (master + fullscreen / silent). */
 onOpenSystemBanners?: () => void;
}) {
 const [msg, setMsg] = useState("");
 const [err, setErr] = useState("");
 const [busy, setBusy] = useState(false);
 const [pauseOpen, setPauseOpen] = useState(false);

 useEffect(() => {
 if (!pauseBlocked) return;
 setPauseOpen(false);
 setTurnOnOpen(false);
 setAllowConfirmOpen(false);
 }, [pauseBlocked]);

 useEffect(() => {
 if (pauseCloseReq > 0) setPauseOpen(false);
 }, [pauseCloseReq]);

 useEffect(() => {
 onPauseOpenChange?.(pauseOpen);
 return () => onPauseOpenChange?.(false);
 }, [pauseOpen, onPauseOpenChange]);
 const [turnOnOpen, setTurnOnOpen] = useState(false);
 const [allowConfirmOpen, setAllowConfirmOpen] = useState(false);

 const protectedOn = !!snap?.protection_on && snap?.mode === "safe";
 const needsHelp = !!snap?.problems_alert;
 const agentsOnly = snap?.mode === "agents";
 const sessionOn = snap?.mode === "session";
 const intentAgents = (snap?.policy_profile || "").toLowerCase() === "agent";
 // Live mode wins over a stale protection_on bit.
 const isOff = (snap?.mode === "off" || !snap?.mode) && !agentsOnly && !sessionOn;
 const pausedUntil = (snap?.protect_paused_until || "").trim();
 const pausedLabel = pausedUntil ? formatPauseUntil(pausedUntil) : "";
 const foreverOff = isOff && (snap?.protect_pause_last || "") === "forever";
 const canChangePause = !!(pausedLabel || foreverOff);
 // Broken leave-on only when alert + no live protector (mode off). Live+unhealthy uses Pause.
 const brokenIntent = needsHelp && (snap?.mode === "off" || !snap?.mode);
 // Off with agent policy: turn Agents only back on (not Protect computer).
 const turnOnAgents = intentAgents && (needsHelp || isOff);

 let headline = "Protection is off";
 let support =
 "Turn on Protect computer to block secret-looking links and clear threats while you browse.";
 if (needsHelp) {
 headline = "Needs your help";
 support = intentAgents
 ? "Agents only did not stay on. Try again, switch to Protect computer from Settings, or open Problems."
 : "Something went wrong with protection. Try again, or open Problems.";
 } else if (protectedOn) {
 headline = "You are protected";
 support = "Browse as usual. We'll only interrupt for clear risks.";
 } else if (agentsOnly) {
 headline = "Agents only is on";
 support =
 "Everyday browsing is not protected like Protect computer. Switch to Protect computer for normal web use, or pause Agents only from here. AI tools also belong under My agents.";
 } else if (sessionOn) {
 headline = "Session protection is on";
 support =
 "This is a limited session proxy — switch to Protect computer for everyday browsing.";
 } else if (pausedLabel) {
 const pauseNoun = intentAgents ? "Agents only" : "Protect";
 headline = intentAgents ? "Agents only is paused" : "Protection is paused";
 support = `${pauseNoun} stays off until ${pausedLabel}. Turn on anytime to resume, or change how long.`;
 } else if (foreverOff) {
 const pauseNoun = intentAgents ? "Agents only" : "Protect";
 headline = intentAgents
 ? "Agents only is off until you turn it on"
 : "Protection is off until you turn it on";
 support = `You chose to leave ${pauseNoun} off. Turn on anytime from here, or change to a timed pause.`;
 } else if (snap?.computer_available === false) {
 headline = "Protection is off";
 support = intentAgents
  ? (snap?.agents_running || 0) > 0
    ? "Agents only was unavailable last time (password cancelled or setup failed). My agents are still running — try Agents only again when ready, or switch to Protect computer from Settings."
    : "Agents only was unavailable last time (password cancelled or setup failed). Try Agents only again when ready, or switch to Protect computer from Settings."
  : (snap?.agents_running || 0) > 0
    ? "Protect computer was unavailable last time (password cancelled or setup failed). My agents are still running — try Protect again when ready."
    : "Protect computer was unavailable last time (password cancelled or setup failed). Try again when ready.";
 } else if ((snap?.agents_running || 0) > 0) {
 headline = "Protection is off";
 support = intentAgents
  ? snap!.agents_running === 1
    ? "My agent is running. Last mode was Agents only — turn it on again from here, or switch to Protect computer from Settings."
    : "My agents are running. Last mode was Agents only — turn it on again from here, or switch to Protect computer from Settings."
  : snap!.agents_running === 1
    ? "My agent is running, but everyday browsing is not protected. Turn on Protect computer when you want that."
    : "My agents are running, but everyday browsing is not protected. Turn on Protect computer when you want that.";
 } else if (intentAgents && isOff) {
 headline = "Protection is off";
 support =
 "Last mode was Agents only. Turn it on again, or switch to Protect computer from Settings.";
 }

 const showTurnOn = needsHelp || isOff || agentsOnly || sessionOn;
 const blockedToday = snap?.blocked_today ?? 0;

 const turnOnTitle = turnOnAgents
 ? "Turn on Agents only?"
 : agentsOnly || sessionOn
   ? "Switch to Protect computer?"
   : snap?.protect_confirm_title || "Turn on Protect computer?";
 const turnOnBody = turnOnAgents
 ? (snap?.helper_ok
     ? "DenyOut will set system network rules. Everyday browsing stays unprotected.\n\nYour system should not ask for a password (helper already installed).\n\nContinue?"
     : "Your system may ask for a password so DenyOut can set network rules. Everyday browsing stays unprotected. Continue?")
 : snap?.protect_confirm_body ||
 "Your system may ask for a password so DenyOut can set network rules. Continue?";

 function requestTurnOn() {
 setTurnOnOpen(true);
 }

 async function turnOn() {
 setBusy(true);
 setMsg("");
 setErr("");
 try {
 if (onBeforeProtect) await onBeforeProtect();
 if (turnOnAgents) await api.retryProtect();
 else if (agentsOnly || sessionOn) await api.switchSafe();
 else await api.enableSafe();
 setTurnOnOpen(false);
 onChanged?.();
 } catch (e) {
 setErr(String(e));
 } finally {
 setBusy(false);
 }
 }

 async function confirmPause(choice: string) {
 setBusy(true);
 setMsg("");
 setErr("");
 try {
 await api.stopProtectionWithChoice(choice);
 setPauseOpen(false);
 onChanged?.();
 } catch (e) {
 setErr(String(e));
 } finally {
 setBusy(false);
 }
 }

 function requestAllowLast() {
 if (!snap?.last_deny_host || looksLikeIP(snap.last_deny_host)) return;
 setAllowConfirmOpen(true);
 }

 async function allowLast() {
 if (!snap?.last_deny_host) return;
 setBusy(true);
 setMsg("");
 setErr("");
 try {
 await api.alwaysAllow(snap.last_deny_host, "", snap.last_deny_process || "");
 setAllowConfirmOpen(false);
 setMsg("Allowed " + snap.last_deny_host);
 onChanged?.();
 } catch (e) {
 setErr(String(e));
 } finally {
 setBusy(false);
 }
 }

 return (
 <div className="stack home">
 <section className={`home-hero card ${needsHelp ? "home-hero-alert" : ""}`}>
 <h1 className="home-headline">{headline}</h1>
 <p className="muted">{support}</p>
 {(snap?.notify_snooze_active ||
 snap?.away ||
 (typeof snap?.away_unread === "number" && snap.away_unread > 0) ||
 snap?.system_banners === false) && (
 <p className="notice-box" style={{ marginTop: "0.35rem" }}>
 {snap?.notify_snooze_active ? "Notifications snoozed. " : ""}
 {snap?.away ? "Away — quiet for now. " : ""}
 {typeof snap?.away_unread === "number" && snap.away_unread > 0
 ? `${snap.away_unread} quiet. `
 : ""}
 {snap?.system_banners === false
 ? "System banners off (Protect failed and tray-hidden on window close can still show). "
 : ""}
 {(snap?.notify_snooze_active ||
 snap?.away ||
 (typeof snap?.away_unread === "number" && snap.away_unread > 0)) && (
 <>
 <button type="button" className="linkish" onClick={() => onOpenSettings?.()}>
 Open Settings → Notifications
 </button>
 {snap?.system_banners === false ? " · " : ""}
 </>
 )}
 {snap?.system_banners === false ? (
 <button
 type="button"
 className="linkish"
 onClick={() => (onOpenSystemBanners || onOpenSettings)?.()}
 >
 Open Settings → Advanced → System banners
 </button>
 ) : null}
 </p>
 )}
 <div className="row-actions">
      {needsHelp ? (
        <>
          <button className="btn primary" disabled={busy} onClick={requestTurnOn}>
            {intentAgents ? "Try Agents only again" : "Try Protect computer again"}
          </button>
          <button className="btn" onClick={() => onOpenProblems?.()}>
            Open Problems
          </button>
          <button
            className="btn danger"
            disabled={busy || pauseBlocked}
            title={
              pauseBlocked
                ? "Finish the open Ask/block or tray pause first."
                : undefined
            }
            onClick={() => setPauseOpen(true)}
          >
            {brokenIntent ? "Clear intent / turn off…" : "Pause / turn off…"}
          </button>
        </>
      ) : showTurnOn ? (
        <>
          <button className="btn primary" disabled={busy} onClick={requestTurnOn}>
            {agentsOnly || sessionOn
              ? "Switch to Protect computer"
              : turnOnAgents
                ? "Turn on Agents only"
                : "Turn on Protect computer"}
          </button>
          {(agentsOnly || sessionOn) ? (
            <button
              className="btn danger"
              disabled={busy || pauseBlocked}
              title={
                pauseBlocked
                  ? "Finish the open Ask/block or tray pause first."
                  : undefined
              }
              onClick={() => setPauseOpen(true)}
            >
              Pause / turn off…
            </button>
          ) : canChangePause ? (
            <button
              className="btn"
              disabled={busy || pauseBlocked}
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
        </>
      ) : (
        <button
          className="btn danger"
          disabled={busy || pauseBlocked}
          title={
            pauseBlocked
              ? "Finish the open Ask/block or tray pause first."
              : undefined
          }
          onClick={() => setPauseOpen(true)}
        >
          Pause / turn off…
        </button>
      )}
 </div>
 {pauseBlocked ? (
  <p className="muted" style={{ marginTop: "0.35rem" }}>
   Pause is busy — finish the open Ask/block or tray pause first.
  </p>
 ) : null}
 {err ? (
 <p className="warn-box" style={{ marginTop: "0.65rem" }}>
 {err}
 </p>
 ) : msg ? (
 <p className="muted" style={{ marginTop: "0.65rem" }}>
 {msg}
 </p>
 ) : null}
 </section>

 {turnOnOpen ? (
 <ConfirmModal
 title={turnOnTitle}
 body={turnOnBody}
 busy={busy}
 error={err}
 onCancel={() => setTurnOnOpen(false)}
 onConfirm={() => void turnOn()}
 />
 ) : null}

 {allowConfirmOpen && snap?.last_deny_host ? (
 <ConfirmModal
 title={`Allow ${snap.last_deny_host}?`}
 body={
 (snap.last_deny_process || "").startsWith("wrap:")
 ? snap.mode === "safe" && snap.protection_on
   ? `Allow this site for Protect computer and this agent?\n\nDenyOut will stop blocking this host.`
   : `Always allow for this agent (and on the global allow list). DenyOut will stop blocking this host.`
 : `DenyOut will stop blocking this host.`
 }
 busy={busy}
 error={err}
 confirmLabel="Allow this site"
 onCancel={() => setAllowConfirmOpen(false)}
 onConfirm={() => void allowLast()}
 />
 ) : null}

 {pauseOpen ? (
 <PauseModal
 busy={busy}
 mode={snap?.mode}
 intentAgents={intentAgents}
 alreadyOff={canChangePause && !brokenIntent}
 brokenIntent={brokenIntent}
 error={err}
 onCancel={() => setPauseOpen(false)}
 onChoose={(c) => void confirmPause(c)}
 />
 ) : null}

 {snap?.last_deny_host ? (
 <section className="card">
 <h2>Last blocked</h2>
 <p>
 <strong>{snap.last_deny_host}</strong>
 </p>
 {snap.last_deny_summary && <p className="muted">{snap.last_deny_summary}</p>}
 {snap.last_deny_url && <p className="url muted">{snap.last_deny_url}</p>}
 {blockedToday > 1 ? (
 <p className="muted">Blocked today: {blockedToday}</p>
 ) : null}
 <div className="row-actions">
 {looksLikeIP(snap.last_deny_host) ? (
 <p className="muted" style={{ margin: 0 }}>
 Raw IP blocks cannot be always-allowed from here.
 </p>
 ) : (
 <button className="btn primary" disabled={busy} onClick={requestAllowLast}>
 Allow this site
 </button>
 )}
 <button className="btn" onClick={() => onSeeHistory?.()}>
 See History
 </button>
 </div>
 </section>
 ) : blockedToday > 0 ? (
 <section className="card">
 <h2>Blocked today: {blockedToday}</h2>
 <p className="muted">Open History to review what was blocked.</p>
 <button className="btn" onClick={() => onSeeHistory?.()}>
 See History
 </button>
 </section>
 ) : (
 <section className="card">
 <h2>Nothing blocked yet - that is OK.</h2>
 <p className="muted">
 {protectedOn || agentsOnly || sessionOn
 ? snap?.quiet_while_away === false
   ? "When DenyOut blocks something while you are here, you get an in-app Keep blocked / Allow this site prompt — and it shows up in History. Stay quiet while away is off — Ask/block dialogs can still appear while locked or idle (~5 min). Soft OS banners still follow How chatty / System banners (Quiet keeps them off except Protect failed). Fullscreen quiet is a separate Advanced setting (Respect fullscreen)."
   : "When DenyOut blocks something while you are here, you get an in-app Keep blocked / Allow this site prompt — and it shows up in History. With Stay quiet while away on, locked or idle (~5 min) stays quiet and shows one summary when you return. Soft OS banners stay off too (Protect failed can still show). Fullscreen quiet is separate (Advanced → Respect fullscreen)."
 : intentAgents
   ? "Last mode was Agents only. Turn it on again from here (or run My agents) to start recording blocks. Everyday browsing stays unprotected until you switch to Protect computer."
   : "Turn on Protect computer (or run My agents) to start recording blocks here. Everyday browsing stays unprotected until then."}
 </p>
 <button className="btn" onClick={() => onSeeHistory?.()}>
 See History
 </button>
 </section>
 )}

 {snap?.notice ? (
 <p className="notice-box" style={{ marginTop: 0 }}>
 {snap.notice}{" "}
 <button
 type="button"
 className="btn subtle"
 onClick={() =>
 void api
 .clearNotice()
 .then(() => onChanged?.())
 .catch((e) => setErr(String(e)))
 }
 >
 Dismiss
 </button>
 </p>
 ) : null}

 {snap?.threat_lists_warn && !snap?.problems_alert ? (
 <p className="home-quiet muted">
 Threat lists need a refresh.{" "}
 <button type="button" className="linkish" onClick={() => onOpenProblems?.()}>
 Open Problems
 </button>
 {" - "}
 <button
 type="button"
 className="linkish"
 onClick={() => (onOpenThreatSettings || onOpenSettings)?.()}
 >
 Threat lists
 </button>
 </p>
 ) : null}

 {snap?.update_available && (
 <p className="home-quiet muted">
 Newer DenyOut available{snap.update_version ? ` (${snap.update_version})` : ""}.{" "}
 <button
 type="button"
 className="linkish"
 onClick={() =>
 void api.openUpdateURL().catch((e) => setErr(String(e)))
 }
 >
 Open release
 </button>
 {" - "}
 <button
 type="button"
 className="linkish"
 onClick={() => {
 if (onOpenSettingsDiagnostics) onOpenSettingsDiagnostics();
 else onOpenSettings?.();
 }}
 >
 Settings
 </button>
 </p>
 )}

 <nav className="home-doors" aria-label="More">
 <button type="button" className="linkish" onClick={() => onOpenSettings?.()}>
 Settings
 </button>
 <span className="muted" aria-hidden>
 - 
 </span>
 <button type="button" className="linkish" onClick={() => onOpenAgents?.()}>
 For AI tools
 </button>
 </nav>
 </div>
 );
}

function looksLikeIP(host: string): boolean {
 const h = (host || "").trim();
 if (!h) return false;
 // IPv4
 if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
 // IPv6 (coarse)
 if (h.includes(":")) return true;
 return false;
}

function formatPauseUntil(iso: string): string {
 const t = Date.parse(iso);
 if (Number.isNaN(t)) return iso;
 const d = new Date(t);
 const now = new Date();
 // Match chrome/tray: time-only today; include day when pause crosses midnight.
 if (d.toDateString() === now.toDateString()) {
 return d.toLocaleTimeString(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
 });
 }
 return d.toLocaleString(undefined, {
 month: "short",
 day: "numeric",
 hour: "2-digit",
 minute: "2-digit",
 hour12: false,
 });
}
