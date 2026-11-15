import { useEffect, useMemo, useRef, useState } from "react";
import { ConfirmModal } from "../components/ConfirmModal";
import { PauseModal } from "../components/PauseModal";
import { Tip, tipGone } from "../components/Tip";
import { api, ThreatListsView, UISnapshot } from "../wails";

type Tab = "basic" | "advanced";

const BASIC_FIND_KEYS = [
  "protection",
  "protect",
  "protected",
  "safe",
  "off",
  "pause",
  "paused",
  "session",
  "notification",
  "notify",
  "toast",
  "quiet",
  "normal",
  "level",
  "chatty",
  "snooze",
  "overnight",
  "night",
  "sound",
  "away",
  "timeout",
  "re-ask",
  "reask",
  "decision",
  "interval",
  "autostart",
  "at login",
  "launch",
  "threat",
  "phish",
  "malware",
  "urlhaus",
  "list",
  "block known",
  "refresh",
  "stronger",
  "hagezi",
  "computer",
  "poll",
  "hours",
  "exception",
  "exceptions",
  "product exception",
];

const ADVANCED_FIND_KEYS = [
  "always allow",
  "always-allow",
  "host",
  "keep",
  "remembered",
  "silenced",
  "sites",
  "allowed",
  "timed",
  "temporary",
  "while",
  "agents only",
  "allowlist",
  "whole",
  "ask",
  "resume",
  "diagn",
  "log",
  "logs",
  "audit",
  "test",
  "version",
  "update",
  "reset",
  "privacy",
  "helper",
  "password",
  "account",
  "sign",
  "sign in",
  "sync",
  "email",
  "agent",
  "wrap",
  "oisd",
  "steven",
  "ads",
  "tracker",
  "optional",
  "optional list",
  "advanced list",
  "advanced lists",
  "undo",
  "detailed",
  "banner",
  "banners",
  "fullscreen",
  "games",
  "silent",
  "system banners",
  "notification",
  "notify",
];

function findKeysMatch(keys: string[], findQ: string): boolean {
  if (!findQ) return true;
  return keys.some((k) => {
    const kk = k.toLowerCase();
    // Exact key always matches (short keys like "log").
    if (kk === findQ) return true;
    // Multi-word keys: whole-token equality only ("log" must not hit "at login").
    if (kk.includes(" ")) {
      return kk.split(/\s+/).some((tok) => tok === findQ);
    }
    // Single-word keys: substring only for queries length ≥ 3.
    if (findQ.length < 3) return false;
    if (kk.includes(findQ)) return true;
    return findQ.includes(kk);
  });
}

export function Settings({
 snap: snapProp,
 onChanged,
 tipsEnabled = true,
 initialTab,
 focusSection,
 focusNonce = 0,
 pauseBlocked = false,
 pauseCloseReq = 0,
 onClearFocus,
 onPauseOpenChange,
 onOpenActivity,
}: {
 snap?: UISnapshot | null;
 onChanged?: () => void;
 tipsEnabled?: boolean;
 initialTab?: Tab;
 focusSection?: string;
 focusNonce?: number;
 pauseBlocked?: boolean;
 pauseCloseReq?: number;
 onClearFocus?: () => void;
 onPauseOpenChange?: (open: boolean) => void;
 onOpenActivity?: () => void;
}) {
 const [snap, setSnap] = useState<UISnapshot | null>(snapProp ?? null);
 const [threats, setThreats] = useState<ThreatListsView | null>(null);
 const [threatBusy, setThreatBusy] = useState(false);
 const [msg, setMsg] = useState("");
 const [err, setErr] = useState("");
 const [filter, setFilter] = useState("");
 const [find, setFind] = useState("");
 const note = (m: string) => {
 setErr("");
 setMsg(m);
 };
 const fail = (e: unknown) => {
 setMsg("");
 setErr(String(e));
 };
 const [tab, setTab] = useState<Tab>(initialTab ?? "basic");
 const [acctEmail, setAcctEmail] = useState("");
 const [acctCode, setAcctCode] = useState("");
 const [apiBase, setApiBase] = useState("");
 const [decisionTimeoutDraft, setDecisionTimeoutDraft] = useState<number | null>(null);
 const [reaskDraft, setReaskDraft] = useState<number | null>(null);
 const [pollHoursDraft, setPollHoursDraft] = useState<number | null>(null);
 const [pauseOpen, setPauseOpen] = useState(false);
 const [pauseBusy, setPauseBusy] = useState(false);
 const [protectConfirm, setProtectConfirm] = useState<null | {
 title: string;
 body: string;
 action: "retry" | "enable" | "switch" | "agents";
 }>(null);
 const [protectBusy, setProtectBusy] = useState(false);
 const [addAllowHost, setAddAllowHost] = useState("");
 const [resetConfirm, setResetConfirm] = useState(false);
 const [resetBusy, setResetBusy] = useState(false);
 const [extraConfirm, setExtraConfirm] = useState<null | {
 title: string;
 body: string;
 danger?: boolean;
 confirmLabel?: string;
 run: () => Promise<void>;
 }>(null);
 const [extraBusy, setExtraBusy] = useState(false);

 async function reloadThreats() {
 const t = await api.threatLists();
 setThreats(t);
 }

 async function reload() {
 const s = await api.snapshot();
 setSnap(s);
 try {
 const acct = await api.accountView();
 if (acct?.api_base) setApiBase(acct.api_base);
 if (acct?.email && !acctEmail) setAcctEmail(acct.email);
 } catch {
 /* optional account bridge */
 }
 try {
 await reloadThreats();
 } catch {
 /* Bridge may omit threats in older builds */
 }
 onChanged?.();
 }

 useEffect(() => {
 if (snapProp) setSnap(snapProp);
 }, [snapProp]);

 useEffect(() => {
 void reload().catch((e) => fail(e));
 }, []);
 useEffect(() => {
 if (initialTab) setTab(initialTab);
 }, [initialTab, focusNonce]);
 // Keep threat card in sync with polled snapshot warn (nav badge can flip first).
 useEffect(() => {
 if (snapProp?.threat_lists_warn == null) return;
 void reloadThreats().catch(() => undefined);
 }, [snapProp?.threat_lists_warn]);

 useEffect(() => {
 if (!pauseBlocked) return;
 setPauseOpen(false);
 setProtectConfirm(null);
 setExtraConfirm(null);
 setResetConfirm(false);
 }, [pauseBlocked]);

 useEffect(() => {
 if (pauseCloseReq > 0) setPauseOpen(false);
 }, [pauseCloseReq]);

 useEffect(() => {
 onPauseOpenChange?.(pauseOpen);
 return () => onPauseOpenChange?.(false);
 }, [pauseOpen, onPauseOpenChange]);

 // Apply Find clear / tab / scroll only on intentional nav (focusNonce).
 // Clearing focus from Find must not wipe the character just typed.
 const appliedFocusNonce = useRef(-1);
 useEffect(() => {
 if (appliedFocusNonce.current === focusNonce) return;
 appliedFocusNonce.current = focusNonce;
 setFind("");
 if (initialTab) setTab(initialTab);
 if (!focusSection) {
 // Bare Settings / settings-advanced: show the tab from the top.
 const top = () => {
 document.querySelector(".main .content")?.scrollTo({ top: 0, behavior: "smooth" });
 };
 requestAnimationFrame(() => requestAnimationFrame(top));
 return;
 }
 const id = `settings-${focusSection}`;
 const scroll = () => {
 document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
 };
 requestAnimationFrame(() => requestAnimationFrame(scroll));
 const t = window.setTimeout(scroll, 100);
 return () => window.clearTimeout(t);
 }, [focusSection, focusNonce, initialTab]);

 const findQ = find.trim().toLowerCase();

 const showSection = useMemo(() => {
 return (keys: string[], id?: string) => {
 if (id && focusSection === id) return true;
 return findKeysMatch(keys, findQ);
 };
 }, [findQ, focusSection]);

 if (!snap) {
 return <p className="muted">{err || msg || "Loading..."}</p>;
 }

 const allows = (snap.always_allow || []).filter((h) =>
 h.toLowerCase().includes(filter.toLowerCase()),
 );
 const dismissed = snap.dismissed_tips;

 function enableAgentsOnly() {
 const running = snap?.agents_running || 0;
 const wraps =
  running > 0
   ? `\n\nRunning My agents wraps will stop (${running}).`
   : "\n\nAny running My agents wraps will stop.";
 setProtectConfirm({
 title: "Turn on Agents only for the whole computer?",
 body:
  "Messengers and many sites may stop working. Prefer My agents for AI tools." +
  wraps +
  "\n\nOnly continue if you understand the risk.",
 action: "agents",
 });
 }

 const intentAgents = (snap.policy_profile || "").toLowerCase() === "agent";
 const agentsConfirmBody = snap.helper_ok
 ? "DenyOut will set system network rules. Everyday browsing stays unprotected.\n\nYour system should not ask for a password (helper already installed).\n\nContinue?"
 : "Your system may ask for a password so DenyOut can set network rules. Everyday browsing stays unprotected. Continue?";
 const protectLive =
 (snap.mode === "safe" || snap.mode === "agents" || snap.mode === "session") &&
 !snap.problems_alert;
 // Proxyd restart (password possible) only for whole-PC computer mode — not session.
 // Live computer proxy (safe / agents). Session is separate below.
 const computerLive = snap.mode === "safe" || snap.mode === "agents";
 const computerLiveNoun =
  snap.mode === "agents" || intentAgents ? "Agents only" : "Protect";
 // available === false means store failed; omit field (older bridge) still counts as ready.
 const threatsReady = !!threats && threats.available !== false;
 const showTurnOnProtect =
 snap?.mode === "agents" || snap?.mode === "session"
 ? false // Switch button handles this
 : !protectLive;
 const brokenIntent = !!snap.problems_alert && (snap.mode === "off" || !snap.mode);
 // Match Home: allow Change pause when paused/forever even if intent protection_on is stale.
 const canChangePause =
 !protectLive &&
 !brokenIntent &&
 (!!(snap?.protect_paused_until || "").trim() ||
 (snap?.protect_pause_last || "") === "forever");
 const pausedUntilLabel = (snap.protect_paused_until || "").trim();
 const foreverOffLabel =
 (snap.mode === "off" || !snap.mode) &&
 (snap.protect_pause_last || "") === "forever";
 const agentsOnlyOff =
 !snap.problems_alert &&
 (snap.mode === "off" || !snap.mode) &&
 !pausedUntilLabel &&
 !foreverOffLabel &&
 (snap.agents_running || 0) > 0;
 const unavailableOff =
 !snap.problems_alert &&
 (snap.mode === "off" || !snap.mode) &&
 !pausedUntilLabel &&
 !foreverOffLabel &&
 snap.computer_available === false;
 const pauseNoun = intentAgents ? "Agents only" : "Protect";
 const protectionNow = snap.problems_alert
 ? "Needs attention"
 : snap.mode === "safe"
   ? "Protected"
   : snap.mode === "agents"
     ? "Agents only"
     : snap.mode === "session"
       ? "Session"
       : pausedUntilLabel
         ? `${pauseNoun} paused until ${formatExpiry(pausedUntilLabel)}`
         : foreverOffLabel
           ? intentAgents
             ? "Agents only off until you turn it on"
             : "Off until you turn it on"
           : unavailableOff
             ? (snap.agents_running || 0) > 0
               ? "Off (unavailable) · agents running"
               : "Off (unavailable)"
             : agentsOnlyOff
               ? "Off · agents running"
               : snap.mode_label || "Off";
 const findHitsBasic = findKeysMatch(BASIC_FIND_KEYS, findQ);
 const findHitsAdvanced = findKeysMatch(ADVANCED_FIND_KEYS, findQ);

 async function confirmPause(choice: string) {
 setPauseBusy(true);
 setErr("");
 try {
 await api.stopProtectionWithChoice(choice);
 setPauseOpen(false);
 await reload();
 } catch (e) {
 fail(e);
 } finally {
 setPauseBusy(false);
 }
 }

 return (
 <div className="stack">
 {err ? <p className="warn-box">{err}</p> : msg ? <p className="muted">{msg}</p> : null}

 <div className="toolbar">
 <input
 className="settings-find"
 placeholder="Find a setting..."
 value={find}
 onChange={(e) => {
 const v = e.target.value;
 setFind(v);
 // Typing Find abandons Jump/deep-link focus so tab switch can show matches.
 if (focusSection) onClearFocus?.();
        const q = v.toLowerCase();
        const basicHit = findKeysMatch(BASIC_FIND_KEYS, q);
        const advHit = findKeysMatch(ADVANCED_FIND_KEYS, q);
        // Prefer Advanced when only Advanced matches (e.g. remembered, login, helper).
        // "pause asks" / ask / resume stay Advanced; plain "pause" stays Basic.
        if (
          /\basks?\b/.test(q) ||
          q.includes("resume") ||
          q.includes("system banner") ||
          q.includes("system banners") ||
          (q.includes("banner") && !q.includes("notification")) ||
          q === "log" ||
          q.includes("logs") ||
          q.includes("allowlist") ||
          q.includes("diagn")
        ) {
          setTab("advanced");
        } else if (advHit && !basicHit) {
          setTab("advanced");
        } else if (basicHit && !advHit) {
          setTab("basic");
        } else if (advHit && basicHit) {
          // "at login" is Autostart (Basic); bare account/sign terms are Advanced.
          if (q.includes("at login") || q.includes("autostart") || q.includes("launch")) {
            setTab("basic");
          } else if (
            q.includes("optional") ||
            q.includes("oisd") ||
            q.includes("steven") ||
            q.includes("agent") ||
            q.includes("always") ||
            q.includes("keep") ||
            q.includes("diagn") ||
            q.includes("account") ||
            q.includes("sign") ||
            q.includes("advanced") ||
            q.includes("password") ||
            q.includes("allowlist") ||
            q === "log" ||
            q.includes("logs")
          ) {
            setTab("advanced");
          } else {
            setTab("basic");
          }
        }
 }}
 />
 </div>

 <div className="tabs" role="tablist">
 <button
 type="button"
 role="tab"
 className={tab === "basic" ? "tab active" : "tab"}
 aria-selected={tab === "basic"}
 onClick={() => setTab("basic")}
 >
 Basic
 </button>
 <button
 type="button"
 role="tab"
 className={tab === "advanced" ? "tab active" : "tab"}
 aria-selected={tab === "advanced"}
 onClick={() => setTab("advanced")}
 >
 Advanced
 </button>
 </div>

 {findQ && !findHitsBasic && !findHitsAdvanced ? (
 <p className="muted">No settings match “{find.trim()}”.</p>
 ) : findQ && tab === "basic" && !findHitsBasic && findHitsAdvanced ? (
 <p className="muted">
 Matches are under Advanced.{" "}
 <button type="button" className="linkish" onClick={() => setTab("advanced")}>
 Open Advanced
 </button>
 </p>
 ) : findQ && tab === "advanced" && !findHitsAdvanced && findHitsBasic ? (
 <p className="muted">
 Matches are under Basic.{" "}
 <button type="button" className="linkish" onClick={() => setTab("basic")}>
 Open Basic
 </button>
 </p>
 ) : findQ &&
   (findQ.includes("wrap") || findQ === "agent" || findQ === "agents") &&
   tab === "advanced" &&
   findHitsAdvanced ? (
 <p className="muted">
 Tip: wrap one program under{" "}
 <strong>My agents</strong> in the sidebar. Whole-PC Agents only is below when you need it.
 </p>
 ) : null}

 {tab === "basic" ? (
 <>
 {tipsEnabled && (
 <Tip
 id="settings-basic"
 dismissed={tipGone(dismissed, "settings-basic")}
 onDismiss={onChanged}
 >
 Basic is Protect on/off, how chatty DenyOut is, snooze, threat lists, and autostart.
 Block timeouts live here too. Allowed sites, system banner master, and Detailed live
 under Advanced.
 </Tip>
 )}

 {showSection(
 [
 "protection",
 "protect",
 "protected",
 "safe",
 "off",
 "pause",
 "paused",
 "session",
 "computer",
 ],
 "protection",
 ) && (
 <section className="card" id="settings-protection">
 <h2>Protection</h2>
 <p className="muted">
 Same On/Off as Home. Rare options (allowed sites, Agents only) are under Advanced.
 </p>
          <p style={{ marginBottom: "0.65rem" }}>
            Now:{" "}
            <strong>{protectionNow}</strong>
 </p>
 <div className="row-actions">
 {snap.mode === "agents" || snap.mode === "session" ? (
 <>
 {snap.mode === "agents" && snap.problems_alert ? (
 <button
 className="btn primary"
 onClick={() =>
 setProtectConfirm({
 title: "Turn on Agents only?",
 body: agentsConfirmBody,
 action: "retry",
 })
 }
 >
 Try Agents only again
 </button>
 ) : null}
 <button
 className="btn primary"
 onClick={() =>
 setProtectConfirm({
 title: "Switch to Protect computer?",
 body:
 snap.protect_confirm_body ||
 "Your system may ask for a password so DenyOut can set network rules. Continue?",
 action: "switch",
 })
 }
 >
 Switch to Protect computer
 </button>
 </>
 ) : showTurnOnProtect ? (
 <button
 className="btn primary"
 onClick={() => {
 setProtectConfirm({
 title: intentAgents
 ? "Turn on Agents only?"
 : snap.protect_confirm_title || "Turn on Protect computer?",
 body: intentAgents
 ? agentsConfirmBody
 : snap.protect_confirm_body ||
 "Your system may ask for a password so DenyOut can set network rules. Continue?",
 action: intentAgents || snap.problems_alert ? "retry" : "enable",
 });
 }}
 >
 {snap.problems_alert
 ? intentAgents
   ? "Try Agents only again"
   : "Try Protect computer again"
 : intentAgents
   ? "Turn on Agents only"
   : "Turn on Protect computer"}
 </button>
 ) : null}
 {brokenIntent || protectLive || snap.problems_alert ? (
 <button
 className="btn danger"
 disabled={pauseBlocked}
 title={
  pauseBlocked
   ? "Finish the open Ask/block or tray pause first."
   : undefined
 }
 onClick={() => setPauseOpen(true)}
 >
 {brokenIntent ? "Clear intent / turn off…" : "Pause / turn off…"}
 </button>
 ) : canChangePause ? (
 <button
  className="btn"
  disabled={pauseBlocked}
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
 {pauseBlocked ? (
  <p className="muted" style={{ marginTop: "0.35rem" }}>
   Pause is busy — finish the open Ask/block or tray pause first.
  </p>
 ) : null}
 </div>
 </section>
 )}

 {showSection(
 [
 "notification",
 "notify",
 "toast",
 "quiet",
 "banner",
 "normal",
 "level",
 "chatty",
 "snooze",
 "overnight",
 "night",
 "sound",
 "away",
 "timeout",
 "re-ask",
 "reask",
 "decision",
 "interval",
 ],
 "notifications",
 ) && (
 <section className="card" id="settings-notifications">
 <h2>Notifications</h2>
 <p className="muted">
 Blocks always go to History. The tray shows a count. With Stay quiet while away
 on, DenyOut shows one summary when you return. Ask and Keep blocked / Allow this
 site stay inside DenyOut.
 </p>
          {(snap.notify_snooze_active ||
            snap.system_banners === false ||
            snap.silent_when_open === false ||
            snap.respect_fullscreen === false ||
            snap.quiet_overnight === false ||
            snap.sound_only_answer === false ||
            snap.away ||
            (typeof snap.away_unread === "number" && snap.away_unread > 0) ||
            snap.away_digest?.pending) && (
            <div className="notice-box" style={{ marginBottom: "0.65rem" }}>
              <p style={{ margin: 0 }}>
                {snap.notify_snooze_active
                  ? `Snoozed${
                      snap.notify_snooze_until
                        ? ` until ${new Date(snap.notify_snooze_until).toLocaleString()}`
                        : ""
                    }. `
                  : ""}
                {snap.system_banners === false
                  ? "System banners off (Protect failed can still show). "
                  : ""}
                {snap.silent_when_open === false
                  ? "OS can speak while DenyOut is focused. "
                  : ""}
                {snap.respect_fullscreen === false
                  ? "Fullscreen respect off. "
                  : ""}
                {snap.quiet_overnight === false ? "Night quiet sound off. " : ""}
                {snap.sound_only_answer === false
                  ? "Sound may play for soft OS banners (Undo / Open / status). "
                  : ""}
                {snap.away ? "Away right now. " : ""}
                {typeof snap.away_unread === "number" && snap.away_unread > 0
                  ? `${snap.away_unread} quiet while away (summary when you return). `
                  : ""}
                {snap.away_digest?.pending ? "Return summary is ready. " : ""}
                {protectionContinuityNow(snap)}
              </p>
              {snap.away_digest?.pending ? (
                <div className="row-actions" style={{ marginTop: "0.5rem", gap: "0.4rem" }}>
                  <button
                    type="button"
                    className="btn primary"
                    onClick={() =>
                      void api
                        .dismissAwayDigest()
                        .then(() => {
                          onOpenActivity?.();
                          return reload();
                        })
                        .catch((err) => fail(err))
                    }
                  >
                    Review History
                  </button>
                  <button
                    type="button"
                    className="btn"
                    onClick={() =>
                      void api
                        .dismissAwayDigest()
                        .then(reload)
                        .catch((err) => fail(err))
                    }
                  >
                    Dismiss summary
                  </button>
                </div>
              ) : null}
            </div>
          )}
          <label>
            How chatty{" "}
            <select
              value={
                snap.notify_level === "quiet"
                  ? "quiet"
                  : snap.notify_level === "detailed"
                    ? "detailed"
                    : "normal"
              }
              onChange={(e) => {
                const v = e.target.value;
                if (v === "detailed") {
                  // Detailed lives under Advanced — jump to the full control.
                  setTab("advanced");
                  window.setTimeout(() => {
                    document
                      .getElementById("settings-system-banners")
                      ?.scrollIntoView({ behavior: "smooth", block: "start" });
                  }, 50);
                  return;
                }
                void api
                  .setNotifyLevel(v)
                  .then(reload)
                  .catch((err) => fail(err));
              }}
            >
              <option value="quiet">Quiet (recommended)</option>
              <option value="normal">A bit more</option>
              {snap.notify_level === "detailed" ? (
                <option value="detailed">Detailed — open Advanced…</option>
              ) : null}
            </select>
          </label>
          <p className="muted" style={{ marginTop: "0.25rem" }}>
            {snap.notify_level === "detailed"
              ? "Detailed is on (Advanced → System banners). Today it uses the same OS banner kinds as A bit more — pick Quiet or A bit more here to leave Detailed."
              : "Detailed lives under Advanced → System banners. Today it matches A bit more for OS banner kinds."}
          </p>
          <label style={{ display: "block", marginTop: "0.65rem" }}>
            <input
              type="checkbox"
              checked={snap.quiet_while_away !== false}
              onChange={(e) =>
                void api
                  .setQuietWhileAway(e.target.checked)
                  .then(reload)
                  .catch((err) => fail(err))
              }
            />{" "}
            Stay quiet while away
          </label>
          <p className="muted" style={{ marginTop: "0.25rem" }}>
            {snap.quiet_while_away === false
              ? "Off: Ask and block dialogs can appear while the screen is locked or idle."
              : "When on: no Ask or block dialogs while locked or idle; soft OS banners stay off. Tray count grows. One summary when you return. Live Away / quiet count stay in the notice above when active."}
          </p>
          <div style={{ marginTop: "0.65rem" }}>
            <div style={{ fontWeight: 500, marginBottom: "0.35rem" }}>Snooze</div>
            <p className="muted" style={{ marginBottom: "0.35rem" }}>
              {snap.notify_snooze_active
                ? `Snoozed${
                    snap.notify_snooze_until
                      ? ` until ${new Date(snap.notify_snooze_until).toLocaleString()}`
                      : ""
                  }. Soft OS banners stay off until then. Clear below or see the notice at the top.`
                : "Temporarily quiet OS banners without changing How chatty. Continuity (what stays on) is in the notice above when snooze or Away is active."}
            </p>
            <div className="row-actions" style={{ gap: "0.4rem", flexWrap: "wrap" }}>
              <button
                type="button"
                className="btn"
                disabled={!!snap.notify_snooze_active}
                onClick={() =>
                  void api.setNotifySnooze("1h").then(reload).catch((err) => fail(err))
                }
              >
                1 hour
              </button>
              <button
                type="button"
                className="btn"
                disabled={!!snap.notify_snooze_active}
                onClick={() =>
                  void api
                    .setNotifySnooze("tomorrow")
                    .then(reload)
                    .catch((err) => fail(err))
                }
              >
                Until tomorrow morning (8am)
              </button>
              {snap.notify_snooze_active ? (
                <button
                  type="button"
                  className="btn primary"
                  onClick={() =>
                    void api
                      .setNotifySnooze("clear")
                      .then(reload)
                      .catch((err) => fail(err))
                  }
                >
                  Clear snooze
                </button>
              ) : null}
            </div>
          </div>
          <label style={{ display: "block", marginTop: "0.65rem" }}>
            <input
              type="checkbox"
              checked={snap.quiet_overnight !== false}
              onChange={(e) =>
                void api
                  .setQuietOvernight(e.target.checked)
                  .then(reload)
                  .catch((err) => fail(err))
              }
            />{" "}
            Quiet overnight
          </label>
          <p className="muted" style={{ marginTop: "0.25rem" }}>
            No sound at night (about 10pm–8am).
          </p>
          <label style={{ display: "block", marginTop: "0.5rem" }}>
            <input
              type="checkbox"
              checked={snap.sound_only_answer !== false}
              onChange={(e) =>
                void api
                  .setSoundOnlyAnswer(e.target.checked)
                  .then(reload)
                  .catch((err) => fail(err))
              }
            />{" "}
            Sound only when you must answer
          </label>
          <p className="muted" style={{ marginTop: "0.25rem" }}>
            Passive OS banners stay silent. Protect failed may still sound.
          </p>
            <label style={{ display: "block", marginTop: "0.5rem" }}>
              Protect block timeout (seconds){" "}
              <input
                type="number"
                min={5}
                max={120}
                value={decisionTimeoutDraft ?? (snap.decision_timeout_sec || 15)}
                onChange={(e) => setDecisionTimeoutDraft(Number(e.target.value) || 15)}
                onBlur={() => {
                  const v = decisionTimeoutDraft ?? (snap.decision_timeout_sec || 15);
                  setDecisionTimeoutDraft(null);
                  void api
                    .setDecisionTimeout(v)
                    .then(reload)
                    .catch((err) => fail(err));
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") (e.target as HTMLInputElement).blur();
                }}
              />
            </label>
            <p className="muted" style={{ marginTop: "0.25rem" }}>
              Countdown for Keep blocked / Allow this site. Agent Ask dialogs always use at least 30
              seconds.
            </p>
            <label style={{ display: "block", marginTop: "0.5rem" }}>
              Keep-repeat / re-ask interval (seconds){" "}
              <input
                type="number"
                min={15}
                max={3600}
                value={reaskDraft ?? (snap.reask_interval_sec || 60)}
                onChange={(e) => setReaskDraft(Number(e.target.value) || 60)}
                onBlur={() => {
                  const v = reaskDraft ?? (snap.reask_interval_sec || 60);
                  setReaskDraft(null);
                  void api
                    .setReaskInterval(v)
                    .then(reload)
                    .catch((err) => fail(err));
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") (e.target as HTMLInputElement).blur();
                }}
              />
            </label>
            <p className="muted" style={{ marginTop: "0.35rem" }}>
              How often to re-open a decision after Decide later / timeout. After Keep blocked,
              repeats stay in History (no OS remind). Agent Ask storms still use a fixed short
              window — pause Asks under Advanced if prompts pile up.
            </p>
 </section>
 )}

        {showSection(["autostart", "at login", "launch"], "autostart") && (
          <section className="card" id="settings-autostart">
            <h2>Autostart</h2>
            <label>
              <input
                type="checkbox"
                checked={!!snap.autostart}
                disabled={!snap.setup_done}
                onChange={(e) =>
                  void api
                    .setAutostart(e.target.checked)
                    .then(reload)
                    .catch((err) => fail(err))
                }
              />{" "}
              Launch DenyOut at login
            </label>
            {!snap.setup_done ? (
              <p className="muted" style={{ marginTop: "0.35rem" }}>
                Available after you finish the first-run choice.
              </p>
            ) : (
              <p className="muted" style={{ marginTop: "0.35rem" }}>
                If login launch was lost, DenyOut recreates it while this stays on.
              </p>
            )}
          </section>
        )}

 {showSection(
 [
 "threat",
 "phish",
 "malware",
 "urlhaus",
 "list",
 "block known",
 "refresh",
 "stronger",
 "hagezi",
 "poll",
 "hours",
 "exception",
 "exceptions",
 "product exception",
 ],
 "threat-lists",
 ) && (
 <section className="card" id="settings-threat-lists">
 <h2>Threat lists</h2>
          <p className="muted">
            {threats?.about_note ||
              "Block domains on known phishing and malware lists. Downloads stay on this computer."}{" "}
            DenyOut refreshes threat lists about every {(threats?.poll_hours || 24)} hours while it
            is running, and when Protect or Agents only starts.
            {computerLive && !snap.problems_alert ? (
              <>
                {" "}
                Changing lists or Refresh now while {computerLiveNoun} is on restarts protection (may
                ask for a password).
              </>
            ) : computerLive && snap.problems_alert ? (
              <>
                {" "}
                Changing lists or Refresh now may restart the computer proxy ({computerLiveNoun}{" "}
                needs attention; may ask for a password).
              </>
            ) : snap?.mode === "session" && snap?.protection_on ? (
              <> Lists update in place for Session — no system restart.</>
            ) : (snap?.agents_running || 0) > 0 ? (
              <> Updates also apply to running My agents wraps without turning on Protect computer.</>
            ) : intentAgents ? (
              <> Changes apply the next time Agents only or Protect turns on.</>
            ) : (
              <> Changes apply the next time Protect turns on.</>
            )}
          </p>
 {!threatsReady && (
 <p className="warn-box" style={{ marginTop: "0.5rem" }}>
 Couldn’t load threat lists yet. Use Retry load below — list choices stay hidden until that
 works (not shown as all off).
 {snap?.threat_lists_warn
 ? " The top bar still shows they need attention."
 : ""}
 </p>
 )}
 {snap?.threat_lists_warn && !threats?.needs_attention && (
 <p className="warn-box" style={{ marginTop: "0.5rem" }}>
 Threat lists need a refresh (same as Home / Problems). Use Refresh now when you can.
 </p>
 )}
 {threats?.needs_attention && (
 <p className="warn-box" style={{ marginTop: "0.5rem" }}>
 {threatListsNeverDownloaded(threats)
 ? "Threat lists are on but have not downloaded yet. Use Refresh now, or check your network."
 : "Threat lists look outdated (over a week). Use Refresh now, or check your network."}
 </p>
 )}
 {threatsReady && threats ? (
 <>
 <label style={{ display: "block", marginTop: "0.5rem" }}>
 <input
 type="checkbox"
 checked={!!threats.block_phishing}
 disabled={threatBusy}
 onChange={(e) => {
 const on = e.target.checked;
 setThreatBusy(true);
 void api
 .setBlockPhishing(on)
 .then(reload)
 .catch((err) => {
 fail(err);
 return reload();
 })
 .finally(() => setThreatBusy(false));
 }}
 />{" "}
 Block known phishing
 </label>
 <label style={{ display: "block", marginTop: "0.35rem" }}>
 <input
 type="checkbox"
 checked={!!threats.block_malware}
 disabled={threatBusy}
 onChange={(e) => {
 const on = e.target.checked;
 setThreatBusy(true);
 void api
 .setBlockMalware(on)
 .then(reload)
 .catch((err) => {
 fail(err);
 return reload();
 })
 .finally(() => setThreatBusy(false));
 }}
 />{" "}
 Block known malware
 </label>
 <label
 style={{
 display: "block",
 marginTop: "0.25rem",
 marginLeft: "1.25rem",
 }}
 >
 <input
 type="checkbox"
 checked={!!threats.block_stronger}
 disabled={threatBusy || !threats.block_malware}
 title={
 !threats.block_malware
 ? "Turn on Block known malware first"
 : undefined
 }
 onChange={(e) => {
 const on = e.target.checked;
 const apply = async () => {
 setThreatBusy(true);
 try {
 await api.setBlockStronger(on);
 await reload();
 } catch (err) {
 fail(err);
 await reload();
 } finally {
 setThreatBusy(false);
 }
 };
 if (on) {
 setExtraConfirm({
 title: "Enable stronger threat list?",
 body:
 threats.stronger_warning ||
 "Stronger adds a large extra list and may break sites. Continue?",
 danger: true,
 confirmLabel: "Enable",
 run: apply,
 });
 return;
 }
 void apply();
 }}
 />{" "}
 Including stronger threat list
 </label>
 <p className="muted" style={{ marginLeft: "1.25rem", marginTop: "0.15rem" }}>
 Optional HaGeZi list - larger, may block more. Use Allow if something breaks.
 {!threats.block_malware
 ? " Turn on Block known malware first to enable this."
 : ""}
 </p>
              <label style={{ display: "block", marginTop: "0.65rem" }}>
                Update every (hours){" "}
                <input
                  type="number"
                  min={6}
                  max={168}
                  value={pollHoursDraft ?? (threats.poll_hours || 24)}
                  disabled={threatBusy}
                  onChange={(e) => setPollHoursDraft(Number(e.target.value) || 24)}
                  onBlur={() => {
                    const h = pollHoursDraft ?? (threats.poll_hours || 24);
                    setPollHoursDraft(null);
                    setThreatBusy(true);
                    void api
                      .setThreatPollHours(h)
                      .then(reload)
                      .catch((err) => fail(err))
                      .finally(() => setThreatBusy(false));
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") (e.target as HTMLInputElement).blur();
                  }}
                />
              </label>
 </>
 ) : null}
 <div className="row-actions" style={{ marginTop: "0.65rem" }}>
 <button
 type="button"
 className="btn"
 disabled={threatBusy}
 onClick={() => {
 setThreatBusy(true);
 const run = !threatsReady
  ? reloadThreats()
  : api.refreshThreatLists().then(async (t) => {
     setThreats(t);
     await reload();
    });
 void run
  .catch(async (err) => {
   fail(err);
   try {
    await reloadThreats();
   } catch {
    /* still unavailable */
   }
  })
  .finally(() => setThreatBusy(false));
 }}
 >
 {threatBusy ? "Working..." : !threatsReady ? "Retry load" : "Refresh now"}
 </button>
 </div>
 {!threatsReady ? (
 <p className="muted" style={{ marginTop: "0.5rem" }}>
 Couldn’t load threat lists. Protect still works for secrets.
 </p>
 ) : ((threats && threats.feeds) || []).length > 0 ? (
 <ul style={{ marginTop: "0.75rem" }}>
 {threats!.feeds.map((f) => (
 <li key={f.id} className="muted" style={{ marginBottom: "0.35rem" }}>
 <span className="mono">{f.label}</span>
 {": "}
 {f.enabled
                   ? f.active
                     ? "on"
                     : f.last_error
                       ? "download failed"
                       : "waiting for first download"
                   : "off"}
 {f.entry_count > 0 ? ` - ${f.entry_count} domains` : ""}
 {f.last_success ? ` - updated ${f.last_success}` : ""}
 {f.last_error ? ` - ${f.last_error}` : ""}
 {f.homepage ? (
 <>
 {" - "}
 <a href={f.homepage} target="_blank" rel="noreferrer">
 about
 </a>
 </>
 ) : null}
 </li>
 ))}
 </ul>
 ) : null}
 <h3 className="settings-subhead">
 Product exceptions ({threats?.product_exceptions ?? 0})
 </h3>
 <p className="muted">
 {threats?.product_exceptions_note ||
 "Built-in hosts that threat lists must not block. Read-only."}
 </p>
 {(threats?.product_exception_hosts || []).length > 0 && (
 <details style={{ marginTop: "0.35rem" }}>
 <summary className="muted">Show list</summary>
 <ul className="mono muted" style={{ marginTop: "0.35rem" }}>
 {threats!.product_exception_hosts.map((h) => (
 <li key={h}>{h}</li>
 ))}
 </ul>
 </details>
 )}
 </section>
 )}
 </>
 ) : (
 <>
 {tipsEnabled && (
 <Tip
 id="settings-advanced"
 dismissed={tipGone(dismissed, "settings-advanced")}
 onDismiss={onChanged}
 >
 Advanced: system banners (including Detailed), allowed/silenced sites, optional lists,
 Asks, diagnostics, account, and whole-PC Agents only. Allowed/silenced hosts are the
 permanent allow controls — other cards here are prefs and tools.
 </Tip>
 )}

 {showSection(
 [
 "notification",
 "notify",
 "banner",
 "banners",
 "detailed",
 "fullscreen",
 "games",
 "silent",
 "system banners",
 "level",
 ],
 "system-banners",
 ) && (
 <section className="card" id="settings-system-banners">
 <h2>System banners</h2>
 <p className="muted">
 How DenyOut may talk through the operating system. Decisions stay inside DenyOut.
 The OS may show Open DenyOut, Undo, status, or Protect failed.
 </p>
 <label style={{ display: "block" }}>
 <input
 type="checkbox"
 checked={snap.system_banners !== false}
 onChange={(e) =>
 void api
 .setSystemBanners(e.target.checked)
 .then(reload)
 .catch((err) => fail(err))
 }
 />{" "}
 Allow system banners
 </label>
 <p className="muted" style={{ marginTop: "0.25rem" }}>
 When off, only Protect failed can still appear so a broken Protect is not silent.
 </p>
 <label style={{ display: "block", marginTop: "0.65rem" }}>
 Level{" "}
 <select
 value={
 snap.notify_level === "quiet"
 ? "quiet"
 : snap.notify_level === "detailed"
 ? "detailed"
 : "normal"
 }
 onChange={(e) =>
 void api
 .setNotifyLevel(e.target.value)
 .then(reload)
 .catch((err) => fail(err))
 }
 >
 <option value="quiet">Quiet</option>
 <option value="normal">A bit more (Normal)</option>
 <option value="detailed">Detailed</option>
 </select>
 </label>
 <p className="muted" style={{ marginTop: "0.25rem" }}>
 Detailed today matches A bit more for which OS banner kinds appear. Quiet still
 limits to Protect failed.
 </p>
 <label style={{ display: "block", marginTop: "0.65rem" }}>
 <input
 type="checkbox"
 checked={snap.respect_fullscreen !== false}
 onChange={(e) =>
 void api
 .setRespectFullscreen(e.target.checked)
 .then(reload)
 .catch((err) => fail(err))
 }
 />{" "}
 Respect fullscreen / games
 </label>
 <p className="muted" style={{ marginTop: "0.25rem" }}>
 Avoid Ask/block dialogs, soft OS banners, and steal-focus while a fullscreen app is in front.
 </p>
 <label style={{ display: "block", marginTop: "0.5rem" }}>
 <input
 type="checkbox"
 checked={snap.silent_when_open !== false}
 onChange={(e) =>
 void api
 .setSilentWhenOpen(e.target.checked)
 .then(reload)
 .catch((err) => fail(err))
 }
 />{" "}
 If DenyOut is focused, stay silent in the system
 </label>
 <p className="muted" style={{ marginTop: "0.25rem" }}>
 Soft OS banners stay off while DenyOut is in front (focused and visible). An open
 but background window does not count as focused.
 </p>
 <p className="muted" style={{ marginTop: "0.65rem" }}>
 <strong style={{ fontWeight: 500, color: "inherit" }}>
 Decisions only inside DenyOut
 </strong>{" "}
 — always on. Allow / Keep / timed choices are in-app. The OS may still show Open /
 Undo / status / Protect failed.
 </p>
 <p className="muted" style={{ marginTop: "0.35rem" }}>
 How long banners live: Protect failed stays · soft Open short (~12s) · status
 quick · Undo ~10s once.
 </p>
 </section>
 )}

 {showSection(["account", "sign", "sign in", "sync", "email"], "account") && (
 <section className="card" id="settings-account">
 <h2>Account</h2>
 <p className="muted">
 {snap.account_trust_line ||
 "Sign in to sync settings across computers. DenyOut works fully without an account."}
 </p>
 {snap.account_signed_in ? (
 <>
 <p>
 Signed in as <strong className="mono">{snap.account_email}</strong>
 </p>
 <label className="row-actions" style={{ gap: "0.5rem", alignItems: "center" }}>
 <input
 type="checkbox"
 checked={!!snap.sync_enabled}
 onChange={(e) =>
 void api
 .setSyncEnabled(e.target.checked)
 .then(reload)
 .catch((err) => fail(err))
 }
 />
 <span>Sync settings when signed in</span>
 </label>
 <div className="row-actions">
 <button
 className="btn primary"
 onClick={() =>
 void api
 .syncNow()
 .then((r) => {
 note(r.message);
 return reload();
 })
 .catch((e) => fail(e))
 }
 >
 Sync now
 </button>
 <button
 className="btn"
 onClick={() => void api.signOut().then(reload).catch((e) => fail(e))}
 >
 Sign out
 </button>
 <button
 className="btn danger"
 onClick={() =>
 setExtraConfirm({
 title: "Delete cloud data?",
 body: "Delete your DenyOut cloud account and synced settings? Local Protect settings stay on this computer.",
 danger: true,
 confirmLabel: "Delete cloud data",
 run: async () => {
 await api.deleteCloudData();
 note("Cloud account deleted. Local settings unchanged.");
 await reload();
 },
 })
 }
 >
 Delete cloud data
 </button>
 </div>
 <details style={{ marginTop: "0.75rem" }}>
 <summary className="muted">API server (advanced)</summary>
 <input
 placeholder="https://api.denyout.com"
 value={apiBase}
 onChange={(e) => setApiBase(e.target.value)}
 style={{ marginTop: "0.5rem", width: "100%" }}
 />
 <button
 className="btn"
 style={{ marginTop: "0.35rem" }}
 onClick={() =>
 void api
 .setAccountAPIBase(apiBase)
 .then(() => note("API base saved."))
 .catch((e) => fail(e))
 }
 >
 Save API base
 </button>
 </details>
 </>
 ) : (
 <>
 <p className="muted">Protect does not need an account.</p>
 <div className="stack" style={{ gap: "0.5rem", maxWidth: "28rem" }}>
 <input
 placeholder="Email"
 value={acctEmail}
 onChange={(e) => setAcctEmail(e.target.value)}
 autoComplete="email"
 />
 <div className="row-actions">
 <button
 className="btn"
 onClick={() =>
 void api
 .requestMagicLink(acctEmail)
 .then(() =>
 note(
 "If the API is reachable, check email (or API logs in local stub) for a one-time code.",
 ),
 )
 .catch((e) => fail(e))
 }
 >
 Email me a code
 </button>
 </div>
 <input
 placeholder="One-time code"
 value={acctCode}
 onChange={(e) => setAcctCode(e.target.value)}
 autoComplete="one-time-code"
 />
 <div className="row-actions">
 <button
 className="btn primary"
 onClick={() =>
 void api
 .verifyMagicLink(acctEmail, acctCode)
 .then(() => {
 setAcctCode("");
 note("Signed in.");
 return reload();
 })
 .catch((e) => fail(e))
 }
 >
 Sign in
 </button>
 </div>
 <details>
 <summary className="muted">API server (advanced)</summary>
 <input
 placeholder="https://api.denyout.com"
 value={apiBase}
 onChange={(e) => setApiBase(e.target.value)}
 style={{ marginTop: "0.5rem", width: "100%" }}
 />
 <button
 className="btn"
 style={{ marginTop: "0.35rem" }}
 onClick={() =>
 void api
 .setAccountAPIBase(apiBase)
 .then(() => note("API base saved."))
 .catch((e) => fail(e))
 }
 >
 Save API base
 </button>
 </details>
 </div>
 </>
 )}
 </section>
 )}

 {showSection(
 [
 "always allow",
 "always-allow",
 "host",
 "keep",
 "remembered",
 "silenced",
 "sites",
 "allowed",
 "timed",
 "temporary",
 "while",
 "undo",
 ],
 "always-allow",
 ) && (
 <section className="card" id="settings-always-allow">
 <h2 id="settings-keeps">Sites I've allowed or silenced</h2>
 <p className="muted">
 Allowed sites skip blocks. Silenced entries stay quiet after you chose Keep blocked.
 {computerLive
  ? ` Adding or removing while ${computerLiveNoun} is on restarts protection (may ask for a password).`
  : ""}
 </p>
 <div className="toolbar">
 <input
 placeholder="Filter hosts..."
 value={filter}
 onChange={(e) => setFilter(e.target.value)}
 />
 <button
 className="btn"
                  onClick={() => {
                    const run = () =>
                      api
                        .undoLastAlways()
                        .then((m) => {
                          note(m || "Undid last allow.");
                          return reload();
                        });
                    if (computerLive) {
                      setExtraConfirm({
                        title: "Undo last allow?",
                        body: `Removing the last allow while ${computerLiveNoun} is on restarts protection (may ask for a password).`,
                        confirmLabel: "Undo and restart",
                        run,
                      });
                      return;
                    }
                    void run().catch((e) => fail(e));
                  }}
                >
                  Undo last allow
                </button>
 </div>

 <h3 className="settings-subhead">Allowed</h3>
 {allows.length === 0 ? (
 <p className="muted">None yet. Allow from History after a block, or add a host below.</p>
 ) : (
 <ul>
 {allows.map((h) => (
 <li key={h} className="row-actions" style={{ marginBottom: "0.35rem" }}>
 <span className="mono">{h}</span>
 <button
 className="btn danger"
 onClick={() => {
  const run = () => api.removeAlways(h).then(reload);
  if (computerLive) {
   setExtraConfirm({
    title: `Remove allow for ${h}?`,
    body: `Removing this allow while ${computerLiveNoun} is on restarts protection (may ask for a password).`,
    confirmLabel: "Remove and restart",
    run,
   });
   return;
  }
  void run().catch((e) => fail(e));
 }}
 >
 Remove
 </button>
 </li>
 ))}
 </ul>
 )}
 <div className="row-actions" style={{ marginTop: "0.5rem" }}>
 <input
 placeholder="Add host (example.com)"
 value={addAllowHost}
 onChange={(e) => setAddAllowHost(e.target.value)}
 style={{ flex: 1 }}
 onKeyDown={(e) => {
 if (e.key !== "Enter") return;
 e.preventDefault();
 const h = addAllowHost.trim().toLowerCase();
 if (!h) return;
 const run = () =>
  api.alwaysAllow(h, "").then(() => {
   setAddAllowHost("");
   note("Allowed " + h);
   return reload();
  });
 if (computerLive) {
  setExtraConfirm({
   title: `Allow ${h}?`,
   body: `Adding this allow while ${computerLiveNoun} is on restarts protection (may ask for a password).`,
   confirmLabel: "Add and restart",
   run,
  });
  return;
 }
 void run().catch((err) => fail(err));
 }}
 />
 <button
 className="btn"
 type="button"
 onClick={() => {
 const h = addAllowHost.trim().toLowerCase();
 if (!h) return;
 const run = () =>
  api.alwaysAllow(h, "").then(() => {
   setAddAllowHost("");
   note("Allowed " + h);
   return reload();
  });
 if (computerLive) {
  setExtraConfirm({
   title: `Allow ${h}?`,
   body: `Adding this allow while ${computerLiveNoun} is on restarts protection (may ask for a password).`,
   confirmLabel: "Add and restart",
   run,
  });
  return;
 }
 void run().catch((e) => fail(e));
 }}
 >
 Add
 </button>
 </div>

 <h3 className="settings-subhead">Allowed for a while</h3>
 {(snap.timed_allows || []).length === 0 ? (
 <p className="muted">None.</p>
 ) : (
 <ul>
 {snap.timed_allows
 .filter((t) => !filter || t.host.toLowerCase().includes(filter.toLowerCase()))
 .map((t) => (
                  <li key={t.host + t.expires_at} className="row-actions" style={{ marginBottom: "0.35rem" }}>
                    <span className="mono">
                      {t.host}{" "}
                      <span className="muted">until {formatExpiry(t.expires_at)}</span>
                    </span>
                    <button
                      className="btn"
                      onClick={() => {
                        const host = t.host;
                        if (computerLive) {
                          setExtraConfirm({
                            title: `Undo timed allow for ${host}?`,
                            body: `Removing this timed allow while ${computerLiveNoun} is on restarts protection (may ask for a password).`,
                            confirmLabel: "Undo and restart",
                            run: () => api.removeTimedAllow(host).then(() => reload()),
                          });
                          return;
                        }
                        void api.removeTimedAllow(host).then(reload).catch((e) => fail(e));
                      }}
                    >
                      Undo
                    </button>
                  </li>
 ))}
 </ul>
 )}

 <h3 className="settings-subhead">Blocked for a while</h3>
 {(snap.timed_denies || []).length === 0 ? (
 <p className="muted">None.</p>
 ) : (
 <ul>
 {snap.timed_denies
 .filter((t) => !filter || t.host.toLowerCase().includes(filter.toLowerCase()))
 .map((t) => (
 <li
 key={t.host + (t.reason || "") + t.expires_at}
 className="row-actions"
 style={{ marginBottom: "0.35rem" }}
 >
                    <span className="mono">
                      {t.host}
                      {t.reason ? (
                        <span className="muted"> — {humanKeepReason(t.reason)}</span>
                      ) : null}{" "}
                      <span className="muted">until {formatExpiry(t.expires_at)}</span>
                    </span>
 <button
 className="btn"
 onClick={() =>
 void api
 .removeTimedDeny(t.host, t.reason || "")
 .then(reload)
 .catch((e) => fail(e))
 }
 >
 Undo
 </button>
 </li>
 ))}
 </ul>
 )}

 <h3 className="settings-subhead">Silenced (Keep blocked)</h3>
 {(snap.remembered_keeps || []).length === 0 ? (
 <p className="muted">None.</p>
 ) : (
 <>
 <ul>
                {snap.remembered_keeps
                  .filter((k) => !filter || k.toLowerCase().includes(filter.toLowerCase()))
                  .map((k) => {
                    const [host, reason] = splitKeepKey(k);
                    return (
                      <li key={k} className="row-actions" style={{ marginBottom: "0.35rem" }}>
                        <span className="mono">
                          {host}
                          {reason ? (
                            <span className="muted"> — {humanKeepReason(reason)}</span>
                          ) : null}
                        </span>
                        <button
                          className="btn"
                          onClick={() =>
                            void api.forgetKeep(k, "").then(reload).catch((e) => fail(e))
                          }
                        >
                          Clear
                        </button>
                      </li>
                    );
                  })}
 </ul>
 <button
 className="btn danger"
 onClick={() => void api.clearKeeps().then(reload).catch((e) => fail(e))}
 >
 Clear all silenced
 </button>
 </>
 )}
 </section>
 )}

 {showSection(
 [
 "oisd",
 "steven",
 "ads",
 "tracker",
 "advanced list",
 "advanced lists",
 "optional list",
 "optional",
 ],
 "advanced-lists",
 ) && (
 <section className="card" id="settings-advanced-lists">
 <h2>Optional lists (not core)</h2>
 <p className="muted">
 {threats?.advanced_warning ||
 "Broader ad/tracker lists - not DenyOut's main job. Default off."}
 {computerLive
  ? ` Changing these while ${computerLiveNoun} is on restarts protection (may ask for a password).`
  : ""}
 </p>
 {!threatsReady ? (
 <p className="muted">Unavailable until threat lists load.</p>
 ) : (threats?.advanced_feeds || []).length === 0 ? (
 <p className="muted">Unavailable.</p>
 ) : (
 <ul style={{ listStyle: "none", padding: 0 }}>
 {threats!.advanced_feeds.map((f) => (
 <li key={f.id} style={{ marginBottom: "0.5rem" }}>
 <label>
 <input
 type="checkbox"
 checked={!!f.enabled}
 disabled={threatBusy || !threatsReady}
 onChange={(e) => {
 const on = e.target.checked;
 const feedID = f.id;
 const apply = async () => {
 setThreatBusy(true);
 try {
 await api.setAdvancedThreatFeed(feedID, on);
 await reload();
 } catch (err) {
 fail(err);
 await reload();
 } finally {
 setThreatBusy(false);
 }
 };
 if (on) {
 setExtraConfirm({
 title: `Enable ${f.label}?`,
 body:
 (threats?.advanced_warning ||
 "Broader list may break sites. Continue?") +
 (computerLive
  ? ` While ${computerLiveNoun} is on this restarts protection (may ask for a password).`
  : ""),
 danger: true,
 confirmLabel: "Enable",
 run: apply,
 });
 return;
 }
 if (computerLive) {
 setExtraConfirm({
 title: `Disable ${f.label}?`,
 body: `Turning this off while ${computerLiveNoun} is on restarts protection (may ask for a password).`,
 confirmLabel: "Disable and restart",
 run: apply,
 });
 return;
 }
 void apply();
 }}
 />{" "}
 {f.label}
 </label>
 <div className="muted" style={{ marginLeft: "1.25rem", fontSize: "0.92em" }}>
 {f.enabled
 ? f.active
 ? `on - ${f.entry_count} domains`
 : f.last_error
   ? "download failed"
   : "waiting for first download"
 : "off"}
 {f.last_error ? ` - ${f.last_error}` : ""}
 </div>
 </li>
 ))}
 </ul>
 )}
 </section>
 )}

 {showSection(
 ["agents only", "allowlist", "whole", "wrap", "agent"],
 "agents-only",
 ) && (
 <section
 className={snap.mode === "agents" ? "card agents-card" : "card"}
 id="settings-agents-only"
 >
 <h2>Agents only (whole PC)</h2>
 {snap.mode === "agents" ? (
 <>
 <p>
 Currently on: whole-PC Agents only. Everyday browsing is not protected like Protect
 computer.
 </p>
 <div className="row-actions">
 {snap.problems_alert ? (
 <button
 className="btn primary"
 onClick={() =>
 setProtectConfirm({
 title: "Turn on Agents only?",
 body: agentsConfirmBody,
 action: "retry",
 })
 }
 >
 Try Agents only again
 </button>
 ) : null}
 <button
 className="btn primary"
 onClick={() =>
 setProtectConfirm({
 title: "Switch to Protect computer?",
 body:
 snap.protect_confirm_body ||
 "Your system may ask for a password so DenyOut can set network rules. Continue?",
 action: "switch",
 })
 }
 >
 Switch to Protect computer
 </button>
 <button
 className="btn danger"
 disabled={pauseBlocked}
 title={
  pauseBlocked
   ? "Finish the open Ask/block or tray pause first."
   : undefined
 }
 onClick={() => setPauseOpen(true)}
 >
 Pause / turn off…
 </button>
 {pauseBlocked ? (
  <p className="muted" style={{ marginTop: "0.35rem", width: "100%" }}>
   Pause is busy — finish the open Ask/block or tray pause first.
  </p>
 ) : null}
 </div>
 </>
 ) : intentAgents ? (
 <>
 <p>
 Last mode was Agents only (whole PC). Everyday browsing stays unprotected.
 Turn it on again here — same as Home / Basic — without redoing the first-enable
 warning. Running My agents wraps keep running on retry.
 </p>
 <div className="row-actions">
 <button
  className="btn primary"
  onClick={() =>
   setProtectConfirm({
    title: "Turn on Agents only?",
    body: agentsConfirmBody,
    action: "retry",
   })
  }
 >
  Turn on Agents only
 </button>
 {canChangePause ? (
  <button
   className="btn"
   disabled={pauseBlocked}
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
 </div>
 </>
 ) : (
 <>
 <p>
 Almost nobody needs this. It puts the entire computer on an allowlist - messengers
 and many sites may stop working. Prefer My agents for AI tools. Enabling stops
 any running My agents wraps.
 </p>
 <button className="btn danger" onClick={enableAgentsOnly}>
 Enable Agents only (whole PC)...
 </button>
 </>
 )}
 </section>
 )}

        {showSection(["ask", "resume"], "asks") && (
          <section className="card" id="settings-asks">
            <h2>Asks</h2>
            <p className="muted">
              For My agents / Agents only: pause new-host Ask dialogs for 15 minutes when prompts
              pile up. New sites stay blocked until the pause ends or you resume.
            </p>
            {snap.mode !== "agents" &&
            !intentAgents &&
            (snap.agents_running || 0) === 0 &&
            !snap.ask_paused ? (
              <p className="muted" style={{ marginBottom: "0.5rem" }}>
                No agent asks right now — this applies when My agents or Agents only is in use.
                Pause stays available here once an agent is running.
              </p>
            ) : null}
            {snap.ask_paused ? (
              <p className="muted" style={{ marginBottom: "0.5rem" }}>
                {(snap.ask_paused_until || "").trim()
                  ? `Paused until ${formatExpiry(snap.ask_paused_until || "")}.`
                  : "Asks are paused. New sites stay blocked until you resume."}
              </p>
            ) : null}
            <div className="row-actions">
              <button
                className="btn"
                disabled={
                  !!snap.ask_paused ||
                  (snap.mode !== "agents" &&
                    !intentAgents &&
                    (snap.agents_running || 0) === 0)
                }
                onClick={() =>
                  void api
                    .pauseAsks()
                    .then((m) => {
                      note(m || "Asks paused.");
                      return reload();
                    })
                    .catch((e) => fail(e))
                }
              >
                Pause asks (15 min)
              </button>
              <button
                className="btn"
                disabled={!snap.ask_paused}
                onClick={() =>
                  void api
                    .resumeAsks()
                    .then((m) => {
                      note(m || "Asks resumed.");
                      return reload();
                    })
                    .catch((e) => fail(e))
                }
              >
                Resume asks
              </button>
            </div>
          </section>
        )}

 {showSection(
 [
 "diagn",
 "log",
 "logs",
 "audit",
 "test",
 "version",
 "update",
 "reset",
 "privacy",
 "helper",
 "password",
 ],
 "diagnostics",
 ) && (
 <section className="card" id="settings-diagnostics">
 <h2>Diagnostics</h2>
 <p className="mono muted">Version {snap.version || "dev"}</p>
 <p className="mono muted">Logs: {snap.log_dir}</p>
 <p className="mono muted">Audit: {snap.audit_path}</p>
 <p className="muted">
 Helper:{" "}
 <strong>{snap.helper_ok ? "installed" : "not installed"}</strong>
 {snap.helper_ok
 ? " — Protect usually skips the password prompt."
 : " — Protect may ask for your password on turn-on."}
 </p>
 <p className="muted" style={{ marginTop: "0.35rem" }}>
 Certificate and clipboard status live on Problems, not here.
 </p>
 <div className="row-actions">
 <button
 className="btn"
 onClick={() => void api.openLogs().catch((e) => fail(e))}
 >
 Open diagnostics folder
 </button>
 <button
 className="btn"
            onClick={() =>
              void api
                .testProtection()
                .then((m) => {
                  const t = m || "Checked.";
                  // Backend returns a plain string for unhealthy — style as warning.
                  if (/did not stay on|did not start correctly/i.test(t)) fail(t);
                  else note(t);
                })
                .catch((e) => fail(e))
            }
          >
            Test protection...
          </button>
 <button
 className="btn"
 onClick={() =>
 void api
 .checkForUpdates()
 .then((v) => {
 note(v.message);
 return reload();
 })
 .catch((e) => fail(e))
 }
 >
 Check for updates
 </button>
 {snap.update_available && snap.update_url ? (
 <button
 className="btn primary"
 onClick={() => void api.openUpdateURL().catch((e) => fail(e))}
 >
 Open update {snap.update_version || ""}
 </button>
 ) : null}
 </div>
 <p className="muted" style={{ marginTop: "0.75rem" }}>
 Update checks use a public version file - no sign-in. Protect still works if the check
 fails.
 </p>
 <div className="row-actions" style={{ marginTop: "1rem" }}>
 <button className="btn danger" onClick={() => setResetConfirm(true)}>
 Reset setup…
 </button>
 </div>
 <p className="muted" style={{ marginTop: "0.75rem" }}>
 Privacy: block History stays on this computer. If you sign in, sync can copy
 allowed/silenced sites and preferences — not your full block History.
 </p>
 </section>
 )}
 </>
 )}
 {protectConfirm ? (
 <ConfirmModal
 title={protectConfirm.title}
 body={protectConfirm.body}
 busy={protectBusy}
 error={err}
 onCancel={() => setProtectConfirm(null)}
 danger={protectConfirm.action === "agents"}
 confirmLabel={protectConfirm.action === "agents" ? "Enable Agents only" : "Continue"}
 onConfirm={() => {
 setProtectBusy(true);
 setErr("");
 const action = protectConfirm.action;
 void (action === "switch"
 ? api.switchSafe()
 : action === "retry"
 ? api.retryProtect()
 : action === "agents"
 ? api.enableAgents()
 : api.enableSafe())
 .then(() => {
 setProtectConfirm(null);
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
 mode={snap?.mode}
 intentAgents={intentAgents}
 alreadyOff={canChangePause}
 brokenIntent={brokenIntent}
 error={err}
 onCancel={() => setPauseOpen(false)}
 onChoose={(c) => void confirmPause(c)}
 />
 ) : null}
 {resetConfirm ? (
 <ConfirmModal
 title="Reset setup?"
 body="DenyOut will ask how to protect this computer again. Protection will turn off."
 busy={resetBusy}
 error={err}
 danger
 confirmLabel="Reset setup"
 onCancel={() => setResetConfirm(false)}
 onConfirm={() => {
 setResetBusy(true);
 setErr("");
 void api
 .resetSetup()
 .then(() => {
 setResetConfirm(false);
 return reload();
 })
 .catch((e) => fail(e))
 .finally(() => setResetBusy(false));
 }}
 />
 ) : null}
 {extraConfirm ? (
 <ConfirmModal
 title={extraConfirm.title}
 body={extraConfirm.body}
 busy={extraBusy}
 error={err}
 danger={extraConfirm.danger}
 confirmLabel={extraConfirm.confirmLabel || "Continue"}
 onCancel={() => setExtraConfirm(null)}
 onConfirm={() => {
 setExtraBusy(true);
 setErr("");
 void extraConfirm
 .run()
 .then(() => setExtraConfirm(null))
 .catch((e) => fail(e))
 .finally(() => setExtraBusy(false));
 }}
 />
 ) : null}
 </div>
 );
}

function threatListsNeverDownloaded(t: ThreatListsView): boolean {
  const rows = [...(t.feeds || []), ...(t.advanced_feeds || [])].filter((f) => f.enabled);
  if (rows.length === 0) return false;
  return rows.every((f) => !f.active && !f.last_success);
}

function formatExpiry(iso: string): string {
  const t = Date.parse(iso || "");
  if (Number.isNaN(t)) return iso || "";
  const d = new Date(t);
  const now = new Date();
  // Match chrome/tray/Home: time-only today; include day across midnight.
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function splitKeepKey(k: string): [string, string] {
  const i = (k || "").indexOf("|");
  if (i < 0) return [k || "", ""];
  return [k.slice(0, i), k.slice(i + 1)];
}

function humanKeepReason(code: string): string {
  switch (code) {
    case "secret_in_url":
      return "secret in link";
    case "secret_in_header":
      return "secret in header";
    case "secret_in_body":
      return "secret in body";
    case "canary_detected":
      return "canary";
    case "threat_list":
      return "threat list";
    case "host_denied":
      return "host denied";
    case "unsafe_ip":
      return "unsafe IP";
    case "ip_literal":
      return "raw IP";
    case "host_not_allowed":
      return "not on allowlist";
    default:
      return code || "blocked";
  }
}

/** Honest continuity line for snooze / away copy (not always “Protect computer”). */
function protectionContinuityNow(snap: UISnapshot): string {
  if (snap.mode === "safe" && snap.protection_on) return "Protect computer stays on.";
  if (snap.mode === "agents") return "Agents only stays on.";
  if (snap.mode === "session") return "Session protection stays on.";
  if ((snap.agents_running || 0) > 0) return "My agents keep running.";
  return "Snooze and Away do not turn protection off by themselves.";
}
