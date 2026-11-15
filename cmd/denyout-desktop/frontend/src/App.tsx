import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AwayDigestModal } from "./components/AwayDigestModal";
import { confirmModalOpen } from "./components/ConfirmModal";
import { DecisionModal, DecisionPayload } from "./components/DecisionModal";
import { PauseModal } from "./components/PauseModal";
import { Tip, tipGone } from "./components/Tip";
import { Activity } from "./pages/Activity";
import { Home } from "./pages/Home";
import { Problems } from "./pages/Problems";
import { Profiles, profileEditOpen } from "./pages/Profiles";
import { Settings } from "./pages/Settings";
import { api, UISnapshot } from "./wails";

type Route = "home" | "activity" | "profiles" | "settings" | "problems";

export default function App() {
 const [route, setRoute] = useState<Route>("home");
 const [snap, setSnap] = useState<UISnapshot | null>(null);
 const [showSetup, setShowSetup] = useState(false);
 /** Peek Problems/Settings during first-run without losing the setup choice. */
 const [deferOnboarding, setDeferOnboarding] = useState(false);
 const [showProtectConfirm, setShowProtectConfirm] = useState(false);
 const [onboardBusy, setOnboardBusy] = useState(false);
 const [onboardMsg, setOnboardMsg] = useState("");
 /** false = success/notice (notice-box); true = failure (warn-box). */
 const [onboardMsgWarn, setOnboardMsgWarn] = useState(false);
 /** First-run chatty choice on the same mode screen (Quiet recommended). */
 const [onboardChatty, setOnboardChatty] = useState<"quiet" | "normal">("quiet");
 function setOnboardToast(msg: string, warn = true) {
 setOnboardMsg(msg);
 setOnboardMsgWarn(!!msg && warn);
 }
 async function applyOnboardChatty() {
 await api.setNotifyLevel(onboardChatty);
 }
 const [openNewProfile, setOpenNewProfile] = useState(false);
 /** Keep Profiles mounted after first visit so New/Edit drafts survive nav. */
 const [profilesEver, setProfilesEver] = useState(false);
 useEffect(() => {
 if (route === "profiles") setProfilesEver(true);
 }, [route]);
 /** After Protect AI agents: Your setup must not yank the user off My agents. */
 const [afterAgentsSetup, setAfterAgentsSetup] = useState(false);
 const [jumpOpen, setJumpOpen] = useState(false);
 const [jumpQ, setJumpQ] = useState("");
 const [settingsTab, setSettingsTab] = useState<"basic" | "advanced">("basic");
 const [settingsFocus, setSettingsFocus] = useState<string | undefined>();
 /** Bumps so Settings re-applies tab/Find/scroll even when focus id is unchanged. */
 const [settingsFocusNonce, setSettingsFocusNonce] = useState(0);
 const [decision, setDecision] = useState<DecisionPayload | null>(null);
 /** Synced on event + resolve — not only on render (Quit race vs Ask). */
 const decisionRef = useRef<DecisionPayload | null>(null);
 const [decisionErr, setDecisionErr] = useState("");
 const [trayPauseOpen, setTrayPauseOpen] = useState(false);
 const trayPauseOpenRef = useRef(false);
 trayPauseOpenRef.current = trayPauseOpen;
 /** Page PauseModal open (Home/Settings/Problems) — Decision must toast if it buries it. */
 const pagePauseOpenRef = useRef(false);
 /** Soft toast after Ask if Decision auto-closed Pause. */
 const buriedPauseToastRef = useRef(false);
 /** Bump to ask the active page to close its PauseModal (Esc). */
 const [pagePauseCloseReq, setPagePauseCloseReq] = useState(0);
 const [trayPauseBusy, setTrayPauseBusy] = useState(false);
 const [trayPauseMsg, setTrayPauseMsg] = useState("");
 /** true = API/Pause failure (warn-box); false = soft info like "Finish the block prompt". */
 const [trayPauseMsgWarn, setTrayPauseMsgWarn] = useState(false);
 const [trayEnablePending, setTrayEnablePending] = useState(false);
 function setTrayToast(msg: string, warn = false) {
 setTrayPauseMsg(msg);
 setTrayPauseMsgWarn(!!msg && warn);
 }
 const [trayProtectConfirm, setTrayProtectConfirm] = useState(false);
 const [trayProtectBusy, setTrayProtectBusy] = useState(false);
 const [quitOpen, setQuitOpen] = useState(false);
 const [quitBusy, setQuitBusy] = useState(false);
 const [quitMsg, setQuitMsg] = useState("");
 const [migrateBusy, setMigrateBusy] = useState(false);
 /** Hide unhealthy Your setup banner without MarkYourSetupShown (tip returns after alert clears). */
 const [hideSetupAlertBanner, setHideSetupAlertBanner] = useState(false);
 /** Esc hides Your setup for this session only — Got it still persists via MarkYourSetupShown. */
 const [deferYourSetup, setDeferYourSetup] = useState(false);
 const deferYourSetupRef = useRef(false);
 deferYourSetupRef.current = deferYourSetup;

 async function refreshSnap() {
 try {
 const s = await api.snapshot();
 setSnap(s);
 if (s.setup_done) setDeferOnboarding(false);
 // Reset setup / first-run: never keep Your setup over the mode chooser.
 if (!s.setup_done) {
 setShowSetup(false);
 setAfterAgentsSetup(false);
 deferYourSetupRef.current = false;
 setDeferYourSetup(false);
 } else if (!s.your_setup_shown) {
 // Ref: poll interval must not revive the tip after Esc session-hide.
 if (!deferYourSetupRef.current) setShowSetup(true);
 } else {
 setShowSetup(false);
 deferYourSetupRef.current = false;
 setDeferYourSetup(false);
 }
 if (!s.problems_alert) setHideSetupAlertBanner(false);
 } catch {
 // browser preview without Wails
 }
 }

 // Pessimistic until first snapshot: treat missing snap as setup pending.
 const setupPending = snap === null || !snap.setup_done;
 const awayDigest =
  snap?.away_digest?.pending &&
  ((snap.away_digest.blocks ?? 0) > 0 ||
    (snap.away_digest.waiting ?? 0) > 0 ||
    (snap.away_unread ?? 0) > 0)
   ? snap.away_digest
   : null;

 // Never cover Quit / Pause / tray Protect / Ask with the first-run modal.
 const showOnboarding =
 setupPending &&
 !deferOnboarding &&
 !quitOpen &&
 !trayPauseOpen &&
 !trayProtectConfirm &&
 !showProtectConfirm &&
 !decision &&
 !awayDigest;

 async function dismissAwayDigest() {
  try {
   await api.dismissAwayDigest();
  } catch {
   try {
    await api.clearAwayUnread();
   } catch {
    /* browser preview */
   }
  }
  await refreshSnap();
 }

 useEffect(() => {
 void refreshSnap();
 try {
 void api.ready();
 } catch {
 // browser preview
 }
 // Keep chrome/Home in sync with tray / external Protect changes.
 const poll = window.setInterval(() => {
 void refreshSnap();
 }, 2500);
 const offNav = api.onNavigate((r) => {
 const key = normalizeRoute(r);
 const low = (r || "").toLowerCase();
 if (key) {
 setRoute(key);
 // Tray/nav to Problems/Settings must not stay trapped under the setup modal.
 if (key === "home") setDeferOnboarding(false);
 else setDeferOnboarding(true);
 }
 if (low === "pause" || low.includes("pause-protect")) {
 setRoute("home");
 // Keep setup modal hidden so Pause is usable during first-run.
 setDeferOnboarding(true);
 // Do not cover an active Ask/block dialog (timer would keep firing underneath).
 if (decisionRef.current) {
 // Ask is already on screen — no toast (would hide under Decision then nag after).
 } else {
 setTrayToast("");
 setTrayPauseOpen(true);
 }
 }
 if (low === "enable-protect" || low.includes("enable-protect")) {
 setRoute("home");
 setDeferOnboarding(true);
 if (decisionRef.current) {
 // Ask visible — skip toast.
 } else {
 setTrayEnablePending(true);
 }
 }
 if (low === "quit") {
 setRoute("home");
 setDeferOnboarding(true);
 // Mirror Pause / Protect: Quit must not bury Ask/block (Bridge timer keeps running).
 if (decisionRef.current) {
 return;
 }
 setQuitMsg("");
 void api
 .quitNeedsChoice()
 .then((need) => {
 if (decisionRef.current) return;
 if (need) setQuitOpen(true);
 else
 void api.quit("off").catch((e) => {
 setQuitMsg(String(e));
 setQuitOpen(true);
 });
 })
 .catch(() => {
 if (decisionRef.current) return;
 setQuitOpen(true);
 });
 }
 if (low.includes("profiles-new") || low === "new") {
 setRoute("profiles");
 setDeferOnboarding(true);
 setOpenNewProfile(true);
 }
 if (low.includes("settings-advanced") || low.includes("agents-only") || low.includes("settings-asks")) {
 setRoute("settings");
 setDeferOnboarding(true);
 setSettingsTab("advanced");
 if (low.includes("agents-only")) setSettingsFocus("agents-only");
 else if (low.includes("settings-asks")) setSettingsFocus("asks");
 else setSettingsFocus(undefined); // settings-advanced → Advanced tab top
 setSettingsFocusNonce((n) => n + 1);
 }
 if (low.includes("always-allow")) {
 setRoute("settings");
 setDeferOnboarding(true);
 setSettingsTab("advanced");
 setSettingsFocus("always-allow");
 setSettingsFocusNonce((n) => n + 1);
 }
 void refreshSnap();
 });
 const offDec = api.onDecision((raw) => {
 setDecisionErr("");
 // Ask/block owns the surface — drop Pause/Quit/Jump/confirm so they do not resurface after.
 const buriedPagePause = pagePauseOpenRef.current || trayPauseOpenRef.current;
 setTrayPauseOpen(false);
 setQuitOpen(false);
 setQuitMsg("");
 // Soft notice after Ask resolves if we auto-closed Pause (toast must not cover Decision).
 buriedPauseToastRef.current = buriedPagePause;
 setTrayToast("");
 pagePauseOpenRef.current = false;
 setJumpOpen(false);
 setShowProtectConfirm(false);
 setTrayProtectConfirm(false);
 setTrayEnablePending(false);
 const payload: DecisionPayload = {
 id: String(raw.id ?? ""),
 host: String(raw.host ?? ""),
 reason: String(raw.reason ?? ""),
 why: String(raw.why ?? ""),
 url: String(raw.url ?? ""),
 timeout: Number(raw.timeout ?? 15),
 taught: Boolean(raw.taught),
 kind: String(raw.kind ?? "hard"),
 profile_name: String(raw.profile_name ?? ""),
 profile_id: String(raw.profile_id ?? ""),
 batch: Boolean(raw.batch),
 multi_agent: Boolean(raw.multi_agent),
 };
 // Before setState so tray Quit awaiting quitNeedsChoice sees Ask immediately.
 decisionRef.current = payload;
 setDecision(payload);
 });
 const offDecDone = api.onDecisionDone((id) => {
 if (!id || !decisionRef.current || decisionRef.current.id !== id) return;
 decisionRef.current = null;
 setDecision(null);
 setDecisionErr("");
 if (buriedPauseToastRef.current) {
 buriedPauseToastRef.current = false;
 setTrayToast("Block prompt closed the pause dialog.", false);
 } else {
 setTrayToast("");
 }
 });
 return () => {
 window.clearInterval(poll);
 offNav();
 offDec();
 offDecDone();
 };
 }, []);

 const resolveDecision = useCallback(async (action: string) => {
 const id = decision?.id || decisionRef.current?.id;
 if (!id) {
 decisionRef.current = null;
 setDecision(null);
 return;
 }
 try {
 await api.resolveDecision(id, action);
 decisionRef.current = null;
 setDecision(null);
 setDecisionErr("");
 if (buriedPauseToastRef.current) {
 buriedPauseToastRef.current = false;
 setTrayToast("Block prompt closed the pause dialog.", false);
 } else {
 setTrayToast("");
 }
 if (action === "open") setRoute("activity");
 await refreshSnap();
 } catch (e) {
 setDecisionErr(String(e) || "Could not apply that choice. Try again.");
 await refreshSnap();
 throw e;
 }
 }, [decision?.id]);

  // Your setup modal (not the peek banner). After Protect AI agents, show over
  // Profiles so dismissing does not unmount the New agent draft.
  const yourSetupModalOpen =
    !!showSetup &&
    !deferYourSetup &&
    !!snap?.setup_done &&
    !snap?.problems_alert &&
    (route === "home" || (afterAgentsSetup && route === "profiles"));

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (
          yourSetupModalOpen ||
          showProtectConfirm ||
          trayProtectConfirm ||
          quitOpen ||
          trayPauseOpen ||
          pagePauseOpenRef.current ||
          confirmModalOpen() ||
          // Hidden Profiles draft must not block Jump — only while My agents is visible.
          (route === "profiles" && profileEditOpen()) ||
          decision ||
          awayDigest ||
          !!snap?.needs_uxv2_migration
        )
          return;
        // First-run: Jump peeks other screens (Continue setup banner brings you back).
        if (setupPending) setDeferOnboarding(true);
        setJumpOpen(true);
        setJumpQ("");
      }
      if (e.key === "Escape") {
        // Do not treat Esc as "Not now" — that permanently finishes setup.
        if (trayProtectConfirm) {
          setTrayProtectConfirm(false);
          setOnboardToast("");
          return;
        }
        if (trayPauseOpen) {
          setTrayPauseOpen(false);
          setTrayToast("");
          return;
        }
        if (pagePauseOpenRef.current) {
          setPagePauseCloseReq((n) => n + 1);
          return;
        }
        if (quitOpen) {
          setQuitOpen(false);
          setQuitMsg("");
          return;
        }
        // Ask/block dialog owns the surface — never dismiss setup/protect under it.
        if (decision) return;
        if (awayDigest) {
          void dismissAwayDigest();
          return;
        }
        // UX v2 migration requires an explicit choice — Esc must not dismiss it via Jump.
        if (snap?.needs_uxv2_migration && !showOnboarding && !showSetup) return;
        if (showProtectConfirm) {
          if (onboardBusy) return;
          setShowProtectConfirm(false);
          setOnboardToast("");
          return;
        }
        // Esc: hide for this session only — Got it / Open DenyOut persist via MarkYourSetupShown.
        if (yourSetupModalOpen) {
          deferYourSetupRef.current = true;
          setDeferYourSetup(true);
          setShowSetup(false);
          return;
        }
        setJumpOpen(false);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [
    showProtectConfirm,
    yourSetupModalOpen,
    setupPending,
    trayProtectConfirm,
    trayPauseOpen,
    quitOpen,
    decision,
    awayDigest,
    route,
    snap?.needs_uxv2_migration,
    showOnboarding,
    showSetup,
    onboardBusy,
  ]);

  // Tray "Protect computer" → same in-app confirm copy as Home (not window.confirm).
  useEffect(() => {
    if (!trayEnablePending) return;
    setTrayEnablePending(false);
    setTrayProtectConfirm(true);
  }, [trayEnablePending]);

 const pillClass = snap?.problems_alert
 ? "pill alert"
 : snap?.mode === "safe"
   ? "pill"
   : snap?.mode === "agents"
     ? "pill agents"
     : snap?.mode === "session"
       ? "pill session"
       : "pill off";

 // Home replaces Getting started checklist; one Safe tip instead of three-mode glossary.
 const showGlossary =
 !showSetup && !!snap?.setup_done && !tipGone(snap?.dismissed_tips, "glossary");
 // Page tips stay available without requiring glossary dismiss first.
 const tipsEnabled = !showSetup && !!snap?.setup_done;

 const pausedUntil = (snap?.protect_paused_until || "").trim();
 const pausedUntilShort = (() => {
 if (!pausedUntil) return "";
 const t = Date.parse(pausedUntil);
 if (Number.isNaN(t)) return "";
 const d = new Date(t);
 const now = new Date();
 const sameDay = d.toDateString() === now.toDateString();
 // Match Home: include day when pause crosses midnight ("Until tomorrow").
 if (sameDay) {
 return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
 }
 return d.toLocaleString(undefined, {
 month: "short",
 day: "numeric",
 hour: "2-digit",
 minute: "2-digit",
 });
 })();
 const foreverOff =
 !snap?.protection_on &&
 (snap?.mode === "off" || !snap?.mode) &&
 (snap?.protect_pause_last || "") === "forever";
 const agentsOnlyOff =
 !snap?.problems_alert &&
 !snap?.protection_on &&
 (snap?.mode === "off" || !snap?.mode) &&
 !pausedUntil &&
 !foreverOff &&
 (snap?.agents_running || 0) > 0;
 const unavailableOff =
 !snap?.problems_alert &&
 !snap?.protection_on &&
 (snap?.mode === "off" || !snap?.mode) &&
 !pausedUntil &&
 !foreverOff &&
 snap?.computer_available === false;
 const modeStatusText = snap?.problems_alert
 ? "Needs attention - open Problems"
 : snap?.protection_on && snap?.mode === "safe"
   ? "Protected"
   : snap?.protection_on && snap?.mode === "agents"
     ? "Agents only"
     : snap?.protection_on && snap?.mode === "session"
       ? "Session"
       : pausedUntil
         ? pausedUntilShort
           ? `Paused until ${pausedUntilShort}`
           : "Paused"
         : foreverOff
           ? "Off until you turn it on"
           : unavailableOff
             ? (snap?.agents_running || 0) > 0
               ? "Off (unavailable) · agents running"
               : "Off (unavailable)"
             : agentsOnlyOff
               ? "Off · agents running"
               : snap?.mode_label || snap?.status || "";
 // Threat warn is a chip; keep Off/Paused detail on the muted line when not Home.
 const unreadAway = snap?.away_unread && snap.away_unread > 0 ? snap.away_unread : 0;
 const unreadSuffix =
 unreadAway === 1 ? " · 1 quiet" : unreadAway > 1 ? ` · ${unreadAway} quiet` : "";
 const snoozeSuffix = snap?.notify_snooze_active ? " · snoozed" : "";
 const statusTextBase =
 snap?.threat_lists_warn && !snap?.problems_alert
 ? modeStatusText
 ? `${modeStatusText} · Threat lists need a refresh`
 : "Threat lists need a refresh"
 : modeStatusText;
 const statusText = statusTextBase
 ? `${statusTextBase}${snoozeSuffix}${unreadSuffix}`
 : unreadAway
   ? unreadAway === 1
     ? `1 quiet${snoozeSuffix}`
     : `${unreadAway} quiet${snoozeSuffix}`
   : snoozeSuffix
     ? "Snoozed"
     : "";
 const pillLabelBase = !snap
 ? "Setup pending"
 : snap.problems_alert
 ? "Needs attention"
 : snap.protection_on && snap.mode === "safe"
   ? "Protected"
   : snap.protection_on && snap.mode === "agents"
     ? "Agents only"
     : snap.protection_on && snap.mode === "session"
       ? "Session"
       : setupPending
         ? "Setup pending"
         : pausedUntil
           ? pausedUntilShort
             ? `Paused until ${pausedUntilShort}`
             : "Paused"
           : foreverOff
             ? "Off until you turn it on"
             : unavailableOff
               ? (snap.agents_running || 0) > 0
                 ? "Off (unavailable) · agents running"
                 : "Off (unavailable)"
               : agentsOnlyOff
                 ? "Off · agents running"
                 : snap.mode_label || "Off";
 const pillLabel = `${pillLabelBase}${snap?.problems_alert ? "" : `${snoozeSuffix}${unreadSuffix}`}`;

 type JumpItem = {
 label: string;
 route: Route;
 hint: string;
 newProfile?: boolean;
 settingsTab?: "basic" | "advanced";
 focus?: string;
 askAction?: "pause" | "resume";
 openProtectPause?: boolean;
 };
 const jumpItems = useMemo(() => {
 const items: JumpItem[] = [
 { label: "Home", route: "home", hint: "Protection status" },
 { label: "History", route: "activity", hint: "What was blocked" },
 { label: "My agents", route: "profiles", hint: "Wrap a program" },
 { label: "New agent", route: "profiles", hint: "Create agent", newProfile: true },
 { label: "Settings", route: "settings", hint: "Basic & Advanced", settingsTab: "basic" },
 {
 label: "Allowed / silenced sites",
 route: "settings",
 hint: "Settings, Advanced",
 settingsTab: "advanced",
 focus: "always-allow",
 },
 {
 label: "Agents only",
 route: "settings",
 hint: "Whole PC - Advanced",
 settingsTab: "advanced",
 focus: "agents-only",
 },
 {
 label: "Threat lists",
 route: "settings",
 hint: "Phishing & malware lists",
 settingsTab: "basic",
 focus: "threat-lists",
 },
 {
 label: "Optional lists",
 route: "settings",
 hint: "Advanced ad/tracker feeds",
 settingsTab: "advanced",
 focus: "advanced-lists",
 },
 {
 label: "Notifications",
 route: "settings",
 hint: "Quiet, snooze, timeouts",
 settingsTab: "basic",
 focus: "notifications",
 },
 {
 label: "System banners",
 route: "settings",
 hint: "Advanced OS banners & Detailed",
 settingsTab: "advanced",
 focus: "system-banners",
 },
 {
 label: "Autostart",
 route: "settings",
 hint: "Launch at login",
 settingsTab: "basic",
 focus: "autostart",
 },
 {
 label: "Diagnostics",
 route: "settings",
 hint: "Logs, test, updates",
 settingsTab: "advanced",
 focus: "diagnostics",
 },
 {
 label: "Account",
 route: "settings",
 hint: "Sign in & sync",
 settingsTab: "advanced",
 focus: "account",
 },
 ];
 const asksVisible =
 snap?.mode === "agents" ||
 (snap?.policy_profile || "").toLowerCase() === "agent" ||
 (snap?.agents_running || 0) > 0 ||
 !!snap?.ask_paused;
 if (asksVisible) {
 items.push({
 label: snap?.ask_paused ? "Resume asks now" : "Pause asks now (15 min)",
 route: "settings",
 hint: "Applies immediately, then opens Settings → Asks",
 settingsTab: "advanced",
 focus: "asks",
 askAction: snap?.ask_paused ? "resume" : "pause",
 });
 }
 const protectLive =
 (snap?.mode === "safe" || snap?.mode === "agents" || snap?.mode === "session") &&
 !snap?.problems_alert;
 const protectPaused =
 !snap?.problems_alert &&
 (snap?.mode === "off" || !snap?.mode) &&
 (!!(snap?.protect_paused_until || "").trim() ||
 (snap?.protect_pause_last || "") === "forever");
 if (protectLive || snap?.problems_alert || protectPaused) {
 items.push({
 label: protectPaused
 ? "Change Protect pause…"
 : snap?.problems_alert && (snap?.mode === "off" || !snap?.mode)
   ? "Clear Protect intent…"
   : "Pause / turn off Protect…",
 route: "home",
 hint: "Opens pause choices",
 openProtectPause: true,
 });
 }
 items.push({ label: "Problems", route: "problems", hint: "Health & errors" });
 const q = jumpQ.trim().toLowerCase();
 if (!q) return items;
 return items.filter(
 (i) => i.label.toLowerCase().includes(q) || i.hint.toLowerCase().includes(q),
 );
 }, [
 jumpQ,
 snap?.ask_paused,
 snap?.mode,
 snap?.policy_profile,
 snap?.agents_running,
 snap?.protection_on,
 snap?.problems_alert,
 snap?.protect_paused_until,
 snap?.protect_pause_last,
 ]);

 function go(
 r: Route,
 opts?: {
 newProfile?: boolean;
 settingsTab?: "basic" | "advanced";
 focus?: string;
 askAction?: "pause" | "resume";
 openProtectPause?: boolean;
 },
 ) {
 if (r === "home") setDeferOnboarding(false);
 else setDeferOnboarding(true);
 setRoute(r);
 setJumpOpen(false);
 if (opts?.newProfile) setOpenNewProfile(true);
 if (opts?.settingsTab) setSettingsTab(opts.settingsTab);
 setSettingsFocus(opts?.focus);
 if (r === "settings") setSettingsFocusNonce((n) => n + 1);
 if (opts?.openProtectPause) {
 if (decision) {
 // Ask already on screen — skip toast (would nag after resolve).
 } else {
 setTrayToast("");
 setTrayPauseOpen(true);
 }
 }
 if (opts?.askAction === "pause") {
 void api
 .pauseAsks()
 .then(() => refreshSnap())
 .catch((e) => setOnboardToast(String(e)));
 } else if (opts?.askAction === "resume") {
 void api
 .resumeAsks()
 .then(() => refreshSnap())
 .catch((e) => setOnboardToast(String(e)));
 }
 }

 async function dismissSetup(opts?: { openHome?: boolean; openNewAgent?: boolean }) {
 // Never MarkYourSetupShown during first-run — that permanently skips the tip.
 if (!snap?.setup_done) {
 setShowSetup(false);
 return;
 }
 await api.markYourSetup();
 setDeferYourSetup(false);
 setShowSetup(false);
 const fromAgents = afterAgentsSetup;
 setAfterAgentsSetup(false);
 if (fromAgents && opts?.openNewAgent) {
 setRoute("profiles");
 setOpenNewProfile(true);
 } else if (opts?.openHome) {
 setRoute("home");
 }
 await refreshSnap();
 }

 async function chooseNotNow() {
 setOnboardBusy(true);
 setOnboardToast("");
 setAfterAgentsSetup(false);
 try {
 await applyOnboardChatty();
 await api.onboardingNotNow();
 setDeferOnboarding(false);
 await refreshSnap();
 } catch (e) {
 setOnboardToast(String(e));
 } finally {
 setOnboardBusy(false);
 }
 }

 async function clearBrokenSetupIntent() {
 setOnboardBusy(true);
 setOnboardToast("");
 try {
 await api.stopProtectionWithChoice("forever");
 await refreshSnap();
 setOnboardToast("Cleared stuck Protect intent. Choose a mode below.", false);
 } catch (e) {
 setOnboardToast(String(e), true);
 } finally {
 setOnboardBusy(false);
 }
 }

 async function chooseAgents() {
 setOnboardBusy(true);
 setOnboardToast("");
 try {
 await applyOnboardChatty();
 await api.onboardingAgents();
 setDeferOnboarding(true);
 setAfterAgentsSetup(true);
 setRoute("profiles");
 // Do not open New agent yet — Your setup (z40) must stay above the draft (z55).
 // "Continue to My agents" on the tip opens New via dismissSetup.
 await refreshSnap();
 } catch (e) {
 setOnboardToast(String(e));
 } finally {
 setOnboardBusy(false);
 }
 }

 async function confirmProtectComputer() {
 // Keep confirm mounted through elevate (mirror tray) — clearing it remounts mode chooser.
 setOnboardBusy(true);
 setOnboardToast("");
 try {
 await applyOnboardChatty();
 await api.enableSafe();
 setShowProtectConfirm(false);
 setDeferOnboarding(false);
 setRoute("home");
 await refreshSnap();
 } catch (e) {
 setOnboardToast(String(e), true);
 // Stay on Protect confirm so the error is visible; Cancel returns to mode chooser.
 } finally {
 setOnboardBusy(false);
 }
 }

 // Presence wave A3: while the window is focused/visible, suppress non-critical OS toasts.
 useEffect(() => {
 function syncFocus() {
 const on =
 typeof document !== "undefined" &&
 document.visibilityState === "visible" &&
 document.hasFocus();
 api.setNotifyUIFocused(on);
 }
 syncFocus();
 window.addEventListener("focus", syncFocus);
 window.addEventListener("blur", syncFocus);
 document.addEventListener("visibilitychange", syncFocus);
 return () => {
 window.removeEventListener("focus", syncFocus);
 window.removeEventListener("blur", syncFocus);
 document.removeEventListener("visibilitychange", syncFocus);
 api.setNotifyUIFocused(false);
 };
 }, []);

 const setupLines = (snap?.your_setup_text || "").split("\n").filter(Boolean);

 return (
 <div className="app">
 <nav className="nav">
 <div className="brand">DenyOut</div>
 <button
 className={route === "home" ? "active" : ""}
 onClick={() => {
 setDeferOnboarding(false);
 setRoute("home");
 }}
 >
 Home
 </button>
 <button
 className={route === "activity" ? "active" : ""}
 onClick={() => {
 setDeferOnboarding(true);
 setRoute("activity");
 }}
 >
 History
 </button>
 <button
 className={route === "settings" ? "active" : ""}
 onClick={() => {
 setDeferOnboarding(true);
 setSettingsTab("basic");
 setSettingsFocus(undefined);
 setSettingsFocusNonce((n) => n + 1);
 setRoute("settings");
 }}
 >
 Settings
 </button>
 <button
 className={route === "problems" ? "active" : ""}
 onClick={() => {
 setDeferOnboarding(true);
 setRoute("problems");
 }}
 >
 Problems
 {snap?.problems_alert ? (
 <span className="nav-badge" title="Needs attention" />
 ) : snap?.threat_lists_warn ? (
 <span className="nav-badge warn" title="Threat lists need a refresh" />
 ) : null}
 </button>
 <button
 className={`nav-secondary ${route === "profiles" ? "active" : ""}`}
 onClick={() => {
 setDeferOnboarding(true);
 setRoute("profiles");
 }}
 >
 My agents
 </button>
 </nav>
 <div className="main">
 <header className="topbar">
 <span className={pillClass}>{pillLabel}</span>
 {snap?.threat_lists_warn && !snap?.problems_alert ? (
 <span className="pill warn" title="Threat lists need a refresh">
 Threat lists
 </span>
 ) : null}
 {snap?.problems_alert ? (
 <>
 <span className="status-alert" role="status">
 Needs attention - open Problems
 </span>
 <button
 className="btn"
 onClick={() => {
 setDeferOnboarding(true);
 setRoute("problems");
 }}
 >
 Open Problems
 </button>
 </>
 ) : route !== "home" && statusText && statusText !== "Protected" ? (
 <span className="muted">{statusText}</span>
 ) : null}
 <span style={{ flex: 1 }} />
 <button className="btn subtle" onClick={() => void refreshSnap()} title="Refresh">
 Refresh
 </button>
 </header>
 <div className="content">
 {setupPending && deferOnboarding ? (
 <p className="warn-box" style={{ marginTop: 0 }}>
 Setup is not finished yet.{" "}
 <button
 type="button"
 className="btn subtle"
 onClick={() => {
 setDeferOnboarding(false);
 setRoute("home");
 }}
 >
 Continue setup
 </button>
 </p>
 ) : showSetup &&
 snap?.setup_done &&
 snap?.problems_alert &&
 !hideSetupAlertBanner ? (
 <p className="notice-box" style={{ marginTop: 0 }}>
 Protect needs attention before Your setup.{" "}
 <button
 type="button"
 className="btn subtle"
 onClick={() => {
 setDeferOnboarding(true);
 setRoute("problems");
 }}
 >
 Open Problems
 </button>
 {" · "}
 <button
 type="button"
 className="btn subtle"
 onClick={() => setHideSetupAlertBanner(true)}
 >
 Hide for now
 </button>
 </p>
 ) : showSetup && snap?.setup_done && afterAgentsSetup && route !== "profiles" ? (
 <p className="notice-box" style={{ marginTop: 0 }}>
 Your setup tip is waiting on My agents.{" "}
 <button
 type="button"
 className="btn subtle"
 onClick={() => setRoute("profiles")}
 >
 Open My agents
 </button>
 {" · "}
 <button type="button" className="btn subtle" onClick={() => void dismissSetup()}>
 Got it
 </button>
 </p>
 ) : showSetup && snap?.setup_done && !yourSetupModalOpen && route !== "home" ? (
 <p className="notice-box" style={{ marginTop: 0 }}>
 Your setup tip is waiting on Home.{" "}
 <button type="button" className="btn subtle" onClick={() => setRoute("home")}>
 Open Home
 </button>
 </p>
 ) : deferYourSetup &&
 snap?.setup_done &&
 !snap?.your_setup_shown &&
 !snap?.problems_alert ? (
 <p className="notice-box" style={{ marginTop: 0 }}>
 Your setup tip is waiting.{" "}
 <button
 type="button"
 className="btn subtle"
 onClick={() => {
 deferYourSetupRef.current = false;
 setDeferYourSetup(false);
 setShowSetup(true);
 if (afterAgentsSetup) setRoute("profiles");
 else setRoute("home");
 }}
 >
 Show tip
 </button>
 {" · "}
 <button type="button" className="btn subtle" onClick={() => void dismissSetup()}>
 Got it
 </button>
 </p>
 ) : null}
 {showGlossary && (
 <div className="tip-wrap">
 <Tip id="glossary" dismissed={false} onDismiss={() => void refreshSnap()}>
 <strong>Protect computer</strong> keeps everyday browsing safe. Open Home anytime to
 see if you are protected - History shows what was blocked.
 </Tip>
 </div>
 )}

 {route === "home" && (
 <Home
 snap={snap}
 pauseBlocked={trayPauseOpen || !!decision}
 pauseCloseReq={pagePauseCloseReq}
 onPauseOpenChange={(open) => {
 pagePauseOpenRef.current = open;
 }}
 onChanged={() => void refreshSnap()}
 onSeeHistory={() => setRoute("activity")}
 onOpenProblems={() => {
 setDeferOnboarding(true);
 setRoute("problems");
 }}
 onOpenSettings={() => {
 setDeferOnboarding(true);
 setSettingsTab("basic");
 setSettingsFocus(undefined);
 setSettingsFocusNonce((n) => n + 1);
 setRoute("settings");
 }}
 onOpenThreatSettings={() => {
 setDeferOnboarding(true);
 setSettingsTab("basic");
 setSettingsFocus("threat-lists");
 setSettingsFocusNonce((n) => n + 1);
 setRoute("settings");
 }}
 onOpenSettingsDiagnostics={() => {
 setDeferOnboarding(true);
 setSettingsTab("advanced");
 setSettingsFocus("diagnostics");
 setSettingsFocusNonce((n) => n + 1);
 setRoute("settings");
 }}
 onOpenAgents={() => {
 setDeferOnboarding(true);
 setRoute("profiles");
 }}
 />
 )}
 {route === "activity" && (
 <Activity
 snap={snap}
 tipsEnabled={tipsEnabled}
 onTipDismiss={() => void refreshSnap()}
 onOpenSettingsAdvanced={() => {
 setDeferOnboarding(true);
 setSettingsTab("advanced");
 setSettingsFocus("diagnostics");
 setSettingsFocusNonce((n) => n + 1);
 setRoute("settings");
 }}
 />
 )}
 {(route === "profiles" || profilesEver) && (
 <div style={{ display: route === "profiles" ? undefined : "none" }}>
 <Profiles
 openNew={openNewProfile}
 onNewConsumed={() => setOpenNewProfile(false)}
 snap={snap}
 tipsEnabled={tipsEnabled}
 onTipDismiss={() => void refreshSnap()}
 escDeferred={
 route !== "profiles" ||
 yourSetupModalOpen ||
 jumpOpen ||
 !!decision ||
 quitOpen ||
 trayPauseOpen ||
 trayProtectConfirm
 }
 />
 </div>
 )}
 {route === "settings" && (
 <Settings
 snap={snap}
 tipsEnabled={tipsEnabled}
 initialTab={settingsTab}
 focusSection={settingsFocus}
 focusNonce={settingsFocusNonce}
 pauseBlocked={trayPauseOpen || !!decision}
 pauseCloseReq={pagePauseCloseReq}
 onPauseOpenChange={(open) => {
 pagePauseOpenRef.current = open;
 }}
 onClearFocus={() => setSettingsFocus(undefined)}
 onChanged={() => void refreshSnap()}
 />
 )}
 {route === "problems" && (
 <Problems
 pauseBlocked={trayPauseOpen || !!decision}
 pauseCloseReq={pagePauseCloseReq}
 onPauseOpenChange={(open) => {
 pagePauseOpenRef.current = open;
 }}
 onOpenActivity={() => {
 setDeferOnboarding(true);
 setRoute("activity");
 }}
 onOpenThreatSettings={() => {
 setDeferOnboarding(true);
 setSettingsTab("basic");
 setSettingsFocus("threat-lists");
 setSettingsFocusNonce((n) => n + 1);
 setRoute("settings");
 }}
 />
 )}
 </div>
 </div>

 {decision && (
 <DecisionModal
 payload={decision}
 error={decisionErr}
 onResolve={(a) => void resolveDecision(a)}
 />
 )}

 {awayDigest && !decision ? (
  <AwayDigestModal
   blocks={awayDigest.blocks ?? 0}
   waiting={awayDigest.waiting ?? 0}
   hosts={awayDigest.hosts ?? []}
   onReview={() => {
    void dismissAwayDigest().then(() => {
     setDeferOnboarding(true);
     setRoute("activity");
    });
   }}
   onDismiss={() => {
    void dismissAwayDigest();
   }}
   onOpenWaiting={
    (awayDigest.waiting ?? 0) > 0
     ? () => {
        void dismissAwayDigest().then(() => {
         setDeferOnboarding(true);
         setRoute("activity");
        });
       }
     : undefined
   }
  />
 ) : null}

 {trayPauseOpen ? (
 <PauseModal
 busy={trayPauseBusy}
 brokenIntent={
 !!snap?.problems_alert && (snap?.mode === "off" || !snap?.mode)
 }
 alreadyOff={
 !snap?.problems_alert &&
 (snap?.mode === "off" || !snap?.mode) &&
 (!!(snap?.protect_paused_until || "").trim() ||
 (snap?.protect_pause_last || "") === "forever")
 }
 error={trayPauseMsgWarn ? trayPauseMsg : ""}
 onCancel={() => {
 setTrayPauseOpen(false);
 setTrayToast("");
 if (setupPending) setDeferOnboarding(false);
 }}
 onChoose={(choice) => {
 setTrayPauseBusy(true);
 setTrayToast("");
 void api
 .stopProtectionWithChoice(choice)
 .then(() => {
 setTrayPauseOpen(false);
 if (setupPending) setDeferOnboarding(false);
 return refreshSnap();
 })
 .catch((e) => {
 setTrayToast(String(e) || "Could not turn Protect off. Try again.", true);
 return refreshSnap();
 })
 .finally(() => setTrayPauseBusy(false));
 }}
 />
 ) : null}

 {quitOpen && !decision ? (
 <div className="modal-backdrop" style={{ zIndex: 55 }}>
 <div className="modal" onClick={(e) => e.stopPropagation()}>
      <h2>Quit DenyOut?</h2>
      <p className="muted">
        {snap?.mode === "session"
          ? "Session protection runs inside DenyOut and always stops when you quit. My agents wraps stop too."
          : snap?.problems_alert && (snap?.mode === "off" || !snap?.mode)
            ? "Protect is not running. Clear restore intent and quit, quit but keep intent for next launch, or Cancel."
            : "Whole-PC Protect (computer proxy) can stay on after Quit, or turn off first. Session and My agents wraps always stop when you quit."}
      </p>
 {quitMsg ? <p className="warn-box">{quitMsg}</p> : null}
 <div className="stack" style={{ gap: "0.5rem", marginTop: "0.85rem" }}>
 <button
 type="button"
 className="btn primary"
 disabled={quitBusy}
 style={{ width: "100%", textAlign: "left" }}
 onClick={() => {
 setQuitBusy(true);
 setQuitMsg("");
 void api
 .quit("off")
 .catch((e) => {
 setQuitMsg(String(e) || "Could not turn Protect off.");
 setQuitBusy(false);
 });
 }}
 >
 <strong>
 {snap?.problems_alert && (snap?.mode === "off" || !snap?.mode)
 ? "Clear intent and quit"
 : "Turn off protection and quit"}
 </strong>
 </button>
 {snap?.mode !== "session" ? (
 <button
 type="button"
 className="btn"
 disabled={quitBusy}
 style={{ width: "100%", textAlign: "left" }}
 onClick={() => {
 setQuitBusy(true);
 setQuitMsg("");
 void api
 .quit("keep")
 .catch((e) => {
 setQuitMsg(String(e) || "Could not quit.");
 setQuitBusy(false);
 });
 }}
 >
 <strong>
 {snap?.problems_alert && (snap?.mode === "off" || !snap?.mode)
 ? "Quit and keep restore intent"
 : "Keep protection on and quit"}
 </strong>
 </button>
 ) : null}
 <button
 type="button"
 className="btn"
 disabled={quitBusy}
 onClick={() => {
 setQuitOpen(false);
 setQuitMsg("");
 if (setupPending) setDeferOnboarding(false);
 }}
 >
 Cancel
 </button>
 </div>
 </div>
 </div>
 ) : null}

 {/* Never cover Ask/block (Decision z=60) — toast only when Decision is closed. */}
 {(!decision &&
 (trayPauseMsg ||
 (onboardMsg &&
 !showOnboarding &&
 !showProtectConfirm &&
 !trayProtectConfirm &&
 !snap?.needs_uxv2_migration))) ? (
 <p
 className={
 trayPauseMsg
 ? trayPauseMsgWarn
 ? "warn-box"
 : "notice-box"
 : onboardMsgWarn
 ? "warn-box"
 : "notice-box"
 }
 style={{
 position: "fixed",
 bottom: "1rem",
 left: "1rem",
 right: "1rem",
 zIndex: 50,
 }}
 >
 {trayPauseMsg || onboardMsg}
 <button
 type="button"
 className="btn subtle"
 style={{ marginLeft: "0.75rem" }}
 onClick={() => {
 setTrayToast("");
 setOnboardToast("");
 }}
 >
 Dismiss
 </button>
 </p>
 ) : null}

 {snap?.needs_uxv2_migration && !showOnboarding && !showSetup && (
 <div className="modal-backdrop" style={{ zIndex: 55 }}>
 <div className="modal" onClick={(e) => e.stopPropagation()}>
 <h2>Update DenyOut defaults?</h2>
 <p className="muted">
 Earlier versions used Agents only for the whole computer — messengers and many sites
 can break. Protect computer is recommended for everyday browsing; use My agents for AI
 tools.
 </p>
 {onboardMsg ? <p className="warn-box">{onboardMsg}</p> : null}
 <div className="row-actions" style={{ marginTop: "1rem" }}>
 <button
 className="btn primary"
 disabled={migrateBusy}
 onClick={() => {
 setMigrateBusy(true);
 setOnboardToast("");
 void api
 .migrateUXv2(true)
 .then(() => refreshSnap())
 .catch((e) => setOnboardToast(String(e)))
 .finally(() => setMigrateBusy(false));
 }}
 >
 Switch to Protect computer
 </button>
 <button
 className="btn"
 disabled={migrateBusy}
 onClick={() => {
 setMigrateBusy(true);
 setOnboardToast("");
 void api
 .migrateUXv2(false)
 .then(() => refreshSnap())
 .catch((e) => setOnboardToast(String(e)))
 .finally(() => setMigrateBusy(false));
 }}
 >
 Keep Agents only
 </button>
 </div>
 </div>
 </div>
 )}

      {showOnboarding && (
        <div className="modal-backdrop">
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>How should DenyOut protect this computer?</h2>
            <p className="muted">
              Choose a mode. Protect computer may ask for your password once; My agents do not.
              {snap?.helper_ok
                ? " A helper is already on this computer, so Protect often skips the password."
                : ""}
            </p>
            <div style={{ marginTop: "1rem" }}>
              <p className="muted" style={{ marginBottom: "0.45rem" }}>
                How should DenyOut talk to you?
              </p>
              <p className="muted" style={{ marginBottom: "0.55rem", fontSize: "0.9em" }}>
                Blocks always go to History. The system stays mostly quiet unless you ask for more.
              </p>
              <div className="row-actions" style={{ flexWrap: "wrap", gap: "0.5rem" }}>
                <button
                  type="button"
                  className={onboardChatty === "quiet" ? "btn primary" : "btn"}
                  disabled={onboardBusy}
                  onClick={() => setOnboardChatty("quiet")}
                >
                  Quiet (recommended)
                </button>
                <button
                  type="button"
                  className={onboardChatty === "normal" ? "btn primary" : "btn"}
                  disabled={onboardBusy}
                  onClick={() => setOnboardChatty("normal")}
                >
                  A bit more
                </button>
              </div>
            </div>
            {snap?.problems_alert ? (
              <p className="warn-box" style={{ marginTop: "0.75rem" }}>
                Protect intent looks stuck from a previous try. Clear it below, or open Problems in
                peek mode — use Continue setup on the banner to return here.
              </p>
            ) : null}
            {snap?.threat_lists_warn && !snap?.problems_alert ? (
              <p className="warn-box" style={{ marginTop: "0.75rem" }}>
                Threat lists need a refresh. Open Problems in peek mode, then Continue setup to
                finish choosing a mode.
              </p>
            ) : null}
 <div className="stack" style={{ gap: "0.75rem", marginTop: "1rem" }}>
            {snap?.problems_alert ? (
              <button
                className="btn danger"
                disabled={onboardBusy}
                onClick={() => void clearBrokenSetupIntent()}
                style={{ width: "100%", textAlign: "left" }}
              >
                <strong>Clear broken Protect intent</strong>
                <div className="muted" style={{ fontWeight: 400, marginTop: "0.25rem" }}>
                  Stops DenyOut from trying to restore Protect before you choose a mode.
                </div>
              </button>
            ) : null}
            {snap?.problems_alert || snap?.threat_lists_warn ? (
              <button
                className="btn"
                disabled={onboardBusy}
                onClick={() => {
                  setDeferOnboarding(true);
                  setRoute("problems");
                }}
                style={{ width: "100%", textAlign: "left" }}
              >
                <strong>Open Problems first</strong>
                <div className="muted" style={{ fontWeight: 400, marginTop: "0.25rem" }}>
                  Review health or threat lists, then continue setup from the banner.
                </div>
              </button>
            ) : null}
 <button
 className="btn primary"
 disabled={onboardBusy}
 onClick={() => setShowProtectConfirm(true)}
 style={{ width: "100%", textAlign: "left", padding: "0.85rem 1rem" }}
 >
 <strong>Protect computer</strong>
 <div className="muted" style={{ fontWeight: 400, marginTop: "0.25rem" }}>
 Browse as usual. We only interrupt for clear risks.
 {snap?.helper_ok
 ? " Helper present — password prompt is often skipped."
 : " May need your computer password until the helper is installed."}
 </div>
 </button>
 <button
 className="btn"
 disabled={onboardBusy}
 onClick={() => void chooseAgents()}
 style={{ width: "100%", textAlign: "left" }}
 >
 <strong>Protect AI agents</strong>
 <div className="muted" style={{ fontWeight: 400, marginTop: "0.25rem" }}>
 Wrap tools you choose. Rest of the PC unchanged. No admin password.
 </div>
 </button>
 <button className="btn" disabled={onboardBusy} onClick={() => void chooseNotNow()}>
 Not now
 </button>
 </div>
 {onboardMsg ? (
 <p className={onboardMsgWarn ? "warn-box" : "notice-box"}>{onboardMsg}</p>
 ) : null}
 </div>
 </div>
 )}

 {trayProtectConfirm && (
 <div className="modal-backdrop" style={{ zIndex: 55 }}>
 <div className="modal" onClick={(e) => e.stopPropagation()}>
 <h2>{snap?.protect_confirm_title || "Turn on Protect computer?"}</h2>
 <p style={{ whiteSpace: "pre-wrap" }}>
 {snap?.protect_confirm_body ||
 "Your system may ask for a password so DenyOut can set network rules. Continue?"}
 </p>
 {onboardMsg ? <p className="warn-box">{onboardMsg}</p> : null}
 <div className="row-actions">
 <button
 className="btn primary"
 disabled={trayProtectBusy}
 onClick={() => {
 setTrayProtectBusy(true);
 setOnboardToast("");
 void api
 .enableSafe()
 .then(() => {
 setTrayProtectConfirm(false);
 setDeferOnboarding(false);
 return refreshSnap();
 })
 .catch((e) =>
 setOnboardToast(String(e) || "Could not turn Protect on. Try again from Home."),
 )
 .finally(() => setTrayProtectBusy(false));
 }}
 >
 Continue
 </button>
 <button
 className="btn"
 disabled={trayProtectBusy}
 onClick={() => {
 setTrayProtectConfirm(false);
 setOnboardToast("");
 if (setupPending) setDeferOnboarding(false);
 }}
 >
 Cancel
 </button>
 </div>
 </div>
 </div>
 )}

 {showProtectConfirm && (
 <div className="modal-backdrop" style={{ zIndex: 55 }}>
 <div className="modal" onClick={(e) => e.stopPropagation()}>
 <h2>{snap?.protect_confirm_title || "Turn on Protect computer?"}</h2>
 <p style={{ whiteSpace: "pre-wrap" }}>
 {snap?.protect_confirm_body ||
 "Your system may ask for a password so DenyOut can set network rules. Continue?"}
 </p>
 {onboardMsg ? (
 <p className={onboardMsgWarn ? "warn-box" : "notice-box"}>{onboardMsg}</p>
 ) : null}
 <div className="row-actions">
 <button className="btn primary" disabled={onboardBusy} onClick={() => void confirmProtectComputer()}>
 Continue
 </button>
 <button
 className="btn"
 disabled={onboardBusy}
 onClick={() => {
 setShowProtectConfirm(false);
 setOnboardToast("");
 }}
 >
 Cancel
 </button>
 </div>
 </div>
 </div>
 )}

 {yourSetupModalOpen && snap && (
 <div className="modal-backdrop">
 <div className="modal">
 <h2>Your setup</h2>
 {setupLines.length > 0 ? (
 setupLines.map((line, i) => <p key={i}>{line}</p>)
 ) : (
 <>
 <p>
 You are on <strong>{snap.mode_label}</strong>.
 </p>
 <p>
 - When something is blocked: Keep blocked or Allow this site.
 <br />- Open DenyOut (Home) to see if you are protected and what was blocked.
 <br />- If Protect failed, open Problems.
 </p>
 </>
 )}
 <div className="row-actions">
 <button
 className="btn primary"
 onClick={() =>
 void dismissSetup(
 afterAgentsSetup ? { openNewAgent: true } : { openHome: true },
 )
 }
 >
 {afterAgentsSetup ? "Continue to My agents" : "Open DenyOut"}
 </button>
 <button className="btn" onClick={() => void dismissSetup()}>
 Got it
 </button>
 </div>
 </div>
 </div>
 )}

 {jumpOpen && (
 <div className="modal-backdrop" style={{ zIndex: 55 }} onClick={() => setJumpOpen(false)}>
 <div className="modal jump" onClick={(e) => e.stopPropagation()}>
 <h2>Jump to</h2>
 <input
 autoFocus
 placeholder="Type a screen..."
 value={jumpQ}
 onChange={(e) => setJumpQ(e.target.value)}
 onKeyDown={(e) => {
 if (e.key === "Enter" && jumpItems[0]) {
 go(jumpItems[0].route, {
 newProfile: jumpItems[0].newProfile,
 settingsTab: jumpItems[0].settingsTab,
 focus: jumpItems[0].focus,
 askAction: jumpItems[0].askAction,
 openProtectPause: jumpItems[0].openProtectPause,
 });
 }
 }}
 />
 <ul className="jump-list">
 {jumpItems.map((i) => (
 <li key={i.label}>
 <button
 type="button"
 className="jump-item"
 onClick={() =>
 go(i.route, {
 newProfile: i.newProfile,
 settingsTab: i.settingsTab,
 focus: i.focus,
 askAction: i.askAction,
 openProtectPause: i.openProtectPause,
 })
 }
 >
 <span>{i.label}</span>
 <span className="muted">{i.hint}</span>
 </button>
 </li>
 ))}
 </ul>
 <p className="muted">Esc to close - Ctrl+K to open</p>
 </div>
 </div>
 )}
 </div>
 );
}

function normalizeRoute(r: string): Route | null {
 const s = (r || "").toLowerCase().trim();
 if (!s) return null;
 if (s === "home" || s === "dashboard") return "home";
 if (s === "activity" || s === "blocked" || s === "history") return "activity";
 if (s === "profiles" || s === "agents" || s === "profiles-new" || s === "new") return "profiles";
 if (s.startsWith("settings")) return "settings";
 if (s === "problems" || s === "help") return "problems";
 return null;
}
