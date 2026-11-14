import { useCallback, useEffect, useMemo, useState } from "react";
import { DecisionModal, DecisionPayload } from "./components/DecisionModal";
import { Tip, tipGone } from "./components/Tip";
import { Activity } from "./pages/Activity";
import { Home } from "./pages/Home";
import { Problems } from "./pages/Problems";
import { Profiles } from "./pages/Profiles";
import { Settings } from "./pages/Settings";
import { api, UISnapshot } from "./wails";

type Route = "home" | "activity" | "profiles" | "settings" | "problems";

export default function App() {
 const [route, setRoute] = useState<Route>("home");
 const [snap, setSnap] = useState<UISnapshot | null>(null);
 const [showSetup, setShowSetup] = useState(false);
 const [openNewProfile, setOpenNewProfile] = useState(false);
 const [jumpOpen, setJumpOpen] = useState(false);
 const [jumpQ, setJumpQ] = useState("");
 const [settingsTab, setSettingsTab] = useState<"basic" | "advanced">("basic");
 const [settingsFocus, setSettingsFocus] = useState<string | undefined>();
 const [decision, setDecision] = useState<DecisionPayload | null>(null);

 async function refreshSnap() {
 try {
 const s = await api.snapshot();
 setSnap(s);
 if (s.setup_done && !s.your_setup_shown) {
 setShowSetup(true);
 }
 } catch {
 // browser preview without Wails
 }
 }

 useEffect(() => {
 void refreshSnap();
 try {
 void api.ready();
 } catch {
 // browser preview
 }
 const offNav = api.onNavigate((r) => {
 const key = normalizeRoute(r);
 if (key) setRoute(key);
 const low = (r || "").toLowerCase();
 if (low.includes("profiles-new") || low === "new") {
 setRoute("profiles");
 setOpenNewProfile(true);
 }
 if (low.includes("settings-advanced") || low.includes("agents-only")) {
 setRoute("settings");
 setSettingsTab("advanced");
 if (low.includes("agents-only")) setSettingsFocus("agents-only");
 }
 if (low.includes("always-allow")) {
 setRoute("settings");
 setSettingsTab("advanced");
 setSettingsFocus("always-allow");
 }
 void refreshSnap();
 });
 const offDec = api.onDecision((raw) => {
 setDecision({
 id: String(raw.id ?? ""),
 host: String(raw.host ?? ""),
 reason: String(raw.reason ?? ""),
 why: String(raw.why ?? ""),
 url: String(raw.url ?? ""),
 timeout: Number(raw.timeout ?? 15),
 taught: Boolean(raw.taught),
 });
 });
 return () => {
 offNav();
 offDec();
 };
 }, []);

 const resolveDecision = useCallback(async (action: string) => {
 const id = decision?.id;
 setDecision(null);
 if (!id) return;
 try {
 await api.resolveDecision(id, action);
 if (action === "open") setRoute("activity");
 await refreshSnap();
 } catch {
 // ignore
 }
 }, [decision?.id]);

 useEffect(() => {
 function onKey(e: KeyboardEvent) {
 if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
 e.preventDefault();
 setJumpOpen(true);
 setJumpQ("");
 }
 if (e.key === "Escape") setJumpOpen(false);
 }
 window.addEventListener("keydown", onKey);
 return () => window.removeEventListener("keydown", onKey);
 }, []);

 const pillClass =
 snap?.mode === "safe" ? "pill" : snap?.mode === "agents" ? "pill agents" : "pill off";

 // Home replaces Getting started checklist; one Safe tip instead of three-mode glossary.
 const showGlossary =
 !showSetup && !!snap?.setup_done && !tipGone(snap?.dismissed_tips, "glossary");
 const tipsEnabled = !showSetup && tipGone(snap?.dismissed_tips, "glossary");

 const statusText = snap?.problems_alert
 ? "Needs attention - open Problems"
 : snap?.protection_on && snap?.mode === "safe"
 ? "Protected"
 : snap?.status || "";

 const jumpItems = useMemo(() => {
 const items = [
 { label: "Home", route: "home" as Route, hint: "Protection status" },
 { label: "History", route: "activity" as Route, hint: "What was blocked" },
 { label: "My agents", route: "profiles" as Route, hint: "Wrap a program" },
 { label: "New agent", route: "profiles" as Route, hint: "Create agent", newProfile: true },
 { label: "Settings", route: "settings" as Route, hint: "Basic & Advanced", settingsTab: "basic" as const },
 {
 label: "Allowed / silenced sites",
 route: "settings" as Route,
 hint: "Settings, Advanced",
 settingsTab: "advanced" as const,
 focus: "always-allow",
 },
 {
 label: "Resume asks",
 route: "settings" as Route,
 hint: "Settings, Advanced",
 settingsTab: "advanced" as const,
 focus: "asks",
 },
 {
 label: "Agents only",
 route: "settings" as Route,
 hint: "Whole PC - Advanced",
 settingsTab: "advanced" as const,
 focus: "agents-only",
 },
 { label: "Problems", route: "problems" as Route, hint: "Health & errors" },
 ];
 const q = jumpQ.trim().toLowerCase();
 if (!q) return items;
 return items.filter(
 (i) => i.label.toLowerCase().includes(q) || i.hint.toLowerCase().includes(q),
 );
 }, [jumpQ]);

 function go(
 r: Route,
 opts?: { newProfile?: boolean; settingsTab?: "basic" | "advanced"; focus?: string },
 ) {
 setRoute(r);
 setJumpOpen(false);
 if (opts?.newProfile) setOpenNewProfile(true);
 if (opts?.settingsTab) setSettingsTab(opts.settingsTab);
 setSettingsFocus(opts?.focus);
 }

 async function dismissSetup(openHome: boolean) {
 await api.markYourSetup();
 setShowSetup(false);
 if (openHome) setRoute("home");
 await refreshSnap();
 }

 const setupLines = (snap?.your_setup_text || "").split("\n").filter(Boolean);

 return (
 <div className="app">
 <nav className="nav">
 <div className="brand">DenyOut</div>
 <button className={route === "home" ? "active" : ""} onClick={() => setRoute("home")}>
 Home
 </button>
 <button className={route === "activity" ? "active" : ""} onClick={() => setRoute("activity")}>
 History
 </button>
 <button className={route === "settings" ? "active" : ""} onClick={() => setRoute("settings")}>
 Settings
 </button>
 <button className={route === "problems" ? "active" : ""} onClick={() => setRoute("problems")}>
 Problems
 {snap?.problems_alert ? <span className="nav-badge" title="Needs attention" /> : null}
 </button>
 <button
 className={`nav-secondary ${route === "profiles" ? "active" : ""}`}
 onClick={() => setRoute("profiles")}
 >
 My agents
 </button>
 </nav>
 <div className="main">
 <header className="topbar">
 <span className={pillClass}>
 {snap?.protection_on && snap?.mode === "safe"
 ? "Protected"
 : snap?.mode_label || "..."}
 </span>
 {snap?.problems_alert ? (
 <>
 <span className="status-alert" role="status">
 Needs attention - open Problems
 </span>
 <button className="btn" onClick={() => setRoute("problems")}>
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
 onChanged={() => void refreshSnap()}
 onSeeHistory={() => setRoute("activity")}
 onOpenProblems={() => setRoute("problems")}
 onOpenSettings={() => {
 setSettingsTab("basic");
 setRoute("settings");
 }}
 onOpenAgents={() => setRoute("profiles")}
 />
 )}
 {route === "activity" && (
 <Activity
 snap={snap}
 tipsEnabled={tipsEnabled}
 onTipDismiss={() => void refreshSnap()}
 onOpenSettingsAdvanced={() => {
 setSettingsTab("advanced");
 setSettingsFocus("diagnostics");
 setRoute("settings");
 }}
 />
 )}
 {route === "profiles" && (
 <Profiles
 openNew={openNewProfile}
 onNewConsumed={() => setOpenNewProfile(false)}
 snap={snap}
 tipsEnabled={tipsEnabled}
 onTipDismiss={() => void refreshSnap()}
 />
 )}
 {route === "settings" && (
 <Settings
 snap={snap}
 tipsEnabled={tipsEnabled}
 initialTab={settingsTab}
 focusSection={settingsFocus}
 onChanged={() => void refreshSnap()}
 />
 )}
 {route === "problems" && (
 <Problems onOpenActivity={() => setRoute("activity")} />
 )}
 </div>
 </div>

 {decision && (
 <DecisionModal payload={decision} onResolve={(a) => void resolveDecision(a)} />
 )}

 {showSetup && snap && (
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
 <button className="btn primary" onClick={() => void dismissSetup(true)}>
 Open DenyOut
 </button>
 <button className="btn" onClick={() => void dismissSetup(false)}>
 Got it
 </button>
 </div>
 </div>
 </div>
 )}

 {jumpOpen && (
 <div className="modal-backdrop" onClick={() => setJumpOpen(false)}>
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
 if (s === "home" || s === "dashboard") return "home";
 if (!s || s === "activity" || s === "blocked" || s === "history") return "activity";
 if (s === "profiles" || s === "agents" || s === "profiles-new" || s === "new") return "profiles";
 if (s.startsWith("settings")) return "settings";
 if (s === "problems" || s === "help") return "problems";
 return null;
}
