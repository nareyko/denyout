/** Thin typed wrappers around Wails-bound Bridge methods. */

export type DenialQuery = {
 search?: string;
 reason?: string;
 process?: string;
 remembered_only?: boolean;
 limit?: number;
};

export type DenialView = {
 id: string;
 ts: string;
 host: string;
 url: string;
 why: string;
 reasons: string[];
 primary_reason?: string;
 process: string;
 method?: string;
 detectors?: string[];
 policy_profile?: string;
 remembered: boolean;
};

export type TimedRule = {
 host: string;
 reason?: string;
 expires_at: string;
};

export type UISnapshot = {
 version: string;
 status: string;
 mode: string;
 mode_label: string;
 protection_on: boolean;
 notify: boolean;
 notify_level: string;
 quiet_while_away?: boolean;
 away?: boolean;
 away_unread?: number;
 away_digest?: {
  pending?: boolean;
  blocks?: number;
  waiting?: number;
  hosts?: string[];
  waiting_hosts?: string[];
 };
 notify_snooze_until?: string;
 notify_snooze_active?: boolean;
 quiet_overnight?: boolean;
 sound_only_answer?: boolean;
 system_banners?: boolean;
 respect_fullscreen?: boolean;
 silent_when_open?: boolean;
 decision_timeout_sec: number;
 reask_interval_sec: number;
 protect_paused_until?: string;
 protect_pause_last?: string;
 timed_allows: TimedRule[];
 timed_denies: TimedRule[];
 ask_mode: boolean;
 autostart: boolean;
 always_allow: string[];
 remembered_keeps: string[];
 last_deny_host: string;
 last_deny_url: string;
 last_deny_summary: string;
 last_deny_process?: string;
 blocked_today: number;
 your_setup_shown: boolean;
 setup_done: boolean;
 policy_profile?: string;
 helper_ok?: boolean;
 protect_confirm_title?: string;
 protect_confirm_body?: string;
 new_denials: number;
 audit_path: string;
 log_dir: string;
 dismissed_tips: string[];
 ask_paused: boolean;
 ask_paused_until?: string;
 needs_uxv2_migration?: boolean;
 problems_alert: boolean;
 your_setup_text: string;
 checklist_done: boolean;
 update_available?: boolean;
 update_version?: string;
 update_url?: string;
 update_notes?: string;
 account_signed_in?: boolean;
 account_email?: string;
 account_trust_line?: string;
  sync_enabled?: boolean;
  computer_available?: boolean;
  agents_running?: number;
  threat_lists_warn?: boolean;
  notice?: string;
};

export type UpdateCheckView = {
 newer: boolean;
 local: string;
 remote_version?: string;
 url?: string;
 notes?: string;
 message: string;
 checked_at?: string;
};

export type ThreatFeedView = {
 id: string;
 label: string;
 category: string;
 enabled: boolean;
 active: boolean;
 entry_count: number;
 last_success?: string;
 last_error?: string;
 homepage?: string;
 advanced?: boolean;
};

export type ThreatListsView = {
 poll_hours: number;
 block_phishing: boolean;
 block_malware: boolean;
 block_stronger: boolean;
 needs_attention: boolean;
 feeds: ThreatFeedView[];
 advanced_feeds: ThreatFeedView[];
 about_note: string;
 stronger_warning: string;
 advanced_warning: string;
 product_exceptions: number;
 product_exception_hosts: string[];
 product_exceptions_note: string;
};

export type ProblemsView = {
  last_error: string;
  last_deny_host: string;
  last_deny_url: string;
  last_deny_summary: string;
  last_deny_process?: string;
  control_ok: boolean;
  proxyd_running: boolean;
  session_running: boolean;
  ca_present: boolean;
  clipboard_ok: boolean;
  helper_ok?: boolean;
  protection_on?: boolean;
  unhealthy?: boolean;
  threat_lists_warn?: boolean;
  log_dir: string;
  audit_path: string;
  status: string;
  mode?: string;
  mode_label: string;
  policy_profile?: string;
  protect_confirm_title?: string;
  protect_confirm_body?: string;
  protect_paused_until?: string;
  protect_pause_last?: string;
  agents_running?: number;
  computer_available?: boolean;
  update_available?: boolean;
  update_version?: string;
  update_url?: string;
};

export type AppliedPack = {
 id: string;
 version: number;
 hosts: string[];
};

export type AllowPack = {
 id: string;
 version: number;
 name: string;
 description: string;
 hosts: string[];
};

export type AgentProfile = {
 id: string;
 name: string;
 command: string[];
 workdir?: string;
 preset: string;
 extra_allow?: string[];
 pending_once?: string[];
 applied_packs?: AppliedPack[];
 ask_mode: boolean;
 notify: boolean;
 tls_mode?: string;
 require_isolation?: boolean;
 sandbox?: string;
 learning: { enabled: boolean; started_at?: string; duration_hours?: number };
};

export type ProfileView = AgentProfile & { running: boolean; pid?: number };

type Bridge = {
 GetUISnapshot(): Promise<UISnapshot>;
  MarkYourSetupShown(): Promise<void>;
  UIClearNotice(): Promise<void>;
 ListDenials(q: DenialQuery): Promise<DenialView[]>;
 UIAlwaysAllowHost(host: string, reason: string): Promise<void>;
 UIAlwaysAllowHostFrom(host: string, reason: string, process: string): Promise<void>;
 UIForgetKeep(host: string, reason: string): Promise<void>;
 UIClearAllKeeps(): Promise<void>;
 UIRemoveAlwaysAllow(host: string): Promise<void>;
 UISetNotify(on: boolean): Promise<void>;
 UISetNotifyLevel(level: string): Promise<void>;
 UISetNotifyUIFocused(on: boolean): void;
 UISetQuietWhileAway(on: boolean): Promise<void>;
 UIClearAwayUnread(): Promise<void>;
 UIDismissAwayDigest(): Promise<void>;
 UISetNotifySnooze(choice: string): Promise<void>;
 UISetQuietOvernight(on: boolean): Promise<void>;
 UISetSoundOnlyAnswer(on: boolean): Promise<void>;
 UISetSystemBanners(on: boolean): Promise<void>;
 UISetRespectFullscreen(on: boolean): Promise<void>;
 UISetSilentWhenOpen(on: boolean): Promise<void>;
 UISetDecisionTimeoutSec(sec: number): Promise<void>;
 UISetReaskIntervalSec(sec: number): Promise<void>;
 UIRemoveTimedAllow(host: string): Promise<void>;
 UIRemoveTimedDeny(host: string, reason: string): Promise<void>;
 UISetAutostart(on: boolean): Promise<void>;
 UIEnableSafeDesktop(): Promise<void>;
 UIEnableAgentsOnly(): Promise<void>;
 UIOnboardingNotNow(): Promise<void>;
 UIOnboardingAgents(): Promise<void>;
 UIResetSetup(): Promise<void>;
 UISwitchSafe(): Promise<void>;
 UIStopProtection(): Promise<void>;
 UIStopProtectionWithChoice(choice: string): Promise<void>;
 GetProblems(): Promise<ProblemsView>;
 UIOpenLogs(): Promise<void>;
 UICopyLastError(): Promise<string>;
 UIRetryProtect(): Promise<void>;
 ListProfileViews(): Promise<ProfileView[]>;
 UISaveProfile(p: AgentProfile): Promise<void>;
 ListAllowPacks(): Promise<AllowPack[]>;
 UIApplyAllowPack(profileID: string, packID: string): Promise<string[]>;
 UIUndoAllowPack(profileID: string, packID: string): Promise<string[]>;
 UISuggestAllowPack(name: string, command: string[]): Promise<string>;
 UIDeleteProfile(id: string): Promise<void>;
 UIStartProfile(id: string): Promise<void>;
 UIStopProfile(id: string): Promise<void>;
 UIPinLearning(id: string): Promise<void>;
 UIDiscardLearning(id: string): Promise<void>;
 TipDismissed(id: string): Promise<boolean>;
 UIDismissTip(id: string): Promise<void>;
 UIPauseAsks(): Promise<string>;
 UIResumeAsks(): Promise<string>;
 UIMigrateUXv2(switchToSafe: boolean): Promise<void>;
 UIUndoLastAlwaysAllow(): Promise<string>;
 UITestProtection(): Promise<string>;
 UIBulkAlwaysAllow(hosts: string[]): Promise<string>;
 GetThreatLists(): Promise<ThreatListsView>;
 UISetBlockPhishing(on: boolean): Promise<void>;
 UISetBlockMalware(on: boolean): Promise<void>;
 UISetBlockStronger(on: boolean): Promise<void>;
 UISetAdvancedThreatFeed(id: string, on: boolean): Promise<void>;
 UISetThreatPollHours(hours: number): Promise<void>;
 UIRefreshThreatLists(): Promise<ThreatListsView>;
 UICheckForUpdates(): Promise<UpdateCheckView>;
 UIOpenUpdateURL(): Promise<void>;
 GetAccountView(): Promise<{
 signed_in: boolean;
 email?: string;
 api_base?: string;
 sync_enabled: boolean;
 trust_line: string;
 }>;
 UIRequestMagicLink(email: string): Promise<void>;
 UIVerifyMagicLink(email: string, code: string): Promise<void>;
 UISignOut(): Promise<void>;
 UIDeleteCloudData(): Promise<void>;
 UISetAccountAPIBase(base: string): Promise<void>;
 UISetSyncEnabled(on: boolean): Promise<void>;
 UISyncNow(): Promise<{ ok: boolean; message: string; pushed?: boolean; pulled?: boolean }>;
 UIReady(): Promise<void>;
 UIResolveDecision(id: string, action: string): Promise<void>; // rejects if expired
 UIQuitNeedsChoice(): Promise<boolean>;
 UIQuit(choice: string): Promise<void>;
};

declare global {
 interface Window {
 go?: { main?: { Bridge?: Bridge } };
 runtime?: {
 EventsOn(event: string, callback: (...args: unknown[]) => void): () => void;
 };
 }
}

function bridge(): Bridge {
 const b = window.go?.main?.Bridge;
 if (!b) {
 throw new Error("Wails Bridge not available (open via denyout-desktop)");
 }
 return b;
}

export const api = {
 snapshot: () => bridge().GetUISnapshot(),
  markYourSetup: () => bridge().MarkYourSetupShown(),
  clearNotice: () => bridge().UIClearNotice(),
 listDenials: (q: DenialQuery) => bridge().ListDenials(q),
 alwaysAllow: (host: string, reason = "", process = "") =>
 process
 ? bridge().UIAlwaysAllowHostFrom(host, reason, process)
 : bridge().UIAlwaysAllowHost(host, reason),
 forgetKeep: (host: string, reason: string) => bridge().UIForgetKeep(host, reason),
 clearKeeps: () => bridge().UIClearAllKeeps(),
 removeAlways: (host: string) => bridge().UIRemoveAlwaysAllow(host),
 setNotify: (on: boolean) => bridge().UISetNotify(on),
 setNotifyLevel: (level: string) => bridge().UISetNotifyLevel(level),
 setNotifyUIFocused: (on: boolean) => {
 try {
 bridge().UISetNotifyUIFocused(on);
 } catch {
 /* browser preview without Wails */
 }
 },
 setQuietWhileAway: (on: boolean) => bridge().UISetQuietWhileAway(on),
 clearAwayUnread: () => bridge().UIClearAwayUnread(),
 dismissAwayDigest: () => bridge().UIDismissAwayDigest(),
 setNotifySnooze: (choice: string) => bridge().UISetNotifySnooze(choice),
 setQuietOvernight: (on: boolean) => bridge().UISetQuietOvernight(on),
 setSoundOnlyAnswer: (on: boolean) => bridge().UISetSoundOnlyAnswer(on),
 setSystemBanners: (on: boolean) => bridge().UISetSystemBanners(on),
 setRespectFullscreen: (on: boolean) => bridge().UISetRespectFullscreen(on),
 setSilentWhenOpen: (on: boolean) => bridge().UISetSilentWhenOpen(on),
 setDecisionTimeout: (sec: number) => bridge().UISetDecisionTimeoutSec(sec),
 setReaskInterval: (sec: number) => bridge().UISetReaskIntervalSec(sec),
 removeTimedAllow: (host: string) => bridge().UIRemoveTimedAllow(host),
 removeTimedDeny: (host: string, reason: string) => bridge().UIRemoveTimedDeny(host, reason),
 setAutostart: (on: boolean) => bridge().UISetAutostart(on),
 enableSafe: () => bridge().UIEnableSafeDesktop(),
 enableAgents: () => bridge().UIEnableAgentsOnly(),
 onboardingNotNow: () => bridge().UIOnboardingNotNow(),
 onboardingAgents: () => bridge().UIOnboardingAgents(),
 resetSetup: () => bridge().UIResetSetup(),
 switchSafe: () => bridge().UISwitchSafe(),
 stopProtection: () => bridge().UIStopProtection(),
 stopProtectionWithChoice: (choice: string) => bridge().UIStopProtectionWithChoice(choice),
 problems: () => bridge().GetProblems(),
 openLogs: () => bridge().UIOpenLogs(),
 copyLastError: () => bridge().UICopyLastError(),
 retryProtect: () => bridge().UIRetryProtect(),
 profiles: () => bridge().ListProfileViews(),
 saveProfile: (p: AgentProfile) => bridge().UISaveProfile(p),
 listAllowPacks: () => bridge().ListAllowPacks(),
 applyAllowPack: (profileID: string, packID: string) =>
 bridge().UIApplyAllowPack(profileID, packID),
 undoAllowPack: (profileID: string, packID: string) =>
 bridge().UIUndoAllowPack(profileID, packID),
 suggestAllowPack: (name: string, command: string[]) =>
 bridge().UISuggestAllowPack(name, command),
 deleteProfile: (id: string) => bridge().UIDeleteProfile(id),
 startProfile: (id: string) => bridge().UIStartProfile(id),
 stopProfile: (id: string) => bridge().UIStopProfile(id),
 pinLearning: (id: string) => bridge().UIPinLearning(id),
 discardLearning: (id: string) => bridge().UIDiscardLearning(id),
 tipDismissed: (id: string) => bridge().TipDismissed(id),
 dismissTip: (id: string) => bridge().UIDismissTip(id),
 pauseAsks: () => bridge().UIPauseAsks(),
 resumeAsks: () => bridge().UIResumeAsks(),
 migrateUXv2: (switchToSafe: boolean) => bridge().UIMigrateUXv2(switchToSafe),
 undoLastAlways: () => bridge().UIUndoLastAlwaysAllow(),
 testProtection: () => bridge().UITestProtection(),
 bulkAlwaysAllow: (hosts: string[]) => bridge().UIBulkAlwaysAllow(hosts) as Promise<string>,
 threatLists: () => bridge().GetThreatLists(),
 setBlockPhishing: (on: boolean) => bridge().UISetBlockPhishing(on),
 setBlockMalware: (on: boolean) => bridge().UISetBlockMalware(on),
 setBlockStronger: (on: boolean) => bridge().UISetBlockStronger(on),
 setAdvancedThreatFeed: (id: string, on: boolean) =>
 bridge().UISetAdvancedThreatFeed(id, on),
 setThreatPollHours: (hours: number) => bridge().UISetThreatPollHours(hours),
 refreshThreatLists: () => bridge().UIRefreshThreatLists(),
 checkForUpdates: () => bridge().UICheckForUpdates(),
 openUpdateURL: () => bridge().UIOpenUpdateURL(),
 accountView: () => bridge().GetAccountView(),
 requestMagicLink: (email: string) => bridge().UIRequestMagicLink(email),
 verifyMagicLink: (email: string, code: string) => bridge().UIVerifyMagicLink(email, code),
 signOut: () => bridge().UISignOut(),
 deleteCloudData: () => bridge().UIDeleteCloudData(),
 setAccountAPIBase: (base: string) => bridge().UISetAccountAPIBase(base),
 setSyncEnabled: (on: boolean) => bridge().UISetSyncEnabled(on),
 syncNow: () => bridge().UISyncNow(),
 ready: () => bridge().UIReady(),
 resolveDecision: (id: string, action: string) => bridge().UIResolveDecision(id, action),
 quitNeedsChoice: () => bridge().UIQuitNeedsChoice(),
 quit: (choice: string) => bridge().UIQuit(choice),
 onNavigate: (cb: (route: string) => void) => {
 if (!window.runtime?.EventsOn) return () => undefined;
 return window.runtime.EventsOn("navigate", (r) => cb(String(r ?? "")));
 },
 onDecision: (cb: (payload: Record<string, unknown>) => void) => {
 if (!window.runtime?.EventsOn) return () => undefined;
 return window.runtime.EventsOn("decision", (raw) => {
 const p = (raw ?? {}) as Record<string, unknown>;
 cb(p);
 });
 },
 /** Bridge timed out — drop a zombie Decision modal (background-tab throttle). */
 onDecisionDone: (cb: (id: string) => void) => {
 if (!window.runtime?.EventsOn) return () => undefined;
 return window.runtime.EventsOn("decision-done", (raw) => {
 const p = (raw ?? {}) as Record<string, unknown>;
 cb(String(p.id ?? ""));
 });
 },
};
