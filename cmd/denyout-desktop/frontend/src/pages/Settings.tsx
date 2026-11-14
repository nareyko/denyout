import { useEffect, useMemo, useState } from "react";
import { Tip, tipGone } from "../components/Tip";
import { api, ThreatListsView, UISnapshot } from "../wails";

type Tab = "basic" | "advanced";

export function Settings({
  snap: snapProp,
  onChanged,
  tipsEnabled = true,
  initialTab,
  focusSection,
}: {
  snap?: UISnapshot | null;
  onChanged?: () => void;
  tipsEnabled?: boolean;
  initialTab?: Tab;
  focusSection?: string;
}) {
  const [snap, setSnap] = useState<UISnapshot | null>(snapProp ?? null);
  const [threats, setThreats] = useState<ThreatListsView | null>(null);
  const [threatBusy, setThreatBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [filter, setFilter] = useState("");
  const [find, setFind] = useState("");
  const [tab, setTab] = useState<Tab>(initialTab ?? "basic");
  const [acctEmail, setAcctEmail] = useState("");
  const [acctCode, setAcctCode] = useState("");
  const [apiBase, setApiBase] = useState("");

  async function reloadThreats() {
    const t = await api.threatLists();
    setThreats(t);
  }

  async function reload() {
    const s = await api.snapshot();
    setSnap(s);
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
    void reload().catch((e) => setMsg(String(e)));
  }, []);
  useEffect(() => {
    if (initialTab) setTab(initialTab);
  }, [initialTab]);

  useEffect(() => {
    if (!focusSection) return;
    const el = document.getElementById(`settings-${focusSection}`);
    el?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [focusSection, tab]);

  const findQ = find.trim().toLowerCase();

  const showSection = useMemo(() => {
    return (keys: string[]) => {
      if (!findQ) return true;
      return keys.some((k) => k.toLowerCase().includes(findQ));
    };
  }, [findQ]);

  if (!snap) {
    return <p className="muted">{msg || "Loading…"}</p>;
  }

  const allows = (snap.always_allow || []).filter((h) =>
    h.toLowerCase().includes(filter.toLowerCase()),
  );
  const dismissed = snap.dismissed_tips;

  function enableAgentsOnly() {
    if (
      !confirm(
        "Turn on Agents only for the whole computer?\n\nMessengers and many sites may stop working. Prefer My agents for AI tools.\n\nOnly continue if you understand the risk.",
      )
    ) {
      return;
    }
    void api.enableAgents().then(reload).catch((e) => setMsg(String(e)));
  }

  return (
    <div className="stack">
      {msg && <p className="muted">{msg}</p>}

      <div className="toolbar">
        <input
          className="settings-find"
          placeholder="Find a setting…"
          value={find}
          onChange={(e) => {
            const v = e.target.value;
            setFind(v);
            const q = v.toLowerCase();
            if (
              q.includes("always") ||
              q.includes("keep") ||
              q.includes("ask") ||
              q.includes("diagn") ||
              q.includes("test") ||
              q.includes("agents only") ||
              q.includes("oisd") ||
              q.includes("steven") ||
              q.includes("account") ||
              q.includes("sign") ||
              q.includes("sync") ||
              q.includes("advanced")
            ) {
              setTab("advanced");
            } else if (
              q.includes("protect") ||
              q.includes("notif") ||
              q.includes("autostart") ||
              q.includes("threat") ||
              q.includes("phish") ||
              q.includes("malware") ||
              q.includes("stronger") ||
              q.includes("hagezi") ||
              q.includes("basic")
            ) {
              setTab("basic");
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

      {tab === "basic" ? (
        <>
          {tipsEnabled && (
            <Tip
              id="settings-basic"
              dismissed={tipGone(dismissed, "settings-basic")}
              onDismiss={onChanged}
            >
              Basic is On/Off, notifications, and autostart. Allowed sites and rare options live
              under Advanced.
            </Tip>
          )}

          {showSection(["protection", "protect", "safe", "off"]) && (
            <section className="card" id="settings-protection">
              <h2>Protection</h2>
              <p className="muted">
                Same On/Off as Home. Rare options (allowed sites, Agents only) are under Advanced.
              </p>
              <div className="row-actions">
                {snap.mode === "agents" ? (
                  <button className="btn primary" onClick={() => void api.switchSafe().then(reload)}>
                    Switch to Protect computer
                  </button>
                ) : (
                  <button
                    className="btn primary"
                    onClick={() => void api.enableSafe().then(reload).catch((e) => setMsg(String(e)))}
                  >
                    Turn on Protect computer
                  </button>
                )}
                <button className="btn danger" onClick={() => void api.stopProtection().then(reload)}>
                  Turn off
                </button>
              </div>
              <p style={{ marginTop: "0.65rem" }}>
                Now:{" "}
                <strong>
                  {snap.protection_on && snap.mode === "safe"
                    ? "Protected"
                    : snap.mode_label || "Off"}
                </strong>
              </p>
            </section>
          )}

          {showSection(["notification", "notify", "toast", "quiet"]) && (
            <section className="card" id="settings-notifications">
              <h2>Notifications</h2>
              <p className="muted">
                Decision dialogs always show when Protect is on. This controls OS banners only.
              </p>
              <label>
                Level{" "}
                <select
                  value={snap.notify_level || "normal"}
                  onChange={(e) =>
                    void api
                      .setNotifyLevel(e.target.value)
                      .then(reload)
                      .catch((err) => setMsg(String(err)))
                  }
                >
                  <option value="quiet">Quiet — failures only</option>
                  <option value="normal">Normal — Keep repeats, Undo, pause ended</option>
                  <option value="detailed">Detailed — same as Normal for now</option>
                </select>
              </label>
              <label style={{ display: "block", marginTop: "0.5rem" }}>
                Decision timeout (seconds){" "}
                <input
                  type="number"
                  min={5}
                  max={120}
                  value={snap.decision_timeout_sec || 15}
                  onChange={(e) =>
                    void api
                      .setDecisionTimeout(Number(e.target.value) || 15)
                      .then(reload)
                      .catch((err) => setMsg(String(err)))
                  }
                />
              </label>
              <label style={{ display: "block", marginTop: "0.5rem" }}>
                Re-ask / Keep-repeat interval (seconds){" "}
                <input
                  type="number"
                  min={15}
                  max={3600}
                  value={snap.reask_interval_sec || 60}
                  onChange={(e) =>
                    void api
                      .setReaskInterval(Number(e.target.value) || 60)
                      .then(reload)
                      .catch((err) => setMsg(String(err)))
                  }
                />
              </label>
            </section>
          )}

          {showSection(["autostart", "login", "launch"]) && (
            <section className="card" id="settings-autostart">
              <h2>Autostart</h2>
              <label>
                <input
                  type="checkbox"
                  checked={snap.autostart}
                  onChange={(e) =>
                    void api
                      .setAutostart(e.target.checked)
                      .then(reload)
                      .catch((e) => setMsg(String(e)))
                  }
                />{" "}
                Launch DenyOut at login
              </label>
            </section>
          )}

          {showSection([
            "threat",
            "phish",
            "malware",
            "urlhaus",
            "list",
            "block known",
            "refresh",
          ]) && (
            <section className="card" id="settings-threat-lists">
              <h2>Threat lists</h2>
              <p className="muted">
                {threats?.about_note ||
                  "Block domains on known phishing and malware lists. Downloads stay on this computer."}
              </p>
              {threats?.needs_attention && (
                <p className="warn-box" style={{ marginTop: "0.5rem" }}>
                  Lists look outdated (over a week). Use Refresh now, or check your network.
                </p>
              )}
              <label style={{ display: "block", marginTop: "0.5rem" }}>
                <input
                  type="checkbox"
                  checked={!!threats?.block_phishing}
                  disabled={threatBusy || !threats}
                  onChange={(e) => {
                    const on = e.target.checked;
                    setThreatBusy(true);
                    void api
                      .setBlockPhishing(on)
                      .then(reloadThreats)
                      .catch((err) => setMsg(String(err)))
                      .finally(() => setThreatBusy(false));
                  }}
                />{" "}
                Block known phishing
              </label>
              <label style={{ display: "block", marginTop: "0.35rem" }}>
                <input
                  type="checkbox"
                  checked={!!threats?.block_malware}
                  disabled={threatBusy || !threats}
                  onChange={(e) => {
                    const on = e.target.checked;
                    setThreatBusy(true);
                    void api
                      .setBlockMalware(on)
                      .then(reloadThreats)
                      .catch((err) => setMsg(String(err)))
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
                  checked={!!threats?.block_stronger}
                  disabled={threatBusy || !threats || !threats?.block_malware}
                  onChange={(e) => {
                    const on = e.target.checked;
                    if (on) {
                      const warn =
                        threats?.stronger_warning ||
                        "Stronger adds a large extra list and may break sites. Continue?";
                      if (!confirm(warn)) {
                        return;
                      }
                    }
                    setThreatBusy(true);
                    void api
                      .setBlockStronger(on)
                      .then(reloadThreats)
                      .catch((err) => setMsg(String(err)))
                      .finally(() => setThreatBusy(false));
                  }}
                />{" "}
                Including stronger threat list
              </label>
              <p className="muted" style={{ marginLeft: "1.25rem", marginTop: "0.15rem" }}>
                Optional HaGeZi list — larger, may block more. Use Allow if something breaks.
              </p>
              <label style={{ display: "block", marginTop: "0.65rem" }}>
                Update every (hours){" "}
                <input
                  type="number"
                  min={6}
                  max={168}
                  value={threats?.poll_hours || 24}
                  disabled={threatBusy || !threats}
                  onChange={(e) => {
                    const h = Number(e.target.value) || 24;
                    setThreatBusy(true);
                    void api
                      .setThreatPollHours(h)
                      .then(reloadThreats)
                      .catch((err) => setMsg(String(err)))
                      .finally(() => setThreatBusy(false));
                  }}
                />
              </label>
              <div className="row-actions" style={{ marginTop: "0.65rem" }}>
                <button
                  type="button"
                  className="btn"
                  disabled={threatBusy || !threats}
                  onClick={() => {
                    setThreatBusy(true);
                    void api
                      .refreshThreatLists()
                      .then((t) => setThreats(t))
                      .catch((err) => setMsg(String(err)))
                      .finally(() => setThreatBusy(false));
                  }}
                >
                  {threatBusy ? "Working…" : "Refresh now"}
                </button>
              </div>
              {(threats?.feeds || []).length > 0 && (
                <ul style={{ marginTop: "0.75rem" }}>
                  {threats!.feeds.map((f) => (
                    <li key={f.id} className="muted" style={{ marginBottom: "0.35rem" }}>
                      <span className="mono">{f.label}</span>
                      {": "}
                      {f.enabled ? (f.active ? "on" : "waiting for first download") : "off"}
                      {f.entry_count > 0 ? ` · ${f.entry_count} domains` : ""}
                      {f.last_success ? ` · updated ${f.last_success}` : ""}
                      {f.last_error ? ` · ${f.last_error}` : ""}
                    </li>
                  ))}
                </ul>
              )}
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
              Advanced lists, diagnostics, and the whole-PC Agents only mode. Changes here affect what
              DenyOut allows permanently.
            </Tip>
          )}

          {showSection(["account", "sign", "sync", "email", "login"]) && (
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
                          .catch((err) => setMsg(String(err)))
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
                            setMsg(r.message);
                            return reload();
                          })
                          .catch((e) => setMsg(String(e)))
                      }
                    >
                      Sync now
                    </button>
                    <button
                      className="btn"
                      onClick={() => void api.signOut().then(reload).catch((e) => setMsg(String(e)))}
                    >
                      Sign out
                    </button>
                    <button
                      className="btn danger"
                      onClick={() => {
                        if (
                          !confirm(
                            "Delete your DenyOut cloud account and synced settings? Local Protect settings stay on this computer.",
                          )
                        ) {
                          return;
                        }
                        void api
                          .deleteCloudData()
                          .then(() => {
                            setMsg("Cloud account deleted. Local settings unchanged.");
                            return reload();
                          })
                          .catch((e) => setMsg(String(e)));
                      }}
                    >
                      Delete cloud data
                    </button>
                  </div>
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
                              setMsg(
                                "If the API is reachable, check email (or API logs in local stub) for a one-time code.",
                              ),
                            )
                            .catch((e) => setMsg(String(e)))
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
                              setMsg("Signed in.");
                              return reload();
                            })
                            .catch((e) => setMsg(String(e)))
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
                            .then(() => setMsg("API base saved."))
                            .catch((e) => setMsg(String(e)))
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

          {showSection([
            "always allow",
            "always-allow",
            "host",
            "keep",
            "remembered",
            "silenced",
            "sites",
            "allowed",
          ]) && (
            <section className="card" id="settings-always-allow">
              <h2 id="settings-keeps">Sites I’ve allowed or silenced</h2>
              <p className="muted">
                Allowed sites skip blocks. Silenced entries stay quiet after you chose Keep blocked.
              </p>
              <div className="toolbar">
                <input
                  placeholder="Filter hosts…"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                />
                <button
                  className="btn"
                  onClick={() =>
                    void api.undoLastAlways().then(reload).catch((e) => setMsg(String(e)))
                  }
                >
                  Undo last allow
                </button>
              </div>

              <h3 className="settings-subhead">Allowed</h3>
              {allows.length === 0 ? (
                <p className="muted">None yet. Use History → Allow this site on a block.</p>
              ) : (
                <ul>
                  {allows.map((h) => (
                    <li key={h} className="row-actions" style={{ marginBottom: "0.35rem" }}>
                      <span className="mono">{h}</span>
                      <button
                        className="btn danger"
                        onClick={() =>
                          void api.removeAlways(h).then(reload).catch((e) => setMsg(String(e)))
                        }
                      >
                        Remove
                      </button>
                    </li>
                  ))}
                </ul>
              )}

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
                          <span className="muted">until {t.expires_at}</span>
                        </span>
                        <button
                          className="btn"
                          onClick={() =>
                            void api.removeTimedAllow(t.host).then(reload).catch((e) => setMsg(String(e)))
                          }
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
                          {t.reason ? `|${t.reason}` : ""}{" "}
                          <span className="muted">until {t.expires_at}</span>
                        </span>
                        <button
                          className="btn"
                          onClick={() =>
                            void api
                              .removeTimedDeny(t.host, t.reason || "")
                              .then(reload)
                              .catch((e) => setMsg(String(e)))
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
                      .map((k) => (
                        <li key={k} className="row-actions" style={{ marginBottom: "0.35rem" }}>
                          <span className="mono">{k}</span>
                          <button
                            className="btn"
                            onClick={() =>
                              void api.forgetKeep(k, "").then(reload).catch((e) => setMsg(String(e)))
                            }
                          >
                            Clear
                          </button>
                        </li>
                      ))}
                  </ul>
                  <button
                    className="btn danger"
                    onClick={() => void api.clearKeeps().then(reload).catch((e) => setMsg(String(e)))}
                  >
                    Clear all silenced
                  </button>
                </>
              )}
            </section>
          )}

          {showSection([
            "oisd",
            "steven",
            "ads",
            "tracker",
            "advanced list",
            "optional list",
          ]) && (
            <section className="card" id="settings-advanced-lists">
              <h2>Optional lists (not core)</h2>
              <p className="muted">
                {threats?.advanced_warning ||
                  "Broader ad/tracker lists — not DenyOut’s main job. Default off."}
              </p>
              {(threats?.advanced_feeds || []).length === 0 ? (
                <p className="muted">Unavailable.</p>
              ) : (
                <ul style={{ listStyle: "none", padding: 0 }}>
                  {threats!.advanced_feeds.map((f) => (
                    <li key={f.id} style={{ marginBottom: "0.5rem" }}>
                      <label>
                        <input
                          type="checkbox"
                          checked={!!f.enabled}
                          disabled={threatBusy || !threats}
                          onChange={(e) => {
                            const on = e.target.checked;
                            if (on) {
                              const warn =
                                threats?.advanced_warning ||
                                "Broader list may break sites. Continue?";
                              if (!confirm(warn)) return;
                            }
                            setThreatBusy(true);
                            void api
                              .setAdvancedThreatFeed(f.id, on)
                              .then(reloadThreats)
                              .catch((err) => setMsg(String(err)))
                              .finally(() => setThreatBusy(false));
                          }}
                        />{" "}
                        {f.label}
                      </label>
                      <div className="muted" style={{ marginLeft: "1.25rem", fontSize: "0.92em" }}>
                        {f.enabled
                          ? f.active
                            ? `on · ${f.entry_count} domains`
                            : "waiting for first download"
                          : "off"}
                        {f.last_error ? ` · ${f.last_error}` : ""}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          )}

          {showSection(["agents only", "allowlist", "whole"]) && (
            <section className="card warn-box" id="settings-agents-only">
              <h2>Agents only (whole PC)</h2>
              <p>
                Almost nobody needs this. It puts the entire computer on an allowlist — messengers
                and many sites may stop working. Prefer My agents for AI tools.
              </p>
              <button className="btn danger" onClick={enableAgentsOnly}>
                Enable Agents only (whole PC)…
              </button>
            </section>
          )}

          {showSection(["ask", "resume", "pause"]) && (
            <section className="card" id="settings-asks">
              <h2>Asks</h2>
              <p className="muted">
                After many Ask prompts, DenyOut may pause new-host asks. Resume when you are ready.
              </p>
              <button
                className="btn"
                disabled={!snap.ask_paused}
                onClick={() => void api.resumeAsks().then(reload)}
              >
                {snap.ask_paused ? "Resume asks" : "Asks not paused"}
              </button>
            </section>
          )}

          {showSection(["diagn", "log", "audit", "test", "version", "update"]) && (
            <section className="card" id="settings-diagnostics">
              <h2>Diagnostics</h2>
              <p className="mono muted">Version {snap.version || "dev"}</p>
              <p className="mono muted">Logs: {snap.log_dir}</p>
              <p className="mono muted">Audit: {snap.audit_path}</p>
              <div className="row-actions">
                <button
                  className="btn"
                  onClick={() => void api.openLogs().catch((e) => setMsg(String(e)))}
                >
                  Open diagnostics folder
                </button>
                <button
                  className="btn"
                  onClick={() => void api.testProtection().catch((e) => setMsg(String(e)))}
                >
                  Test protection…
                </button>
                <button
                  className="btn"
                  onClick={() =>
                    void api
                      .checkForUpdates()
                      .then((v) => {
                        setMsg(v.message);
                        return reload();
                      })
                      .catch((e) => setMsg(String(e)))
                  }
                >
                  Check for updates
                </button>
                {snap.update_available && snap.update_url ? (
                  <button
                    className="btn primary"
                    onClick={() => void api.openUpdateURL().catch((e) => setMsg(String(e)))}
                  >
                    Open update {snap.update_version || ""}
                  </button>
                ) : null}
              </div>
              <p className="muted" style={{ marginTop: "0.75rem" }}>
                Update checks use a public version file — no sign-in. Protect still works if the check
                fails.
              </p>
              <p className="muted" style={{ marginTop: "0.75rem" }}>
                Privacy: decisions stay on this computer.
              </p>
            </section>
          )}
        </>
      )}
    </div>
  );
}
