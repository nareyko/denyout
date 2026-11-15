import { useCallback, useEffect, useMemo, useState } from "react";
import { ConfirmModal } from "../components/ConfirmModal";
import { Tip, tipGone } from "../components/Tip";
import { api, DenialView, UISnapshot } from "../wails";

const REASONS: { value: string; label: string }[] = [
 { value: "", label: "All reasons" },
 { value: "secret_in_url", label: "Secret in link" },
 { value: "secret_in_header", label: "Secret in header" },
 { value: "secret_in_body", label: "Secret in body" },
 { value: "canary_detected", label: "Canary detected" },
 { value: "host_denied", label: "Host denied" },
 { value: "unsafe_ip", label: "Unsafe IP" },
 { value: "ip_literal", label: "Raw IP (agents)" },
 { value: "threat_list", label: "Threat list" },
 { value: "host_not_allowed", label: "Host not allowed" },
];

function looksLikeIP(host: string): boolean {
 const h = (host || "").trim();
 if (!h) return false;
 if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
 if (h.includes(":")) return true;
 return false;
}

export function Activity({
 snap,
 onTipDismiss,
 tipsEnabled = true,
 onOpenSettingsAdvanced,
}: {
 snap?: UISnapshot | null;
 onTipDismiss?: () => void;
 tipsEnabled?: boolean;
 onOpenSettingsAdvanced?: () => void;
}) {
 const [rows, setRows] = useState<DenialView[]>([]);
 const [search, setSearch] = useState("");
 const [reason, setReason] = useState("");
 const [rememberedOnly, setRememberedOnly] = useState(false);
 const [showFilters, setShowFilters] = useState(false);
 const [groupByHost, setGroupByHost] = useState(false);
 const [selectMode, setSelectMode] = useState(false);
 const [selected, setSelected] = useState<DenialView | null>(null);
 const [checked, setChecked] = useState<Record<string, boolean>>({});
 const [err, setErr] = useState("");
 const [info, setInfo] = useState("");
 const [busy, setBusy] = useState(false);
 const [allowRow, setAllowRow] = useState<DenialView | null>(null);
 const [allowBusy, setAllowBusy] = useState(false);

 const dismissed = snap?.dismissed_tips;

 const load = useCallback(async (opts?: { preserveErr?: boolean }) => {
 setBusy(true);
 if (!opts?.preserveErr) setErr("");
 try {
 const list = await api.listDenials({
 search: showFilters ? search : "",
 reason: showFilters ? reason : "",
 remembered_only: showFilters && rememberedOnly,
 limit: 200,
 });
 setRows(list ?? []);
 setSelected((prev) => {
 if (!prev) return null;
 return (list ?? []).find((r) => r.id === prev.id) ?? null;
 });
 } catch (e) {
 if (!opts?.preserveErr) setErr(String(e));
 } finally {
 setBusy(false);
 }
 }, [search, reason, rememberedOnly, showFilters]);

 useEffect(() => {
 void load();
 }, [load]);

 useEffect(() => {
 const poll = window.setInterval(() => {
 // Poll must not wipe Allow / bulk failure under ConfirmModal.
 void load({ preserveErr: true });
 }, 4000);
 return () => window.clearInterval(poll);
 }, [load]);

 const displayRows = useMemo(() => {
 if (!groupByHost) return rows;
 const best = new Map<string, DenialView>();
 for (const r of rows) {
 const key = (r.host || "").toLowerCase() || r.id;
 const prev = best.get(key);
 if (!prev || r.ts > prev.ts) best.set(key, r);
 }
 return Array.from(best.values()).sort((a, b) => (a.ts < b.ts ? 1 : -1));
 }, [rows, groupByHost]);

 const selectedHosts = useMemo(() => {
 const hosts = new Set<string>();
 for (const r of displayRows) {
 if (checked[r.id] && r.host) hosts.add(r.host);
 }
 return Array.from(hosts);
 }, [checked, displayRows]);

 function denialReason(row: DenialView): string {
 return row.primary_reason || row.reasons?.[0] || "";
 }

 function requestAlwaysAllow(row: DenialView) {
 if (looksLikeIP(row.host)) {
 setErr("Raw IP addresses cannot be always-allowed.");
 return;
 }
 setAllowRow(row);
 }

 async function confirmAlwaysAllow() {
 const row = allowRow;
 if (!row) return;
 const code = denialReason(row);
 setAllowBusy(true);
 setErr("");
 try {
 await api.alwaysAllow(row.host, code, row.process || "");
 setAllowRow(null);
 setErr("");
 setInfo("Allowed " + row.host);
 await load();
 } catch (e) {
 setInfo("");
 setErr(String(e));
 // Keep failure visible on ConfirmModal — do not clear err via load().
 await load({ preserveErr: true });
 } finally {
 setAllowBusy(false);
 }
 }

 async function bulkAllow() {
 const hosts = selectedHosts.filter((h) => !looksLikeIP(h));
 if (hosts.length === 0) {
 setErr("Selected rows are raw IPs — they cannot be always-allowed.");
 return;
 }
 try {
 const msg = await api.bulkAlwaysAllow(hosts);
 setErr("");
 setInfo(msg || "Allowed selected sites.");
 setChecked({});
 await load();
 } catch (e) {
 // Partial success still updates disk — reload rows, keep failure message.
 setInfo("");
 setErr(String(e));
 await load({ preserveErr: true });
 }
 }

 function copy(text: string) {
 void navigator.clipboard.writeText(text);
 }

 function toggleCheck(id: string) {
 setChecked((c) => ({ ...c, [id]: !c[id] }));
 }

 function toggleSelectMode() {
 setSelectMode((v) => {
 if (v) setChecked({});
 return !v;
 });
 }

 return (
 <div className="stack">
 {tipsEnabled && (
 <Tip id="activity" dismissed={tipGone(dismissed, "activity")} onDismiss={onTipDismiss}>
 This is your block history. Open a row to decide Allow this site - only when you trust it.
 </Tip>
 )}

 <div className="toolbar">
 <button className="btn" onClick={() => setShowFilters((v) => !v)}>
 {showFilters ? "Hide filters" : "Filters"}
 </button>
 <button className="btn" onClick={toggleSelectMode}>
 {selectMode ? "Done selecting" : "Select..."}
 </button>
 {selectMode && selectedHosts.length > 0 && (
 <button className="btn primary" onClick={() => void bulkAllow()}>
 Allow selected ({selectedHosts.length})
 </button>
 )}
 <button className="btn subtle" onClick={() => void load()} disabled={busy}>
 Refresh
 </button>
 </div>

 {showFilters && (
 <div className="toolbar">
 <input
 placeholder="Search host, URL, why..."
 value={search}
 onChange={(e) => setSearch(e.target.value)}
 />
 <select value={reason} onChange={(e) => setReason(e.target.value)}>
 {REASONS.map((r) => (
 <option key={r.value || "all"} value={r.value} title={r.value || r.label}>
 {r.label}
 </option>
 ))}
 </select>
 <label className="muted">
 <input
 type="checkbox"
 checked={rememberedOnly}
 onChange={(e) => setRememberedOnly(e.target.checked)}
 />{" "}
 Silenced only
 </label>
 <label className="muted">
 <input
 type="checkbox"
 checked={groupByHost}
 onChange={(e) => setGroupByHost(e.target.checked)}
 />{" "}
 Group by host
 </label>
 </div>
 )}

 {err && <p className="warn-box">{err}</p>}
 {info && !err ? <p className="muted">{info}</p> : null}
 {snap && (snap.problems_alert || snap.mode !== "safe") && (
 <p className="notice-box">
 {snap.problems_alert
 ? "Needs attention — protection may not be working. History can look empty even when you expect blocks. Open Problems or try again from Home."
 : snap.mode === "agents"
   ? "Agents only is on — everyday browsing is not protected like Protect computer. History may show agent blocks. Switch from Home when you want Protect computer."
   : snap.mode === "session"
     ? "Session protection is limited. Switch to Protect computer from Home for everyday browsing."
     : (snap.policy_profile || "").toLowerCase() === "agent"
       ? "Last mode was Agents only — everyday browsing is not protected. Turn Agents only on from Home, or switch to Protect computer from Settings. History may only show My agents blocks until then."
       : "Everyday browsing is not protected right now. History may be empty or only show My agents blocks. Turn on Protect computer from Home when you want that."}
 </p>
 )}
 {displayRows.length === 0 ? (
 <div className="empty card">
 {showFilters && (search.trim() || reason || rememberedOnly) ? (
 <>
 <p>
 <strong>No matches for these filters.</strong>
 </p>
 <p className="muted">
 Clear search, reason, or Silenced only to see the full History again.
 </p>
 <div className="row-actions">
 <button
 className="btn subtle"
 type="button"
 onClick={() => {
 setSearch("");
 setReason("");
 setRememberedOnly(false);
 }}
 >
 Clear filters
 </button>
 </div>
 </>
 ) : (
 <>
 <p>
 <strong>Nothing blocked yet - that is OK.</strong>
 </p>
 <p>
 Every block is recorded here.
 {snap?.problems_alert
 ? " Fix Needs attention from Home or Problems first — until then, DenyOut may not be asking about blocks as usual."
 : snap?.mode === "safe" || snap?.mode === "agents" || snap?.mode === "session"
   ? snap?.quiet_while_away === false
     ? " When you are at the computer, DenyOut asks Keep blocked / Allow this site in the app. Stay quiet while away is off — Ask/block dialogs and soft OS banners can still appear while locked or idle (~5 min). Fullscreen quiet is separate (Advanced → Respect fullscreen)."
     : " When you are at the computer, DenyOut asks Keep blocked / Allow this site in the app. With Stay quiet while away on, locked or idle (~5 min) stays quiet and shows one summary when you return. Fullscreen quiet is separate (Advanced → Respect fullscreen)."
   : (snap?.policy_profile || "").toLowerCase() === "agent"
     ? " Last mode was Agents only. Turn it on from Home (or run My agents) to start recording blocks here."
     : " Turn on Protect computer (or run My agents) to start recording blocks here."}
 </p>
 <div className="row-actions">
 <button
 className="btn subtle"
                  onClick={() =>
                    void api
                      .testProtection()
                      .then((m) => {
                        const t = m || "Checked.";
                        // Backend returns a plain string for unhealthy — style as warning.
                        if (/did not stay on|did not start correctly/i.test(t)) {
                          setInfo("");
                          setErr(t);
                        } else {
                          setErr("");
                          setInfo(t);
                        }
                      })
                      .catch((e) => {
                        setInfo("");
                        setErr(String(e));
                      })
                  }
                >
                  Try a safe check...
                </button>
 {onOpenSettingsAdvanced ? (
 <button className="btn subtle" onClick={onOpenSettingsAdvanced}>
 Open diagnostics
 </button>
 ) : null}
 </div>
 </>
 )}
 </div>
 ) : (
 <div className="layout-split">
 <div className="table-wrap">
 <table>
 <thead>
 <tr>
 {selectMode ? <th style={{ width: 36 }} /> : null}
 <th>Time</th>
 <th>Site</th>
 <th>Why</th>
 <th />
 </tr>
 </thead>
 <tbody>
 {displayRows.map((r) => (
 <tr
 key={r.id}
 className={selected?.id === r.id ? "selected" : undefined}
 onClick={() => setSelected(r)}
 >
 {selectMode ? (
 <td onClick={(e) => e.stopPropagation()}>
 <input
 type="checkbox"
 checked={!!checked[r.id]}
 onChange={() => toggleCheck(r.id)}
 aria-label={`Select ${r.host}`}
 />
 </td>
 ) : null}
 <td className="mono">{formatTime(r.ts)}</td>
 <td>
 {r.host || " - "}
 {r.remembered ? <div className="muted">Silenced</div> : null}
 {groupByHost ? <div className="muted">Latest for host</div> : null}
 </td>
 <td>{r.why}</td>
 <td onClick={(e) => e.stopPropagation()}>
 <div className="row-actions">
 {looksLikeIP(r.host) ? (
 <span className="muted">IP — no allow</span>
 ) : (
 <button className="btn subtle" onClick={() => requestAlwaysAllow(r)}>
 Allow this site
 </button>
 )}
 </div>
 </td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 <aside className="drawer">
 {selected ? (
 <>
 <h3>{selected.host || "Blocked"}</h3>
 <p>{selected.why || "Blocked for your safety."}</p>
 <p className="url muted">{selected.url || " - "}</p>
 <div className="row-actions">
 {looksLikeIP(selected.host) ? (
 <p className="muted" style={{ margin: 0 }}>
 Raw IPs cannot be always-allowed here. Under Protect computer, many public IPs are
 allowed; some blocks still depend on the reason.
 </p>
 ) : (
 <button className="btn primary" onClick={() => requestAlwaysAllow(selected)}>
 Allow this site
 </button>
 )}
 <button className="btn" onClick={() => copy(selected.url || selected.host)}>
 Copy URL
 </button>
 </div>
 <p className="muted drawer-note">
 Secrets in URLs are redacted in the UI. Allow this site matches the in-app prompt.
 </p>
 <details className="tech-details">
 <summary>Technical details</summary>
 <dl>
 <dt>Reason codes</dt>
 <dd className="mono" title={selected.reasons?.join(", ")}>
 {selected.reasons?.join(", ") || " - "}
 </dd>
 <dt>Primary</dt>
 <dd className="mono">{selected.primary_reason || " - "}</dd>
 <dt>Method</dt>
 <dd>{selected.method || " - "}</dd>
 <dt>Process</dt>
 <dd className="mono">{selected.process || " - "}</dd>
 <dt>Policy</dt>
 <dd className="mono">{selected.policy_profile || " - "}</dd>
 <dt>Detectors</dt>
 <dd className="mono">{selected.detectors?.join(", ") || " - "}</dd>
 <dt>When</dt>
 <dd className="mono">{selected.ts}</dd>
 </dl>
 </details>
 </>
 ) : (
 <p className="muted">Select a row to see why it was blocked and what you can do.</p>
 )}
 </aside>
 </div>
 )}

 {allowRow ? (
 <ConfirmModal
 title={`Allow ${allowRow.host}?`}
 body={
 (allowRow.process || "").startsWith("wrap:")
 ? snap?.mode === "safe" && snap?.protection_on
   ? `Allow this site for Protect computer and this agent?\n\nDenyOut will stop blocking this host.`
   : `Always allow for this agent (and on the global allow list). DenyOut will stop blocking this host.`
 : `DenyOut will stop blocking this host.`
 }
 busy={allowBusy}
 error={err}
 confirmLabel="Allow this site"
 onCancel={() => setAllowRow(null)}
 onConfirm={() => void confirmAlwaysAllow()}
 />
 ) : null}
 </div>
 );
}

function formatTime(ts: string): string {
  const t = Date.parse(ts || "");
  if (Number.isNaN(t)) return ts || " - ";
  const d = new Date(t);
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  if (sameDay) {
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
