import { useCallback, useEffect, useMemo, useState } from "react";
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
  { value: "host_not_allowed", label: "Host not allowed" },
];

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
  const [busy, setBusy] = useState(false);

  const dismissed = snap?.dismissed_tips;

  const load = useCallback(async () => {
    setBusy(true);
    setErr("");
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
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }, [search, reason, rememberedOnly, showFilters]);

  useEffect(() => {
    void load();
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

  async function alwaysAllow(row: DenialView) {
    const code = row.reasons?.[0] ?? "";
    await api.alwaysAllow(row.host, code);
    await load();
  }

  async function allowThisSite(row: DenialView) {
    const code = row.reasons?.[0] ?? "";
    await api.forgetKeep(row.host, code);
    await api.alwaysAllow(row.host, code);
    await load();
  }

  async function bulkAllow() {
    if (selectedHosts.length === 0) return;
    await api.bulkAlwaysAllow(selectedHosts);
    setChecked({});
    await load();
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
          This is your block history. Open a row to decide Allow this site — only when you trust it.
        </Tip>
      )}

      <div className="toolbar">
        <button className="btn" onClick={() => setShowFilters((v) => !v)}>
          {showFilters ? "Hide filters" : "Filters"}
        </button>
        <button className="btn" onClick={toggleSelectMode}>
          {selectMode ? "Done selecting" : "Select…"}
        </button>
        {selectMode && selectedHosts.length > 0 && (
          <button className="btn primary" onClick={() => void bulkAllow()}>
            Always allow selected ({selectedHosts.length})
          </button>
        )}
        <button className="btn subtle" onClick={() => void load()} disabled={busy}>
          Refresh
        </button>
      </div>

      {showFilters && (
        <div className="toolbar">
          <input
            placeholder="Search host, URL, why…"
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

      {err && <p className="muted">{err}</p>}
      {displayRows.length === 0 ? (
        <div className="empty card">
          <p>
            <strong>Nothing blocked yet — that is OK.</strong>
          </p>
          <p>
            When DenyOut blocks something, you’ll get a short Keep blocked / Allow this site toast,
            and it will show up here.
          </p>
          {onOpenSettingsAdvanced && (
            <button className="btn subtle" onClick={onOpenSettingsAdvanced}>
              Try a safe check…
            </button>
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
                      {r.host || "—"}
                      {r.remembered ? <div className="muted">Silenced</div> : null}
                      {groupByHost ? <div className="muted">Latest for host</div> : null}
                    </td>
                    <td>{r.why}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div className="row-actions">
                        <button className="btn subtle" onClick={() => void alwaysAllow(r)}>
                          Always allow
                        </button>
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
                <p className="url muted">{selected.url || "—"}</p>
                <div className="row-actions">
                  <button className="btn primary" onClick={() => void allowThisSite(selected)}>
                    Allow this site
                  </button>
                  <button className="btn" onClick={() => void alwaysAllow(selected)}>
                    Always allow host
                  </button>
                  <button className="btn" onClick={() => copy(selected.url || selected.host)}>
                    Copy URL
                  </button>
                </div>
                <p className="muted drawer-note">
                  Secrets in URLs are shown as ***. Allow this site matches the toast.
                </p>
                <details className="tech-details">
                  <summary>Technical details</summary>
                  <dl>
                    <dt>Reason codes</dt>
                    <dd className="mono" title={selected.reasons?.join(", ")}>
                      {selected.reasons?.join(", ") || "—"}
                    </dd>
                    <dt>Method</dt>
                    <dd>{selected.method || "—"}</dd>
                    <dt>Process</dt>
                    <dd className="mono">{selected.process || "—"}</dd>
                    <dt>Detectors</dt>
                    <dd className="mono">{selected.detectors?.join(", ") || "—"}</dd>
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
    </div>
  );
}

function formatTime(ts: string): string {
  if (ts.length >= 19) return ts.slice(11, 19);
  return ts || "—";
}
