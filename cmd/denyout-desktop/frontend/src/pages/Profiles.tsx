import { useEffect, useMemo, useState } from "react";
import { ConfirmModal } from "../components/ConfirmModal";
import { Tip, tipGone } from "../components/Tip";
import { AllowPack, api, AgentProfile, ProfileView, UISnapshot } from "../wails";

const emptyProfile = (): AgentProfile => ({
 id: "",
 name: "My agent",
 command: ["python", "app.py"],
 preset: "agent",
 ask_mode: true,
 notify: true,
 learning: { enabled: true, duration_hours: 24 },
});

/** Count of open Edit/New agent drafts — App blocks Jump (Ctrl+K) while editing. */
let openProfileEditCount = 0;

export function profileEditOpen(): boolean {
 return openProfileEditCount > 0;
}

export function Profiles({
 openNew,
 onNewConsumed,
 snap,
 onTipDismiss,
 tipsEnabled = true,
 /** Shell owns Esc (Your setup / Jump / Decision / Quit / Pause) — do not discard draft. */
 escDeferred = false,
}: {
 openNew?: boolean;
 onNewConsumed?: () => void;
 snap?: UISnapshot | null;
 onTipDismiss?: () => void;
 tipsEnabled?: boolean;
 escDeferred?: boolean;
}) {
 const [list, setList] = useState<ProfileView[]>([]);
 const [edit, setEdit] = useState<AgentProfile | null>(null);
 const [cmdLine, setCmdLine] = useState("");
 const [msg, setMsg] = useState("");
 const [err, setErr] = useState("");
 const note = (m: string) => {
 setErr("");
 setMsg(m);
 };
 const fail = (e: unknown) => {
 setMsg("");
 setErr(String(e));
 };
 const [packs, setPacks] = useState<AllowPack[]>([]);
 const [addPackID, setAddPackID] = useState("");
 const [addHost, setAddHost] = useState("");
 const [confirm, setConfirm] = useState<null | {
 title: string;
 body: string;
 danger?: boolean;
 confirmLabel?: string;
 run: () => Promise<void>;
 }>(null);
 const [confirmBusy, setConfirmBusy] = useState(false);

 async function reload() {
 setList((await api.profiles()) ?? []);
 }

 useEffect(() => {
 void api
 .listAllowPacks()
 .then((p) => setPacks(p ?? []))
 .catch(() => setPacks([]));
 }, []);

 useEffect(() => {
 void reload().catch((e) => fail(e));
 const poll = window.setInterval(() => {
 void reload().catch(() => undefined);
 }, 4000);
 return () => window.clearInterval(poll);
 }, []);

 useEffect(() => {
 if (!openNew) return;
 requestOpenNew();
 onNewConsumed?.();
 }, [openNew]);

 useEffect(() => {
 if (!edit) return;
 openProfileEditCount += 1;
 return () => {
 openProfileEditCount = Math.max(0, openProfileEditCount - 1);
 };
 }, [edit]);

 useEffect(() => {
 if (!edit || confirm || escDeferred) return;
 function onKey(e: KeyboardEvent) {
 if (e.key !== "Escape") return;
 e.preventDefault();
 e.stopPropagation();
 setEdit(null);
 }
 window.addEventListener("keydown", onKey, true);
 return () => window.removeEventListener("keydown", onKey, true);
 }, [edit, confirm, escDeferred]);

 function openNewForm() {
 const p = emptyProfile();
 setEdit(p);
 setCmdLine(p.command.join(" "));
 }

 /** Jump / toolbar New agent: keep New draft; confirm before discarding Edit. */
 function requestOpenNew() {
 if (edit && !(edit.id || "").trim()) return;
 if (edit && (edit.id || "").trim()) {
 setConfirm({
 title: "Discard edit?",
 body: `Discard changes to ${edit.name || "this agent"} and create a new agent?`,
 confirmLabel: "Discard and create new",
 danger: true,
 run: async () => {
 openNewForm();
 },
 });
 return;
 }
 openNewForm();
 }

 function openEdit(p: ProfileView) {
 setEdit({ ...p });
 setCmdLine((p.command || []).join(" "));
 }

 async function save() {
 if (!edit) return;
 const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
 if (!edit.name.trim() || parts.length === 0) {
 fail("Name and command are required.");
 return;
 }
 const isNew = !edit.id;
 const p: AgentProfile = {
 ...edit,
 name: edit.name.trim(),
 command: parts,
 id: edit.id || slug(edit.name),
 };
 try {
 await api.saveProfile(p);
 if (isNew) {
 let suggest = "";
 try {
 suggest = (await api.suggestAllowPack(p.name, p.command)) || "";
 } catch {
 suggest = "";
 }
 const pack =
 packs.find((x) => x.id === suggest) ||
 packs.find((x) => x.id === "cursor-starter") ||
 packs[0];
 setEdit(null);
 await reload();
 if (pack) {
 setConfirm({
 title: `Add ${pack.name}?`,
 body: `${pack.description}\n\nYou can Undo the pack later from Edit agent.`,
 confirmLabel: "Add hosts",
 run: async () => {
 const added = await api.applyAllowPack(p.id, pack.id);
 note(
 added?.length
 ? `Saved ${p.name}. Added ${added.length} host(s) from ${pack.name}.`
 : `Saved ${p.name}. Pack already covered.`,
 );
 await reload();
 },
 });
 note(`Saved ${p.name}.`);
 } else {
 note(`Saved ${p.name}.`);
 }
 } else {
 note("");
 setEdit(null);
 await reload();
 }
 } catch (e) {
 fail(e);
 }
 }

 const pendingTotal = useMemo(
 () => list.reduce((n, p) => n + (p.pending_once?.length ?? 0), 0),
 [list],
 );

 return (
 <div className="stack">
 {tipsEnabled && (
 <Tip id="profiles" dismissed={tipGone(snap?.dismissed_tips, "profiles")} onDismiss={onTipDismiss}>
 For AI tools: wrap one command so DenyOut can ask before new sites. Everyday browsing stays
 on Home under Protect computer.
 </Tip>
 )}

 <div className="toolbar">
 <button className="btn primary" onClick={requestOpenNew}>
 New agent
 </button>
 </div>
 {err ? <p className="warn-box">{err}</p> : msg ? <p className="muted">{msg}</p> : null}

 {pendingTotal > 0 && (
 <section className="card">
 <h2>Learning</h2>
 <p className="muted">
 {pendingTotal} pending Allow once host{pendingTotal === 1 ? "" : "s"}. Pin adds them to
 the agent allowlist; Discard clears them.
 </p>
 <div className="row-actions" style={{ marginTop: "0.55rem" }}>
 {list
 .filter((p) => (p.pending_once?.length || 0) > 0)
 .map((p) => (
 <span key={p.id} className="row-actions" style={{ gap: "0.35rem" }}>
 <button
 className="btn"
 onClick={() => {
 const n = p.pending_once?.length || 0;
 setConfirm({
 title: `Pin sites for ${p.name}?`,
 body: `Pin ${n} site${n === 1 ? "" : "s"}?\n\nThey move onto this agent’s allowlist.`,
 confirmLabel: "Pin",
 run: async () => {
 await api.pinLearning(p.id);
 await reload();
 },
 });
 }}
 >
 Pin {p.name}
 </button>
 <button
 className="btn subtle"
 onClick={() => {
 const n = p.pending_once?.length || 0;
 setConfirm({
 title: `Discard pending for ${p.name}?`,
 body: `Discard ${n} pending site${n === 1 ? "" : "s"}?\n\nThey stay blocked for this agent — including this run if the agent is running.`,
 danger: true,
 confirmLabel: "Discard",
 run: async () => {
 await api.discardLearning(p.id);
 await reload();
 },
 });
 }}
 >
 Discard {p.name}
 </button>
 </span>
 ))}
 </div>
 </section>
 )}

 {list.length === 0 && !edit ? (
 <div className="empty card">
 <p>
 <strong>No AI agents yet</strong> - that is fine for everyday browsing.
 </p>
 <p className="muted">
 Create an agent only when you want to wrap a tool (for example an AI CLI). Protect
 computer on Home covers normal web use.
 </p>
 <button className="btn primary" onClick={requestOpenNew}>
 New agent
 </button>
 </div>
 ) : (
 <div className="table-wrap">
 <table>
 <thead>
 <tr>
 <th>Name</th>
 <th>Command</th>
 <th>Ask</th>
 <th>Ask / block</th>
 <th>Learning</th>
 <th>Status</th>
 <th />
 </tr>
 </thead>
 <tbody>
 {list.map((p) => (
 <tr key={p.id}>
 <td>{p.name}</td>
 <td className="mono">{(p.command || []).join(" ")}</td>
 <td>{p.ask_mode ? "on" : "off"}</td>
 <td>{p.notify ? "on" : "off"}</td>
 <td>
 {p.learning?.enabled ? "on" : "off"}
 {(p.pending_once?.length ?? 0) > 0
 ? ` - ${p.pending_once!.length} pending`
 : ""}
 </td>
 <td>{p.running ? `running (pid ${p.pid})` : "stopped"}</td>
 <td>
 <div className="row-actions">
                    {p.running ? (
                      <button
                        className="btn"
                        onClick={() =>
                          void api
                            .stopProfile(p.id)
                            .then(reload)
                            .catch((e) => fail(e))
                        }
                      >
                        Stop
                      </button>
                    ) : (
 <button
 className="btn primary"
 onClick={() =>
 void api.startProfile(p.id).then(reload).catch((e) => fail(e))
 }
 >
 Start
 </button>
 )}
 <button className="btn" onClick={() => openEdit(p)}>
 Edit
 </button>
 {(p.pending_once?.length ?? 0) > 0 && (
 <>
 <button
 className="btn"
 onClick={() => {
 const n = p.pending_once?.length || 0;
 setConfirm({
 title: `Pin sites for ${p.name}?`,
 body: `Pin ${n} site${n === 1 ? "" : "s"}?\n\nThey move onto this agent’s allowlist.`,
 confirmLabel: "Pin",
 run: async () => {
 await api.pinLearning(p.id);
 await reload();
 },
 });
 }}
 >
 Pin
 </button>
 <button
 className="btn"
 onClick={() => {
 const n = p.pending_once?.length || 0;
 setConfirm({
 title: `Discard pending for ${p.name}?`,
 body: `Discard ${n} pending site${n === 1 ? "" : "s"}?\n\nThey stay blocked for this agent — including this run if the agent is running.`,
 danger: true,
 confirmLabel: "Discard",
 run: async () => {
 await api.discardLearning(p.id);
 await reload();
 },
 });
 }}
 >
 Discard
 </button>
 </>
 )}
 <button
 className="btn danger"
 onClick={() =>
 setConfirm({
 title: `Delete ${p.name}?`,
 body: "This removes the agent profile. Running wraps for it will stop.",
 danger: true,
 confirmLabel: "Delete",
 run: async () => {
 await api.deleteProfile(p.id);
 await reload();
 },
 })
 }
 >
 Delete
 </button>
 </div>
 </td>
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 )}

 {edit && (
 <div className="modal-backdrop" style={{ zIndex: 55 }}>
 <div className="modal">
 <h2>{edit.id ? "Edit agent" : "New agent"}</h2>
 <p className="muted">Wrap one command. Ask prompts before new hosts when enabled.</p>
 <label>
 Name
 <input
 style={{ width: "100%", marginTop: 4 }}
 value={edit.name}
 onChange={(e) => setEdit({ ...edit, name: e.target.value })}
 />
 </label>
 <label style={{ display: "block", marginTop: 8 }}>
 Command
 <input
 style={{ width: "100%", marginTop: 4 }}
 value={cmdLine}
 onChange={(e) => setCmdLine(e.target.value)}
 placeholder="claude or python app.py"
 />
 </label>
 <label style={{ display: "block", marginTop: 8 }}>
 Workdir (optional)
 <input
 style={{ width: "100%", marginTop: 4 }}
 value={edit.workdir || ""}
 onChange={(e) => setEdit({ ...edit, workdir: e.target.value })}
 />
 </label>
          <label style={{ display: "block", marginTop: 8 }}>
            Allowlist preset{" "}
            <select
              value={edit.preset || "agent"}
              onChange={(e) => setEdit({ ...edit, preset: e.target.value })}
            >
              <option value="agent">Agent + Cursor (recommended)</option>
              <option value="models">Models only (stricter)</option>
              <option value="none">None (allowlist empty)</option>
            </select>
          </label>
          <label style={{ display: "block", marginTop: 8 }}>
            <input
              type="checkbox"
              checked={edit.ask_mode}
              onChange={(e) => setEdit({ ...edit, ask_mode: e.target.checked })}
            />{" "}
            Ask before new hosts
          </label>
 <label style={{ display: "block", marginTop: 8 }}>
 <input
 type="checkbox"
 checked={edit.notify}
 onChange={(e) => setEdit({ ...edit, notify: e.target.checked })}
 />{" "}
 Show Ask and block dialogs for this agent
 </label>
 <p className="muted" style={{ marginTop: 4 }}>
 {snap?.quiet_while_away === false
  ? "When on, prompts appear while you are at the computer. Stay quiet while away is off (Settings) — Ask and block dialogs can still appear while locked or idle."
  : "When on, prompts appear while you are at the computer. With Stay quiet while away on (Settings), they stay quiet while you are away and show in the return summary."}
 </p>
 <label style={{ display: "block", marginTop: 8 }}>
 <input
 type="checkbox"
 checked={!!edit.learning?.enabled}
 onChange={(e) =>
 setEdit({
 ...edit,
 learning: { ...edit.learning, enabled: e.target.checked },
 })
 }
 />{" "}
 Remember Allow once hosts (Learning)
 </label>
 {edit.learning?.enabled ? (
 <label style={{ display: "block", marginTop: 8 }}>
 Learning window (hours){" "}
 <input
 type="number"
 min={1}
 max={168}
 value={edit.learning?.duration_hours || 24}
 onChange={(e) =>
 setEdit({
 ...edit,
 learning: {
 ...edit.learning,
 enabled: true,
 duration_hours: Number(e.target.value) || 24,
 },
 })
 }
 />
 </label>
 ) : null}
 <details className="tech-details">
 <summary>Advanced options</summary>
 <label style={{ display: "block", marginTop: 8 }}>
 <input
 type="checkbox"
 checked={!!edit.require_isolation}
 onChange={(e) =>
 setEdit({
 ...edit,
 require_isolation: e.target.checked,
 // Uncheck must clear sandbox — startProfile still enforces sandbox=="srt".
 sandbox: e.target.checked ? "srt" : "",
 })
 }
 />{" "}
 Require stronger isolation (srt)
 </label>
 </details>
 {edit.id && (
 <div style={{ marginTop: 12 }}>
 <h3 className="settings-subhead">Allow packs</h3>
 <p className="muted">
 Curated host lists from DenyOut. Undo removes only hosts that pack added.
 </p>
 {(edit.applied_packs || []).length > 0 ? (
 <ul>
 {edit.applied_packs!.map((ap) => {
 const meta = packs.find((x) => x.id === ap.id);
 return (
 <li
 key={ap.id}
 className="row-actions"
 style={{ marginBottom: "0.35rem" }}
 >
 <span>
 {meta?.name || ap.id}{" "}
 <span className="muted">
 v{ap.version} - {ap.hosts?.length ?? 0} hosts
 </span>
 </span>
 <button
 className="btn"
 type="button"
 onClick={() => {
 void api
 .undoAllowPack(edit.id, ap.id)
 .then(async () => {
 const views = await api.profiles();
 const fresh = views?.find((v) => v.id === edit.id);
 if (fresh) setEdit({ ...fresh });
 await reload();
 note(`Undid pack ${ap.id}.`);
 })
 .catch((e) => fail(e));
 }}
 >
 Undo pack
 </button>
 </li>
 );
 })}
 </ul>
 ) : (
 <p className="muted">None applied yet.</p>
 )}
 {packs.length > 0 && (
 <div className="row-actions" style={{ marginTop: 8 }}>
 <select
 value={addPackID}
 onChange={(e) => setAddPackID(e.target.value)}
 >
 <option value="">Add pack...</option>
 {packs.map((pk) => (
 <option key={pk.id} value={pk.id}>
 {pk.name}
 </option>
 ))}
 </select>
 <button
 className="btn"
 type="button"
 disabled={!addPackID}
 onClick={() => {
 if (!addPackID) return;
 void api
 .applyAllowPack(edit.id, addPackID)
 .then(async (added) => {
 const views = await api.profiles();
 const fresh = views?.find((v) => v.id === edit.id);
 if (fresh) setEdit({ ...fresh });
 await reload();
 setAddPackID("");
 note(
 added?.length
 ? `Added ${added.length} host(s) from pack.`
 : "Pack already applied (no new hosts).",
 );
 })
 .catch((e) => fail(e));
 }}
 >
 Add
 </button>
 </div>
 )}
 <div style={{ marginTop: 8 }}>
 <h3 className="settings-subhead">Allowlist</h3>
 {(edit.extra_allow || []).length > 0 ? (
 <ul>
 {edit.extra_allow!.map((h) => (
 <li key={h} className="row-actions" style={{ marginBottom: "0.35rem" }}>
 <span className="mono">{h}</span>
 <button
 className="btn danger"
 type="button"
 onClick={() =>
 setEdit({
 ...edit,
 extra_allow: (edit.extra_allow || []).filter((x) => x !== h),
 })
 }
 >
 Remove
 </button>
 </li>
 ))}
 </ul>
 ) : (
 <p className="muted">None yet.</p>
 )}
 <div className="row-actions" style={{ marginTop: 8 }}>
 <input
 placeholder="Add host..."
 value={addHost}
 onChange={(e) => setAddHost(e.target.value)}
 style={{ flex: 1 }}
 onKeyDown={(e) => {
 if (e.key !== "Enter") return;
 e.preventDefault();
 const h = addHost.trim().toLowerCase();
 if (!h) return;
 if ((edit.extra_allow || []).includes(h)) {
 setAddHost("");
 return;
 }
 setEdit({ ...edit, extra_allow: [...(edit.extra_allow || []), h] });
 setAddHost("");
 }}
 />
 <button
 className="btn"
 type="button"
 onClick={() => {
 const h = addHost.trim().toLowerCase();
 if (!h) return;
 if ((edit.extra_allow || []).includes(h)) {
 setAddHost("");
 return;
 }
 setEdit({ ...edit, extra_allow: [...(edit.extra_allow || []), h] });
 setAddHost("");
 }}
 >
 Add
 </button>
 </div>
          <p className="muted">
            Save to apply allowlist changes. If this agent is running, DenyOut restarts it so the
            new allowlist takes effect.
          </p>
 </div>
 </div>
 )}
 {err ? <p className="warn-box" style={{ marginTop: 12 }}>{err}</p> : null}
 <div className="row-actions" style={{ marginTop: 12 }}>
 <button className="btn primary" onClick={() => void save()}>
 Save
 </button>
 <button className="btn" onClick={() => setEdit(null)}>
 Cancel
 </button>
 </div>
 </div>
 </div>
 )}

 {confirm ? (
 <ConfirmModal
 title={confirm.title}
 body={confirm.body}
 busy={confirmBusy}
 error={err}
 danger={confirm.danger}
 confirmLabel={confirm.confirmLabel || "Continue"}
 onCancel={() => setConfirm(null)}
 onConfirm={() => {
 setConfirmBusy(true);
 setErr("");
 void confirm
 .run()
 .then(() => setConfirm(null))
 .catch((e) => fail(e))
 .finally(() => setConfirmBusy(false));
 }}
 />
 ) : null}
 </div>
 );
}

function slug(name: string): string {
 return (
 name
 .toLowerCase()
 .trim()
 .replace(/[^a-z0-9]+/g, "-")
 .replace(/^-|-$/g, "") || `agent-${Date.now() % 100000}`
 );
}
