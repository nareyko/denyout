import { useEffect, useMemo, useState } from "react";
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

export function Profiles({
  openNew,
  onNewConsumed,
  snap,
  onTipDismiss,
  tipsEnabled = true,
}: {
  openNew?: boolean;
  onNewConsumed?: () => void;
  snap?: UISnapshot | null;
  onTipDismiss?: () => void;
  tipsEnabled?: boolean;
}) {
  const [list, setList] = useState<ProfileView[]>([]);
  const [edit, setEdit] = useState<AgentProfile | null>(null);
  const [cmdLine, setCmdLine] = useState("");
  const [msg, setMsg] = useState("");
  const [packs, setPacks] = useState<AllowPack[]>([]);
  const [addPackID, setAddPackID] = useState("");

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
    void reload().catch((e) => setMsg(String(e)));
  }, []);

  useEffect(() => {
    if (openNew) {
      openNewForm();
      onNewConsumed?.();
    }
  }, [openNew]);

  function openNewForm() {
    const p = emptyProfile();
    setEdit(p);
    setCmdLine(p.command.join(" "));
  }

  function openEdit(p: ProfileView) {
    setEdit({ ...p });
    setCmdLine((p.command || []).join(" "));
  }

  async function save() {
    if (!edit) return;
    const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
    if (!edit.name.trim() || parts.length === 0) {
      setMsg("Name and command are required.");
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
        if (pack) {
          const ok = confirm(
            `Add recommended hosts?\n\n${pack.name}: ${pack.description}\n\nYou can Undo the pack later from Edit agent.`,
          );
          if (ok) {
            const added = await api.applyAllowPack(p.id, pack.id);
            setMsg(
              added?.length
                ? `Saved ${p.name}. Added ${added.length} host(s) from ${pack.name}.`
                : `Saved ${p.name}. Pack already covered.`,
            );
          } else {
            setMsg(`Saved ${p.name}.`);
          }
        } else {
          setMsg(`Saved ${p.name}.`);
        }
      } else {
        setMsg("");
      }
      setEdit(null);
      await reload();
    } catch (e) {
      setMsg(String(e));
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
          on Home → Protect computer.
        </Tip>
      )}

      <div className="toolbar">
        <button className="btn primary" onClick={openNewForm}>
          New agent
        </button>
      </div>
      {msg && <p className="muted">{msg}</p>}

      {pendingTotal > 0 && (
        <section className="card">
          <h2>Learning</h2>
          <p className="muted">
            {pendingTotal} pending Allow once host{pendingTotal === 1 ? "" : "s"}. Pin adds them to
            the agent allowlist; Discard clears them.
          </p>
        </section>
      )}

      {list.length === 0 && !edit ? (
        <div className="empty card">
          <p>
            <strong>No AI agents yet</strong> — that is fine for everyday browsing.
          </p>
          <p className="muted">
            Create an agent only when you want to wrap a tool (for example an AI CLI). Protect
            computer on Home covers normal web use.
          </p>
          <button className="btn primary" onClick={openNewForm}>
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
                  <td>
                    {p.learning?.enabled ? "on" : "off"}
                    {(p.pending_once?.length ?? 0) > 0
                      ? ` · ${p.pending_once!.length} pending`
                      : ""}
                  </td>
                  <td>{p.running ? `running (pid ${p.pid})` : "stopped"}</td>
                  <td>
                    <div className="row-actions">
                      {p.running ? (
                        <button className="btn" onClick={() => void api.stopProfile(p.id).then(reload)}>
                          Stop
                        </button>
                      ) : (
                        <button
                          className="btn primary"
                          onClick={() =>
                            void api.startProfile(p.id).then(reload).catch((e) => setMsg(String(e)))
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
                            onClick={() =>
                              void api.pinLearning(p.id).then(reload).catch((e) => setMsg(String(e)))
                            }
                          >
                            Pin
                          </button>
                          <button
                            className="btn"
                            onClick={() =>
                              void api
                                .discardLearning(p.id)
                                .then(reload)
                                .catch((e) => setMsg(String(e)))
                            }
                          >
                            Discard
                          </button>
                        </>
                      )}
                      <button
                        className="btn danger"
                        onClick={() => {
                          if (!confirm(`Delete agent ${p.name}?`)) return;
                          void api.deleteProfile(p.id).then(reload).catch((e) => setMsg(String(e)));
                        }}
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
        <div className="modal-backdrop">
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
                placeholder="claude  or  python app.py"
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
                      sandbox: e.target.checked ? "srt" : edit.sandbox,
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
                              v{ap.version} · {ap.hosts?.length ?? 0} hosts
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
                                  setMsg(`Undid pack ${ap.id}.`);
                                })
                                .catch((e) => setMsg(String(e)));
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
                      <option value="">Add pack…</option>
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
                            setMsg(
                              added?.length
                                ? `Added ${added.length} host(s) from pack.`
                                : "Pack already applied (no new hosts).",
                            );
                          })
                          .catch((e) => setMsg(String(e)));
                      }}
                    >
                      Add
                    </button>
                  </div>
                )}
                {(edit.extra_allow || []).length > 0 && (
                  <p className="muted mono" style={{ marginTop: 8 }}>
                    Allowlist: {(edit.extra_allow || []).join(", ")}
                  </p>
                )}
              </div>
            )}
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
