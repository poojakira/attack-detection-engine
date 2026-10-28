import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  Finding,
  Incident,
  TimelineItem,
  addNote,
  assign,
  changeStatus,
  closeIncident,
  getEvidence,
  getHistory,
  getIncident,
  getSession,
  getTimeline,
} from "../api/client";

const NEXT_STATUS = ["TRIAGED", "INVESTIGATING", "RESOLVED"];

export function Investigation() {
  const { id = "" } = useParams();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canWrite = getSession().role !== "read_only_auditor";

  const refresh = useCallback(async () => {
    try {
      setIncident(await getIncident(id));
      setFindings((await getEvidence(id)).findings);
      setTimeline((await getTimeline(id)).timeline);
      await getHistory(id);
    } catch (e) {
      setError(String(e));
    }
  }, [id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function act(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (error) return <div className="error">{error}</div>;
  if (!incident) return <div className="muted">Loading…</div>;

  return (
    <div className="investigation">
      <h2>{incident.title}</h2>
      <div className="meta">
        <span className={`sev ${incident.severity}`}>{incident.severity}</span>
        <span>Status: <b>{incident.status}</b></span>
        <span>Assigned: {incident.assigned_analyst ?? "unassigned"}</span>
        <span className="muted">{incident.incident_id}</span>
      </div>

      <section>
        <h3>Why this was flagged</h3>
        <p>{incident.correlation_reason || incident.description}</p>
        <p className="muted">
          Note: a finding's severity is an investigation signal, not proof of compromise.
        </p>
      </section>

      <section>
        <h3>Linked findings &amp; evidence</h3>
        <table className="grid">
          <thead><tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>ATT&amp;CK</th><th>Description</th></tr></thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.finding_id}>
                <td>{f.rule_id}</td>
                <td><span className={`sev ${f.severity}`}>{f.severity}</span></td>
                <td>{f.confidence}</td>
                <td>{f.attack_techniques.join(", ") || "-"}</td>
                <td>{f.description}</td>
              </tr>
            ))}
            {findings.length === 0 && <tr><td colSpan={5} className="muted">No findings linked.</td></tr>}
          </tbody>
        </table>
      </section>

      <section>
        <h3>Timeline</h3>
        <ul className="timeline">
          {timeline.map((t) => (
            <li key={t.ref} className={`tl ${t.kind}`}>
              <span className="muted">{new Date(t.timestamp).toLocaleString()}</span> · <b>{t.kind}</b> · {t.summary}
            </li>
          ))}
        </ul>
      </section>

      {canWrite ? (
        <section className="actions">
          <h3>Analyst response</h3>
          <div className="row">
            <button disabled={busy} onClick={() => act(() => assign(id, getSession().orgId ? "me" : "me"))}>
              Assign to me
            </button>
            {NEXT_STATUS.map((s) => (
              <button key={s} disabled={busy} onClick={() => act(() => changeStatus(id, s))}>
                → {s}
              </button>
            ))}
            <button disabled={busy} onClick={() => act(() => closeIncident(id, "resolved via console"))}>
              Close
            </button>
          </div>
          <div className="row">
            <input placeholder="Add investigation note" value={note} onChange={(e) => setNote(e.target.value)} />
            <button
              disabled={busy || !note.trim()}
              onClick={() => act(async () => { await addNote(id, note); setNote(""); })}
            >
              Add note
            </button>
          </div>
        </section>
      ) : (
        <p className="muted">Read-only auditor: investigation actions are disabled.</p>
      )}
    </div>
  );
}
