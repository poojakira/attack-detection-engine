import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Incident, listIncidents } from "../api/client";

const STATUSES = ["", "NEW", "TRIAGED", "INVESTIGATING", "RESOLVED", "CLOSED"];
const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const PAGE = 20;

export function IncidentQueue() {
  const [rows, setRows] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listIncidents({ status: status || undefined, severity: severity || undefined, limit: PAGE, offset })
      .then((r) => {
        setRows(r.items);
        setTotal(r.total);
      })
      .catch((e) => setError(String(e)));
  }, [status, severity, offset]);

  return (
    <div>
      <h2>Incident Queue</h2>
      <div className="filters">
        <label>Status
          <select value={status} onChange={(e) => { setOffset(0); setStatus(e.target.value); }}>
            {STATUSES.map((s) => <option key={s} value={s}>{s || "all"}</option>)}
          </select>
        </label>
        <label>Severity
          <select value={severity} onChange={(e) => { setOffset(0); setSeverity(e.target.value); }}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s || "all"}</option>)}
          </select>
        </label>
        <span className="muted">{total} total</span>
      </div>

      {error && <div className="error">{error}</div>}

      <table className="grid">
        <thead>
          <tr>
            <th>ID</th><th>Title</th><th>Severity</th><th>Status</th>
            <th>First seen</th><th>Last seen</th><th>Assigned</th><th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((i) => (
            <tr key={i.incident_id}>
              <td><Link to={`/incidents/${i.incident_id}`}>{i.incident_id.slice(0, 12)}</Link></td>
              <td>{i.title}</td>
              <td><span className={`sev ${i.severity}`}>{i.severity}</span></td>
              <td>{i.status}</td>
              <td>{i.first_seen ? new Date(i.first_seen).toLocaleString() : "-"}</td>
              <td>{i.last_seen ? new Date(i.last_seen).toLocaleString() : "-"}</td>
              <td>{i.assigned_analyst ?? "-"}</td>
              <td>{i.related_finding_count ?? "-"}</td>
            </tr>
          ))}
          {rows.length === 0 && <tr><td colSpan={8} className="muted">No incidents match.</td></tr>}
        </tbody>
      </table>

      <div className="pager">
        <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Prev</button>
        <span>{offset + 1}–{Math.min(offset + PAGE, total)}</span>
        <button disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>Next</button>
      </div>
    </div>
  );
}
