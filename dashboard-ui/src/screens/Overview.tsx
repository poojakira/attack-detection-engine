import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Incident, listIncidents } from "../api/client";

// All metrics here are computed from real backend incident queries. There are
// no hardcoded numbers.
export function Overview() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [ready, setReady] = useState<string>("checking…");

  useEffect(() => {
    listIncidents({ limit: 200 })
      .then((r) => {
        setIncidents(r.items);
        setTotal(r.total);
      })
      .catch((e) => setError(String(e)));
    fetch("/readiness")
      .then((r) => r.json())
      .then((j) => setReady(j.status ?? "unknown"))
      .catch(() => setReady("unavailable"));
  }, []);

  const open = incidents.filter((i) => !["CLOSED", "RESOLVED"].includes(i.status)).length;
  const highCrit = incidents.filter((i) => ["HIGH", "CRITICAL"].includes(i.severity)).length;
  const latest = [...incidents]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, 5);
  const suspiciousIdentities = Array.from(
    new Set(
      incidents
        .map((i) => (i.affected_entities?.["identity"] as string) || null)
        .filter(Boolean),
    ),
  ).slice(0, 8);

  if (error) return <div className="error">Failed to load overview: {error}</div>;

  return (
    <div>
      <h2>Security Overview</h2>
      <div className="cards">
        <div className="card"><div className="num">{total}</div><div>Total incidents</div></div>
        <div className="card"><div className="num">{open}</div><div>Open</div></div>
        <div className="card"><div className="num">{highCrit}</div><div>High / Critical</div></div>
        <div className="card"><div className="num">{ready}</div><div>Ingestion / DB health</div></div>
      </div>

      <h3>Latest detections</h3>
      <table className="grid">
        <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>
          {latest.map((i) => (
            <tr key={i.incident_id}>
              <td><Link to={`/incidents/${i.incident_id}`}>{i.title}</Link></td>
              <td><span className={`sev ${i.severity}`}>{i.severity}</span></td>
              <td>{i.status}</td>
              <td>{new Date(i.created_at).toLocaleString()}</td>
            </tr>
          ))}
          {latest.length === 0 && <tr><td colSpan={4} className="muted">No incidents yet.</td></tr>}
        </tbody>
      </table>

      <h3>Suspicious identities</h3>
      {suspiciousIdentities.length ? (
        <ul>{suspiciousIdentities.map((id) => <li key={id}>{id}</li>)}</ul>
      ) : (
        <p className="muted">None observed.</p>
      )}
    </div>
  );
}
