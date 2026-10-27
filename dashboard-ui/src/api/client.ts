// Typed client for the Aegis HealthSec backend API. Every call hits a real
// endpoint; there are no mocked responses. The bearer token is kept in memory
// (and mirrored to sessionStorage) after login.

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
  first_seen: string | null;
  last_seen: string | null;
  assigned_analyst: string | null;
  correlation_reason: string;
  affected_entities: Record<string, unknown>;
  resolution_summary: string | null;
  close_reason: string | null;
  row_version: number;
  organization_id: string;
  related_finding_count?: number;
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  severity: string;
  confidence: number;
  description: string;
  attack_techniques: string[];
  evidence: Record<string, unknown>;
}

export interface TimelineItem {
  kind: string;
  timestamp: string;
  ref: string;
  summary: string;
}

let token: string | null = sessionStorage.getItem("aegis_token");
let orgId: string | null = sessionStorage.getItem("aegis_org");
let role: string | null = sessionStorage.getItem("aegis_role");

export function getSession() {
  return { token, orgId, role };
}

function headers(): HeadersInit {
  const h: HeadersInit = { "Content-Type": "application/json" };
  if (token) h["Authorization"] = `Bearer ${token}`;
  return h;
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

export async function login(username: string, password: string): Promise<void> {
  const res = await fetch("/api/v1/auth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await handle<{ access_token: string; role: string; organization_id: string }>(res);
  token = data.access_token;
  orgId = data.organization_id;
  role = data.role;
  sessionStorage.setItem("aegis_token", token);
  sessionStorage.setItem("aegis_org", orgId);
  sessionStorage.setItem("aegis_role", role);
}

export function logout(): void {
  token = null;
  orgId = null;
  role = null;
  sessionStorage.clear();
}

export async function listIncidents(params: {
  status?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}): Promise<{ total: number; items: Incident[] }> {
  const q = new URLSearchParams();
  if (params.status) q.set("status", params.status);
  if (params.severity) q.set("severity", params.severity);
  q.set("limit", String(params.limit ?? 50));
  q.set("offset", String(params.offset ?? 0));
  return handle(await fetch(`/api/v1/incidents?${q}`, { headers: headers() }));
}

export async function getIncident(id: string): Promise<Incident> {
  return handle(await fetch(`/api/v1/incidents/${id}`, { headers: headers() }));
}

export async function getEvidence(id: string): Promise<{ findings: Finding[]; events: unknown[] }> {
  return handle(await fetch(`/api/v1/incidents/${id}/evidence`, { headers: headers() }));
}

export async function getTimeline(id: string): Promise<{ timeline: TimelineItem[] }> {
  return handle(await fetch(`/api/v1/incidents/${id}/timeline`, { headers: headers() }));
}

export async function getHistory(id: string): Promise<{ actions: unknown[] }> {
  return handle(await fetch(`/api/v1/incidents/${id}/history`, { headers: headers() }));
}

export async function addNote(id: string, note: string): Promise<void> {
  await handle(
    await fetch(`/api/v1/incidents/${id}/notes`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ note }),
    }),
  );
}

export async function changeStatus(id: string, status: string): Promise<void> {
  await handle(
    await fetch(`/api/v1/incidents/${id}`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ status }),
    }),
  );
}

export async function assign(id: string, analystId: string): Promise<void> {
  await handle(
    await fetch(`/api/v1/incidents/${id}/assign`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ analyst_id: analystId }),
    }),
  );
}

export async function closeIncident(id: string, reason: string): Promise<void> {
  await handle(
    await fetch(`/api/v1/incidents/${id}/close`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ reason }),
    }),
  );
}
