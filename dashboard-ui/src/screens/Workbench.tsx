import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { CaseConfig, RunReport, exportRun, importCase, listCases, loadCase, rerunCase, sampleInput } from '../api/client';

const DEFAULT_CONFIG: CaseConfig = {bulk_access_threshold: 25, denial_streak_threshold: 3};
export function Workbench() {
  const [input, setInput] = useState('');
  const [title, setTitle] = useState('Local FHIR investigation');
  const [config, setConfig] = useState<CaseConfig>(DEFAULT_CONFIG);
  const [report, setReport] = useState<RunReport | null>(null);
  const [runs, setRuns] = useState<RunReport[]>([]);
  const [cases, setCases] = useState<{case_id: string; title: string}[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const revision = useRef(0);
  const pending = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  const caseListSequence = useRef(0);
  async function refreshCases() {
    const sequence = ++caseListSequence.current;
    try {
      const data = await listCases();
      if (mounted.current && caseListSequence.current === sequence) setCases(data.items);
    } catch (err) {
      if (mounted.current && caseListSequence.current === sequence) setError(String(err));
    }
  }
  useEffect(() => {
    mounted.current = true;
    void refreshCases();
    return () => {
      mounted.current = false;
      caseListSequence.current++;
      pending.current?.abort();
      revision.current++;
    };
  }, []);
  function invalidate(clear = true) {
    revision.current++; pending.current?.abort(); pending.current = null;
    setBusy(false); setError(''); setNotice('');
    if (clear) {setReport(null); setRuns([]);}
    return revision.current;
  }
  function edit(text: string) {invalidate(); setInput(text);}
  async function sample() {
    const id = invalidate();
    try {const data = await sampleInput(); if (revision.current === id) {setInput(data.input_text); setNotice(data.label);}} catch(e) {if (revision.current === id) setError(String(e));}
  }
  async function upload(file: File | undefined) {
    const id = invalidate(); // invalidates before asynchronous File.text finishes
    setInput('');
    if (!file) return;
    if (file.size > 1024 * 1024) {setError('File exceeds 1 MiB limit.'); return;}
    try {const text = await file.text(); if (revision.current === id) setInput(text);} catch(e) {if (revision.current === id) setError(String(e));}
  }
  async function openCase(caseId: string) {
    if (!caseId) return;
    const id = invalidate(); setInput(''); setBusy(true);
    try {const data = await loadCase(caseId); if (revision.current === id) {setRuns(data.runs); const last = data.runs[data.runs.length - 1] ?? null; setReport(last); if (last) {setConfig(last.config); setTitle(last.title);}}} catch(e) {if (revision.current === id) setError(String(e));} finally {if (revision.current === id) setBusy(false);}
  }
  async function run(rerun: boolean) {
    const prior = report;
    const id = invalidate(false); setReport(null); setBusy(true);
    const controller = new AbortController(); pending.current = controller;
    try {
      const result = rerun && prior ? await rerunCase(prior, config, controller.signal) : await importCase(input, title, config, controller.signal);
      if (revision.current !== id) return;
      setReport(result); setRuns(old => rerun ? [...old, result] : [result]);
      setNotice('Run persisted in PostgreSQL. Findings are review signals, not a verdict.');
      void refreshCases();
    } catch(e) {if (revision.current === id) setError(`${String(e)}. A cancelled response may still have committed; reload saved cases before retrying.`);} finally {if (revision.current === id) setBusy(false);}
  }
  async function download() {
    const snapshot = report;
    if (!snapshot) return;
    const id = revision.current;
    pending.current?.abort(); const controller = new AbortController(); pending.current = controller;
    try {
      const result = await exportRun(snapshot, controller.signal);
      if (revision.current !== id || controller.signal.aborted) return;
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${snapshot.run_id}.json`; anchor.click(); URL.revokeObjectURL(url);
      setNotice(`Export verified: SHA-256 ${result.sha256}`);
    } catch(e) {if (revision.current === id && !controller.signal.aborted) setError(String(e));}
  }
  function changeConfig(next: CaseConfig) {invalidate(false); setConfig(next);}
  const configChanged = !!report && JSON.stringify(report.config) !== JSON.stringify(config);
  return <div className="workbench">
    <header><p className="eyebrow">OFFLINE · LOCAL POSTGRESQL · AUTHENTICATED</p><h1>Security Investigation Workbench</h1><p>Import FHIR access events, inspect the evidence, then challenge the threshold.</p></header>
    <section aria-label="Import dataset"><h2>1. Choose a dataset</h2><p>Use synthetic data only in this local evaluation. JSON and extracted reference tokens are retained in your local database; tokens are not guaranteed anonymization.</p>
      <div className="workbench-actions"><button onClick={() => void sample()}>Load synthetic sample</button><label>FHIR JSON file <input aria-label="FHIR JSON file" type="file" accept=".json,application/json" onChange={e => void upload(e.target.files?.[0])}/></label></div>
      <label>Investigation title <input value={title} maxLength={160} onChange={e => {invalidate(); setTitle(e.target.value);}} /></label>
      <label>FHIR JSON (1 MiB, up to 1,000 entries)<textarea aria-label="FHIR JSON" rows={8} value={input} onChange={e => edit(e.target.value)} spellCheck={false}/></label>
      <label>Saved investigation <select aria-label="Saved investigation" value="" onChange={e => void openCase(e.target.value)}><option value="">Open a persisted case…</option>{cases.map(c => <option key={c.case_id} value={c.case_id}>{c.title} · {c.case_id.slice(-6)}</option>)}</select></label>
    </section>
    <section aria-label="Detection configuration"><h2>2. Configure and investigate</h2><p>Case-level thresholds apply to this entire imported batch. No care assignments or shift context are inferred.</p><div className="workbench-actions">
      <label>Distinct patient read threshold <input aria-label="Distinct patient read threshold" type="number" min={2} max={1000} value={config.bulk_access_threshold} onChange={e => changeConfig({...config, bulk_access_threshold: Number(e.target.value)})}/></label>
      <label>Denial streak threshold <input type="number" min={2} max={100} value={config.denial_streak_threshold} onChange={e => changeConfig({...config, denial_streak_threshold: Number(e.target.value)})}/></label>
      <button disabled={busy || !input.trim()} onClick={() => void run(false)}>Import and investigate</button>
      <button disabled={busy || !report} onClick={() => void run(true)}>Rerun same dataset</button>
    </div><p>FHIR outcomes 4/8/12 are failures, not proven authorization denials. Missing optional action/outcome stays UNKNOWN; invalid codes are rejected.</p></section>
    <div role="status" aria-live="polite">{busy ? 'Running the real detector and persisting evidence…' : notice}</div>{error && <p role="alert" className="error">{error}</p>}
    {report && <section aria-label="Run evidence"><h2>3. Evidence and finding delta</h2><div className="workbench-actions"><button disabled={busy || configChanged} onClick={() => void download()}>Export reproducible report</button><label>Run history <select aria-label="Run history" value={report.run_id} onChange={e => {const selected = runs.find(r => r.run_id === e.target.value); if (selected) {invalidate(false); setReport(selected); setConfig(selected.config);}}}>{runs.map(r => <option key={r.run_id} value={r.run_id}>{r.started_at} · threshold {r.config.bulk_access_threshold}</option>)}</select></label></div>
      {configChanged && <p>Configuration changed. Rerun to export a report for the new configuration.</p>}
      <div className="cards"><div className="card">Normalized <div className="num">{report.connector.normalized}</div></div><div className="card">Rejected <div className="num">{report.connector.rejected}</div></div><div className="card">Findings <div className="num" data-testid="finding-count">{report.findings.length}</div></div><div className="card">Delta <p data-testid="finding-delta">+{report.delta.added} / −{report.delta.removed} / {report.delta.unchanged} unchanged</p></div></div>
      <p>Origin: <strong>{report.data_origin}</strong> · Version {report.app_version} · {report.rule_version}</p><p className="hash">Input SHA-256 {report.input_sha256}<br/>Config SHA-256 {report.config_sha256}<br/>Source {report.source.commit} · clean {String(report.source.clean)}</p>
      {report.connector.rejected > 0 && <details><summary>Rejected / unsupported entries</summary><pre>{JSON.stringify(report.connector.errors, null, 2)}</pre></details>}
      {report.findings.length === 0 && <p>No findings under this configuration. This does not establish authorized access or absence of risk.</p>}
      {report.findings.map(f => <details key={f.finding_id} className="finding"><summary><strong>{f.rule_id}</strong> · {f.severity} · {f.description}</summary><p>{f.hypothesis}</p><p>{f.counter_evidence}</p><p>{f.uncertainty}</p><p>ATT&amp;CK mappings: {f.mapped_attack_techniques.join(', ') || 'None supported for this signal'}</p><p>Related persisted events: {f.related_event_ids.length}</p><pre>{JSON.stringify(f.evidence_references, null, 2)}</pre></details>)}
      {report.incidents.map(i => <p key={i.incident_id}><Link to={`/incidents/${i.incident_id}`}>{i.title}</Link> · {i.correlation_reason}</p>)}
      <h3>Persisted event timeline</h3><ol className="timeline">{report.events.map(e => <li key={`${e.event_id}-${e.source_index}`}><details><summary>{e.normalized.event_timestamp} · {e.normalized.identity_id} · {e.normalized.action} / {e.normalized.outcome}</summary><p>Persisted event {e.event_id} · source index {e.source_index}</p><h4>Source event</h4><pre>{JSON.stringify(e.source, null, 2)}</pre><h4>Normalized representation</h4><pre>{JSON.stringify(e.normalized, null, 2)}</pre></details></li>)}</ol>
      <h3>Uncertainty and limits</h3><ul>{report.limitations.map(l => <li key={l}>{l}</li>)}</ul>
    </section>}
    <footer>Aegis HealthSec 1.1.0 · Local investigation candidate · Separate automotive/firmware CLI workflows are not integrated here.</footer>
  </div>;
}
