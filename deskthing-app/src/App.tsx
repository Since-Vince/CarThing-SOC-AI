import { useEffect, useState, useRef } from 'react';
import { DeskThing } from '@deskthing/client';

type Alert = {
  id: string; description: string; agent: string; source_ip: string;
  level: number | null; severity: string; timestamp: string;
  rule_id?: string; event_id?: string; username?: string; logon_type?: string;
  failure_reason?: string; workstation?: string; mitre_ids?: string[];
};
type AIReport = {
  report_type: string;
  facts: Record<string, unknown>;
  correlation: { sample_records: number; same_host_matching_records_in_sample: number; matching_event_ids: Record<string, number>; sample_scope: string };
  ai: { verdict: string; summary: string; supporting_evidence: string; alternative_explanation: string; next_steps: string; limitations: string; model: string; disclaimer: string };
};
type AIState = { alertId: string; status: 'starting' | 'analyzing' | 'complete' | 'failed'; error?: string | null; report?: AIReport };
type Container = { name: string; state: string; health: string };
type Data = {
  host: { status: string; hostname: string; cpu: number | null; ram: number | null; disk: number | null; uptime: number | null; free: number | null };
  tailscale: { status: string; connected: boolean; peers: number | null; ip: string };
  docker: { status: string; running: number | null; total: number | null; containers: Container[] };
  wazuh: { status: string; window: number | null; returned: number | null; counts: Record<string, number>; alerts: Alert[] };
};
type State = { connected: boolean; updatedAt: string | null; error: string | null; data: Data | null };
const TABS = ['OVERVIEW', 'SECURITY', 'SERVICES', 'NETWORK'];
const api = DeskThing;
// This demo is local to the display and is never inserted in live Wazuh results.
const EXAMPLE: Alert = {
  id: 'EXAMPLE-4625', description: 'Windows failed logon (demonstration)', agent: 'STARBOY',
  level: 9, severity: 'high', timestamp: 'EXAMPLE ONLY', rule_id: 'EXAMPLE',
  source_ip: '10.0.0.25', event_id: '4625', username: 'lab-user',
  logon_type: '3', failure_reason: 'Bad password (illustrative)',
  workstation: 'STARBOY', mitre_ids: []
};
const field = (value?: string | number | null) => value === '' || value == null ? 'Not reported' : String(value);

const pct = (value: number | null | undefined) => value == null ? '--' : `${value.toFixed(1)}%`;
const asNum = (value: number | null | undefined) => value == null ? '--' : String(value);
const uptime = (s: number | null) => s == null ? '--' : `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
const ago = (date: string | null) => {
  if (!date) return 'NO DATA';
  const sec = Math.max(0, Math.round((Date.now() - Date.parse(date)) / 1000));
  return !Number.isFinite(sec) ? 'UNKNOWN' : `${sec}s AGO`;
};
const clip = (str: string, n = 66) => str.length > n ? str.slice(0, n - 1) + '…' : str;
const statusClass = (ok: boolean) => ok ? 'ok' : 'bad';

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return <div className="stat"><div className={`stat-number ${tone || ''}`}>{value}</div><div className="stat-label">{label}</div></div>;
}
function Summary({ data }: { data: Data }) {
  const { host, wazuh, docker, tailscale } = data;
  return <div className="cols">
    <div className="panel">
      <div className="eyebrow">SERVER HEALTH <span className="pale">{clip(host.hostname || 'UBUNTU', 20)}</span></div>
      <div className="stats three"><Stat label="CPU" value={pct(host.cpu)}/><Stat label="RAM" value={pct(host.ram)}/><Stat label="DISK" value={pct(host.disk)}/></div>
      <div className="panel-footer">UPTIME {uptime(host.uptime)}</div>
    </div>
    <div className="panel">
      <div className="eyebrow">SECURITY SNAPSHOT <span className="pale">{wazuh.status === 'ok' ? 'WAZUH' : 'UNAVAILABLE'}</span></div>
      <div className="stats three"><Stat label="CRITICAL" value={wazuh.counts.critical} tone="red"/><Stat label="HIGH" value={wazuh.counts.high} tone="gold"/><Stat label="MEDIUM" value={wazuh.counts.medium} tone="cyan"/></div>
      <div className="panel-footer">{asNum(wazuh.returned)} RECENT ALERTS · SAMPLE COUNTS</div>
    </div>
    <div className="strip wide">
      <span className="dot green"/><strong>DOCKER</strong> {asNum(docker.running)}/{asNum(docker.total)} RUNNING
      <span className="sep"/>
      <span className={`dot ${tailscale.connected ? 'green' : 'red-dot'}`}/><strong>TAILSCALE</strong> {tailscale.connected ? 'CONNECTED' : 'OFFLINE'}
    </div>
  </div>;
}
function Alerts({ data, onInspect, onExample }: { data: Data; onInspect: (a: Alert) => void; onExample: () => void }) {
  const alerts = data.wazuh.alerts;
  return <div className="panel fill">
    <div className="eyebrow alert-topline">
      <span>LATEST WAZUH EVENTS</span>
      <button type="button" className="example-btn" onClick={onExample}>TRY 4625 EXAMPLE</button>
      <span className="pale">{alerts.length} RECORDS · {data.wazuh.window || 24}H</span>
    </div>
    <div className="scroll-list">
      {alerts.length ? alerts.map((a, i) => <button type="button" className="event event-button" key={`${a.id}-${i}`} onClick={() => onInspect(a)} aria-label={`Investigate ${a.severity} alert ${a.description}`}>
        <div className="event-main"><span className={`sev ${a.severity}`}>{a.severity.toUpperCase()}</span><div className="event-text">{clip(a.description, 73)}</div><span className="event-chevron">DETAILS ›</span></div>
        <div className="event-meta">{clip(a.agent || 'UNKNOWN', 22)} · LEVEL {a.level ?? '--'} · {a.timestamp.slice(11,19) || '--'}</div>
      </button>) : <div className="empty">{data.wazuh.status === 'ok' ? 'No recent alerts in this sample.' : 'Wazuh source unavailable.'}</div>}
    </div><div className="panel-footer">TAP AN ALERT TO INVESTIGATE · SAMPLE COUNTS ONLY</div>
  </div>;
}
const logonLabel = (t?: string) => t === '3' ? '3 — Network' : t === '2' ? '2 — Interactive' : t === '10' ? '10 — Remote interactive' : field(t);
function Investigation({ alert, demo, onBack, onPrev, onNext, count, aiState, onAnalyze }: {
  alert: Alert; demo: boolean; onBack: () => void; onPrev: () => void; onNext: () => void; count: number;
  aiState: AIState | null; onAnalyze: (alert: Alert) => void;
}) {
  const items = [
    ['EVENT TIME', field(alert.timestamp)],
    ['AGENT', field(alert.agent)],
    ['EVENT ID', field(alert.event_id)],
    ['WAZUH RULE', field(alert.rule_id)],
    ['ACCOUNT', field(alert.username)],
    ['SOURCE IP', field(alert.source_ip)],
    ['LOGON TYPE', logonLabel(alert.logon_type)],
    ['FAILURE / STATUS', field(alert.failure_reason)],
    ['WORKSTATION', field(alert.workstation)],
    ['WAZUH ALERT ID', field(alert.id)],
  ];
  const [showFullAiReport, setShowFullAiReport] = useState(false);
  return <div className="panel detail-panel fill">
    <div className="detail-heading">
      <button type="button" className="detail-back" onClick={onBack}>‹ BACK TO ALERTS</button>
      <span className="eyebrow">INVESTIGATE ALERT</span>
      <span className={`sev ${alert.severity}`}>{alert.severity.toUpperCase()}</span>
      {demo && <span className="demo-pill">DEMO — NOT LIVE</span>}
    </div>
    <div className="detail-scroll">
      <div className="detail-title">{alert.description}</div>
      <div className="ai-box ai-summary-top" aria-live="polite">
        <div className="ai-title">OLLAMA // SECURITY INVESTIGATION <span>ON DEMAND</span></div>
        {demo ? <div className="detail-caution">Choose a real Wazuh event to run local AI analysis.</div> : <>
          {aiState?.status === 'complete' && aiState.report ? <>
            <div className="ai-conclusion"><span>AI SUMMARY</span><span className="ai-verdict-badge">{field(aiState.report.ai?.verdict).replace(/_/g, ' ').toUpperCase()} · PROVISIONAL</span></div>
            <p className="ai-main-summary">{field(aiState.report.ai?.summary)}</p>
            <div className="ai-quick-evidence"><strong>KEY EVIDENCE</strong><span>{field(aiState.report.ai?.supporting_evidence)}</span></div>
            <div className="ai-summary-actions">
              <button type="button" onClick={() => setShowFullAiReport(v => !v)}>{showFullAiReport ? 'HIDE FULL REPORT ↑' : 'VIEW FULL REPORT ↓'}</button>
              <button type="button" onClick={() => { setShowFullAiReport(false); onAnalyze(alert); }}>↻ ANALYZE AGAIN</button>
            </div>
            {showFullAiReport && <div className="ai-report" aria-label="Full AI report">
              <div><b>RELATED EVENTS (SAMPLE)</b><p>{aiState.report.correlation?.same_host_matching_records_in_sample ?? 0} related records in {aiState.report.correlation?.sample_records ?? 0} recent Wazuh records; not full incident history.</p></div>
              <div><b>ALTERNATIVE EXPLANATION</b><p>{field(aiState.report.ai?.alternative_explanation)}</p></div>
              <div><b>NEXT STEPS</b><p>{field(aiState.report.ai?.next_steps)}</p></div>
              <div><b>LIMITATIONS</b><p>{field(aiState.report.ai?.limitations)}</p></div>
              <div className="ai-hint">{field(aiState.report.ai?.disclaimer)} · Model: {field(aiState.report.ai?.model)}</div>
            </div>}
          </> : <>
            <button className="ai-button" type="button" disabled={aiState?.status === 'starting' || aiState?.status === 'analyzing'} onClick={() => onAnalyze(alert)}>
              {aiState?.status === 'starting' ? '◌ REQUESTING ANALYSIS…' : aiState?.status === 'analyzing' ? '◌ OLLAMA ANALYZING…' : '✦ INVESTIGATE WITH AI'}
            </button>
            {(aiState?.status === 'starting' || aiState?.status === 'analyzing') && <div className="ai-hint">Waiting for a local Ollama report. You can keep this alert open; results appear here automatically when delivered.</div>}
            {aiState?.status === 'failed' && <div className="ai-error" role="alert">{aiState.error || 'Analysis failed.'} Check the DeskThing app worker and try again.</div>}
          </>}
        </>}
      </div>
      <div className="detail-grid">{items.map(([label, value]) => <div className="detail-field" key={label}><div className="detail-label">{label}</div><div className="detail-value">{value}</div></div>)}</div>
      {alert.mitre_ids?.length ? <div className="detail-mitre">MITRE IDS: {alert.mitre_ids.join(', ')}</div> : null}
      <div className="investigate-note"><strong>INVESTIGATION CHECKLIST</strong>
        <span>{alert.event_id === '4625' ? 'Compare nearby failed and successful logons, source IPs, affected accounts, and possible password changes.' : alert.event_id === '5038' || alert.event_id === '3004' ? 'Identify the affected file and publisher, verify the signature on the endpoint, and check whether related integrity failures repeat.' : 'Compare related events and affected hosts; verify evidence before marking any alert a true or false positive.'}</span>
      </div>
      <div className="detail-caution">{demo ? 'This is a local illustration. It is not a Wazuh event.' : 'Read-only alert snapshot. Blank fields mean Wazuh did not provide that metadata.'}</div>
    </div>
    {!demo && count > 1 && <div className="detail-actions"><button onClick={onPrev}>‹ PREVIOUS ALERT</button><span>TURN KNOB TO BROWSE</span><button onClick={onNext}>NEXT ALERT ›</button></div>}
  </div>;
}

function Services({ data }: { data: Data }) {
  const { docker } = data;
  return <div className="panel fill">
    <div className="eyebrow">DOCKER SERVICES <span className="pale">{asNum(docker.running)} / {asNum(docker.total)} RUNNING</span></div>
    <div className="scroll-list two-col">
      {docker.containers.map((item, i) => <div key={`${item.name}-${i}`} className="service">
        <span className="service-name">{clip(item.name, 24)}</span><span className={`pill ${statusClass(item.state === 'running')}`}>{item.state.toUpperCase()}</span>
      </div>)}
      {!docker.containers.length && <div className="empty">Docker metrics unavailable.</div>}
    </div>
    <div className="panel-footer">READ-ONLY · NO CONTAINER CONTROLS</div>
  </div>;
}
function Network({ data }: { data: Data }) {
  return <div className="cols">
    <div className="panel"><div className="eyebrow">TAILSCALE NETWORK</div>
      <div className="network-state"><span className={`dot ${data.tailscale.connected ? 'green' : 'red-dot'}`}/>{data.tailscale.connected ? 'CONNECTED' : 'OFFLINE'}</div>
      <div className="info-row"><span>TAILNET PEERS</span><strong>{asNum(data.tailscale.peers)}</strong></div>
      <div className="info-row"><span>TAILSCALE IP</span><strong>{data.tailscale.ip || '--'}</strong></div>
    </div>
    <div className="panel"><div className="eyebrow">UBUNTU SERVER</div>
      <div className="info-row"><span>HOST</span><strong>{clip(data.host.hostname, 21)}</strong></div>
      <div className="info-row"><span>UPTIME</span><strong>{uptime(data.host.uptime)}</strong></div>
      <div className="info-row"><span>DISK FREE</span><strong>{data.host.free == null ? '--' : `${data.host.free.toFixed(1)} GB`}</strong></div>
      <div className="info-row"><span>MONITORING</span><strong className="accent">READ ONLY</strong></div>
    </div>
  </div>;
}
export default function App() {
  const [state, setState] = useState<State>({ connected: false, updatedAt: null, error: null, data: null });
  const [page, setPage] = useState(0);
  const [inspection, setInspection] = useState<Alert | null>(null);
  const [aiStatus, setAiStatus] = useState<AIState | null>(null);
  const pageRef = useRef(0);
  const inspectionRef = useRef<Alert | null>(null);
  const currentAlertsRef = useRef<Alert[]>([]);
  const [, setTick] = useState(0);
  const aiAttemptIdRef = useRef<string | null>(null);
  const aiIgnoredIdRef = useRef<string | null>(null);
  const aiAckTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const aiDeadlineTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearAiTimers = () => {
    if (aiAckTimer.current) clearTimeout(aiAckTimer.current);
    if (aiDeadlineTimer.current) clearTimeout(aiDeadlineTimer.current);
    aiAckTimer.current = null;
    aiDeadlineTimer.current = null;
  };

  const startAi = (alert: Alert) => {
    clearAiTimers();
    aiAttemptIdRef.current = alert.id;
    aiIgnoredIdRef.current = null;
    setAiStatus({ alertId: alert.id, status: 'starting' });
    // The Windows worker must acknowledge the request. Otherwise an installed
    // Web App can show ANALYZING forever even when the worker isn't running.
    aiAckTimer.current = setTimeout(() => {
      if (aiAttemptIdRef.current === alert.id) {
        aiAttemptIdRef.current = null;
        aiIgnoredIdRef.current = alert.id;
        setAiStatus({ alertId: alert.id, status: 'failed',
          error: 'DeskThing did not acknowledge this request within 15 seconds. In Windows DeskThing, pause/resume CarThing SOC and check Dev → Logs for an app-worker error.' });
      }
    }, 15000);
    aiDeadlineTimer.current = setTimeout(() => {
      if (aiAttemptIdRef.current === alert.id) {
        aiAttemptIdRef.current = null;
        aiIgnoredIdRef.current = alert.id;
        clearAiTimers();
        setAiStatus({ alertId: alert.id, status: 'failed',
          error: 'No result arrived in four minutes. The analysis may still be running on Ubuntu. Check DeskThing Dev → Logs and the carthing-soc service.' });
      }
    }, 240000);
    api.send({ type: 'soc_ai_request', payload: { alert_id: alert.id } });
    removeOldFocus();
  };
  const removeOldFocus = () => {
    const active = document.activeElement;
    if (active instanceof HTMLElement && active.tagName === 'BUTTON') active.blur();
  };
  const closeDetail = () => {
    inspectionRef.current = null;
    setInspection(null);
    api.send({ type: 'soc_detail_open', payload: { open: false } });
    removeOldFocus();
  };
  const openDetail = (alert: Alert) => {
    inspectionRef.current = alert;
    setInspection(alert);
    api.send({ type: 'soc_detail_open', payload: { open: true } });
    removeOldFocus();
  };
  const browseDetail = (step: number) => {
    const current = inspectionRef.current;
    if (!current || current.id === EXAMPLE.id) return;
    const list = currentAlertsRef.current;
    if (!list.length) return;
    const position = list.findIndex(a => a.id === current.id);
    const next = (Math.max(0, position) + step + list.length) % list.length;
    inspectionRef.current = list[next];
    setInspection(list[next]);
    removeOldFocus();
  };
  const selectPage = (target: number) => {
    if (!Number.isInteger(target) || target < 0 || target >= TABS.length) return;
    if (target !== 1 && inspectionRef.current) closeDetail();
    pageRef.current = target;
    setPage(target);
    removeOldFocus();
    api.send({ type: 'soc_set_page', payload: { page: target } });
  };
  const navigate = (step: number) => {
    if (inspectionRef.current) browseDetail(step);
    else selectPage((pageRef.current + step + TABS.length) % TABS.length);
  };
  useEffect(() => {
    const offState = api.on('soc_state', (packet: any) => {
      if (packet?.payload) {
        const incoming = packet.payload as State;
        currentAlertsRef.current = incoming.data?.wazuh?.alerts || [];
        setState(incoming);
      }
    });
    const offPage = api.on('soc_page', (packet: any) => {
      const target = Number(packet?.payload?.page);
      if (Number.isInteger(target) && target >= 0 && target < TABS.length) {
        if (target !== 1 && inspectionRef.current) {
          inspectionRef.current = null;
          setInspection(null);
        }
        pageRef.current = target;
        setPage(target);
        removeOldFocus();
      }
    });
    const offAi = api.on('soc_ai_state', (packet: any) => {
      if (!packet?.payload) return;
      const incoming = packet.payload as AIState;
      if (aiIgnoredIdRef.current === incoming.alertId) return;
      // Do not overwrite a newer alert's result with a delayed older event.
      if (aiAttemptIdRef.current && incoming.alertId !== aiAttemptIdRef.current) return;
      if (aiAckTimer.current) { clearTimeout(aiAckTimer.current); aiAckTimer.current = null; }
      if (incoming.status === 'complete' || incoming.status === 'failed') {
        aiAttemptIdRef.current = null;
        clearAiTimers();
      }
      setAiStatus(incoming);
    });
    const offDetailStep = api.on('soc_detail_step', (packet: any) => {
      const step = Number(packet?.payload?.step);
      if (step === 1 || step === -1) browseDetail(step);
    });
    const t = setInterval(() => setTick(x => x + 1), 5000);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && inspectionRef.current) closeDetail();
      else if (e.key === 'ArrowRight') navigate(1);
      else if (e.key === 'ArrowLeft') navigate(-1);
    };
    window.addEventListener('keydown', onKey);
    api.send({ type: 'soc_request' });
    const retry = setTimeout(() => api.send({ type: 'soc_request' }), 1500);
    return () => { offState?.(); offPage?.(); offAi?.(); offDetailStep?.(); clearInterval(t); clearTimeout(retry); clearAiTimers(); window.removeEventListener('keydown', onKey); };
  }, []);
  const data = state.data;
  const stale = !state.connected || (!!state.updatedAt && (Date.now() - Date.parse(state.updatedAt) > 45000));
  return <main className="screen">
    <header className="header">
      <div className="brand"><div className="shield">✚</div><div><div className="brand-title">CARTHING <span>// SOC</span></div><div className="subtitle">HOME LAB SECURITY CONSOLE</div></div></div>
      <div className={`status-pill ${!stale ? 'up' : 'down'}`}><span className="dot"/>{!stale ? 'LIVE' : data ? 'STALE' : 'OFFLINE'} <span className="last-updated">· {ago(state.updatedAt)}</span></div>
    </header>
    <nav className="tabs">{TABS.map((title, i) => <button key={title} type="button" onClick={() => selectPage(i)} aria-current={page === i ? 'page' : undefined} className={page === i ? 'selected' : ''}>{title}</button>)}</nav>
    <section className="content">
      {data ? page === 0 ? <Summary data={data}/> : page === 1 ? inspection
          ? <Investigation alert={inspection} demo={inspection.id === EXAMPLE.id} count={data.wazuh.alerts.length} aiState={aiStatus?.alertId === inspection.id ? aiStatus : null} onAnalyze={startAi} onBack={closeDetail} onPrev={() => browseDetail(-1)} onNext={() => browseDetail(1)}/>
          : <Alerts data={data} onInspect={openDetail} onExample={() => openDetail(EXAMPLE)}/>
        : page === 2 ? <Services data={data}/> : <Network data={data}/>
        : <div className="unconfigured"><div className="loading-icon">◎</div><h2>{TABS[page]} — WAITING FOR SOC DATA</h2><p>{state.error || 'Connecting to Windows DeskThing server…'}</p><p className="hint">Check Windows bridge / Tailscale. Touch tabs switch screens even offline.</p></div>}
      {!!state.error && !!data && <div className="error-bubble">{clip(state.error, 120)}</div>}
    </section>
    <footer className="footer"><button onClick={() => navigate(-1)}>{inspection ? '‹ ALERT' : '‹ PREV'}</button><span>{inspection ? (inspection.id === EXAMPLE.id ? 'DEMO ALERT · NOT LIVE' : 'ALERT DETAILS · TURN KNOB TO BROWSE') : `${page + 1} / ${TABS.length} · TURN KNOB OR TAP TO NAVIGATE`}</span>{inspection && <button onClick={closeDetail}>BACK</button>}<button onClick={() => api.send({ type: 'soc_refresh' })}>↻ REFRESH</button><button onClick={() => navigate(1)}>{inspection ? 'ALERT ›' : 'NEXT ›'}</button></footer>
  </main>;
}
