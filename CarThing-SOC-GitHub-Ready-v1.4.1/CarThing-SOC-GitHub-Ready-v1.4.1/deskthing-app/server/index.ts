/** DeskThing server worker (runs on Windows PC, not on the Car Thing). */
import { DeskThing } from '@deskthing/server';
import { DESKTHING_EVENTS } from '@deskthing/types';
import { readFileSync, existsSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { buildConfigCandidates } from './config-paths.js';
import { normalizeOverview, validateEndpoint } from './normalize.js';

// DeskThing 0.11.17 creates worker threads with a restricted `env` map:
// { DESKTHING_URL, DESKTHING_APP_NAME }. LOCALAPPDATA/USERPROFILE are therefore
// missing even when the Windows configuration file really exists. Use native
// os.homedir()/os.userInfo() as fallbacks; they resolve the current Windows user.
function configCandidates() {
  const homes = [];
  try { homes.push(homedir()); } catch { /* native lookup may fail */ }
  try { homes.push(userInfo().homedir); } catch { /* optional backup */ }
  return buildConfigCandidates(process.env, homes, process.platform);
}
let timer = null;
let running = false;
let busy = false;
let registered = false;
let currentPage = 0;
let investigating = false;
let aiStatus = null;
let aiInFlight = false;
let latest = { connected: false, updatedAt: null, error: 'Waiting for the Windows bridge', data: null };
const PAGES = 4;

function emitState() {
  DeskThing.send({ type: 'soc_state', payload: latest });
}
function emitAi() { if (aiStatus) DeskThing.send({ type: 'soc_ai_state', payload: aiStatus }); }
async function apiRequest(url, apiKey, method = 'GET', body = undefined) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    return await fetch(url, {
      method, headers: { 'X-API-Key': apiKey, 'Accept': 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      cache: 'no-store', signal: controller.signal
    });
  } finally { clearTimeout(timeout); }
}
async function investigateOnDemand(id) {
  // Never called by timers: this runs only from an explicit touch action.
  if (aiInFlight) {
    aiStatus = { alertId: id, status: 'failed', error: 'Another AI investigation is running. Please wait.' };
    emitAi(); return;
  }
  if (!/^[A-Za-z0-9_.:-]{1,96}$/.test(id) || id.startsWith('EXAMPLE')) {
    aiStatus = { alertId: id, status: 'failed', error: 'Select a real Wazuh alert to investigate.' };
    emitAi(); return;
  }
  aiInFlight = true;
  aiStatus = { alertId: id, status: 'starting', error: null };
  emitAi();
  try {
    const { url, apiKey } = readConfig();
    const endpoint = new URL('/api/v1/ai/investigate', url).toString();
    const response = await apiRequest(endpoint, apiKey, 'POST', { alert_id: id });
    if (!response.ok) throw new Error(response.status === 404 ? 'The selected Wazuh alert was not found.' :
      response.status === 429 ? 'Another investigation is running on Ubuntu.' :
      response.status === 401 ? 'API key rejected by Ubuntu.' : `AI backend returned HTTP ${response.status}. Is the v1.4 backend installed?`);
    const job = await response.json();
    aiStatus = { alertId: id, status: 'analyzing', error: null }; emitAi();
    if (!/^[a-f0-9-]{36}$/.test(String(job.job_id || ''))) throw new Error('Invalid investigation job response.');
    let attempts = 0;
    while (running && attempts++ < 75) {
      await new Promise(resolve => setTimeout(resolve, 3000));
      const result = await apiRequest(`${endpoint}/${job.job_id}`, apiKey);
      if (!result.ok) throw new Error('Could not retrieve investigation result.');
      const outcome = await result.json();
      if (outcome.status === 'complete') {
        aiStatus = { alertId: id, status: 'complete', report: outcome }; emitAi(); return;
      }
      if (outcome.status === 'failed') throw new Error(outcome.error || 'Ollama could not analyze the event.');
      aiStatus = { alertId: id, status: 'analyzing', error: null }; emitAi();
    }
    throw new Error('AI analysis is taking too long; please check Ollama and try again.');
  } catch (error) {
    let message = error instanceof Error ? error.message : 'Investigation failed.';
    if (!message.startsWith('The selected') && !message.startsWith('Another') &&
        !message.startsWith('API key') && !message.startsWith('AI backend') &&
        !message.startsWith('Could not retrieve') && !message.startsWith('Ollama') &&
        !message.startsWith('Invalid investigation') && !message.startsWith('AI analysis'))
      message = 'Unable to request AI analysis. Check your Ollama and SOC backend.';
    aiStatus = { alertId: id, status: 'failed', error: message }; emitAi();
  } finally { aiInFlight = false; }
}
function emitPage() {
  DeskThing.send({ type: 'soc_page', payload: { page: currentPage } });
}
function navigate(step) {
  if (investigating && currentPage === 1) {
    DeskThing.send({ type: 'soc_detail_step', payload: { step } });
    return;
  }
  currentPage = (currentPage + step + PAGES) % PAGES;
  emitPage();
}
function readConfig() {
  const file = configCandidates().find(path => existsSync(path));
  if (!file) throw new Error('Windows configuration file not found from DeskThing worker; check Windows user profile and restart app');
  let config;
  try { config = JSON.parse(readFileSync(file, 'utf8').replace(/^\uFEFF/, '')); }
  catch { throw new Error('Windows configuration file is unreadable or invalid JSON'); }
  if (!config?.apiKey || typeof config.apiKey !== 'string') {
    throw new Error('API key missing from Windows bridge configuration');
  }
  return {
    url: validateEndpoint(config.backendUrl), apiKey: config.apiKey
  };
}

async function poll() {
  if (busy || !running) return;
  busy = true;
  try {
    const { url, apiKey } = readConfig();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7500);
    let response;
    try {
      response = await fetch(url, {
        headers: { 'X-API-Key': apiKey, 'Accept': 'application/json' },
        cache: 'no-store', signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      if (response.status === 401) throw new Error('API key rejected (401); rerun Windows configuration');
      throw new Error(`Backend returned HTTP ${response.status}`);
    }
    const data = normalizeOverview(await response.json());
    latest = { connected: true, updatedAt: new Date().toISOString(), error: null, data };
  } catch (error) {
    // Never log the API key or raw error, which can contain a URL or other information.
    let message = error instanceof Error ? error.message : 'Unknown connection error';
    if (!message.startsWith('API key rejected') && !message.startsWith('Backend returned') &&
        !message.startsWith('Windows configuration') && !message.startsWith('API key missing') &&
        !message.startsWith('Unsupported') && !message.startsWith('Use HTTPS') &&
        !message.startsWith('Invalid backend')) message = 'Cannot reach your SOC backend. Check Tailscale and configuration.';
    latest = { connected: false, updatedAt: latest.updatedAt, error: message, data: latest.data };
  } finally {
    busy = false;
    emitState();
  }
}

async function registerMappings() {
  const actions = [
    ['soc_next', 'SOC: Next screen', 'Go to the next SOC screen'],
    ['soc_previous', 'SOC: Previous screen', 'Go to the previous SOC screen'],
    ['soc_refresh', 'SOC: Refresh now', 'Fetch the latest security metrics']
  ];
  for (const [id, name, description] of actions) {
    try {
      await DeskThing.registerAction({ id, name, description, tag: 'basic',
        version: '1.0.0', version_code: 100, enabled: true });
    } catch { /* Physical mapping optional; touch navigation always works. */ }
  }
  try { await DeskThing.registerKey({ id: 'scroll', description: 'Car Thing knob rotation' }); }
  catch { /* Optional key registration varies by client version. */ }
}

function registerHandlers() {
  if (registered) return;
  registered = true;
  DeskThing.on('soc_request', () => { emitState(); emitPage(); emitAi(); });
  DeskThing.on('soc_ai_request', event => {
    const id = event?.payload?.alert_id;
    if (typeof id === 'string') {
      console.log('[CarThing SOC] Received an on-demand AI investigation request.');
      void investigateOnDemand(id);
    }
  });
  DeskThing.on('soc_detail_open', event => { investigating = !!event?.payload?.open; });
  DeskThing.on('soc_nav', event => {
    const step = Number(event?.payload?.step || 0);
    if (step === 1 || step === -1) navigate(step);
  });
  DeskThing.on('soc_set_page', event => {
    const p = Number(event?.payload?.page);
    if (Number.isInteger(p) && p >= 0 && p < PAGES) { currentPage = p; if (p !== 1) investigating = false; emitPage(); }
  });
  DeskThing.on('soc_refresh', () => { void poll(); });
  DeskThing.on(DESKTHING_EVENTS.ACTION, event => {
    const id = event?.payload?.id || event?.id;
    if (id === 'soc_next') navigate(1);
    if (id === 'soc_previous') navigate(-1);
    if (id === 'soc_refresh') void poll();
  });
  DeskThing.on('scroll', event => {
    const raw = event?.payload?.direction ?? event?.payload?.value ?? 0;
    const dir = typeof raw === 'string' ? raw.toLowerCase() : raw;
    if (dir === 'up' || dir === -1) navigate(-1);
    else if (dir === 'down' || dir === 1) navigate(1);
  });
}

async function start() {
  if (running) return;
  running = true;
  registerHandlers();
  await registerMappings();
  investigating = false;
  emitState();
  emitPage();
  void poll();
  timer = setInterval(() => { void poll(); }, 15000);
  console.log('[CarThing SOC] Started read-only Windows bridge (native Windows-profile fallback enabled).');
}
async function stop() {
  running = false;
  if (timer) clearInterval(timer);
  timer = null;
}

DeskThing.on(DESKTHING_EVENTS.START, start);
DeskThing.on(DESKTHING_EVENTS.STOP, stop);
