import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeOverview, validateEndpoint } from '../server/normalize.js';

const sample = {
  schema_version: 1, generated_at: '2026-10-19T06:25:24+00:00',
  server: {status:'ok',hostname:'laptop',cpu_percent:2.4,ram_percent:27.7,disk_percent:27.1, uptime_seconds:12345, disk_free_gb:632.79},
  docker: {status:'ok',running:2,total:3,containers:[{name:'jellyfin',state:'running',health:'not_configured'}, {name:'osticket',state:'running',health:'healthy'}]},
  tailscale: {status:'ok',connected:true,peer_count:4,tailscale_ips:['100.101.102.103']},
  wazuh: {status:'ok',returned:2,window_hours:168,severity_in_returned:{critical:0,high:0,medium:1,low:1}, alerts:[{ id:'1', description:'Windows Logon Success', level:3, severity:'low', agent:'STARBOY', timestamp:'2026-10-19T06:21:40+00:00'}]}
};
test('normalizer maps actual v1.1 overview shape', () => {
 const x = normalizeOverview(sample);
 assert.equal(x.host.cpu,2.4);
 assert.equal(x.docker.running,2);
 assert.equal(x.tailscale.peers,4);
 assert.equal(x.wazuh.counts.medium,1);
 assert.equal(x.wazuh.alerts[0].agent,'STARBOY');
 assert.ok(!JSON.stringify(x).includes('apiKey'));
});
test('normalizer rejects incorrect API schema',()=>{
 assert.throws(()=>normalizeOverview({schema_version:3}));
});
test('endpoint validation enforces private HTTPS and rejects URL credentials',()=>{
 assert.equal(validateEndpoint('https://your-server.your-tailnet.ts.net'), 'https://your-server.your-tailnet.ts.net/api/v1/overview');
 assert.equal(validateEndpoint('http://127.0.0.1:8765/'), 'http://127.0.0.1:8765/api/v1/overview');
 assert.throws(()=>validateEndpoint('http://100.101.102.103:8765'));
 assert.throws(()=>validateEndpoint('https://user:pass@laptop.example'));
});

test('investigation fields are present when Wazuh reports them', () => {
 const sample4625 = structuredClone(sample);
 sample4625.wazuh.alerts = [{ id:'w-4625', level:9, severity:'high', description:'Windows failed logon',
  timestamp:'2026-10-20T18:00:00Z', agent:'STARBOY', rule_id:'60122', event_id:'4625',
  username:'lab-user', source_ip:'10.0.0.25', logon_type:'3',
  failure_reason:'0xC000006A', workstation:'STARBOY', mitre_ids:['T1110'] }];
 const a = normalizeOverview(sample4625).wazuh.alerts[0];
 assert.equal(a.event_id, '4625');
 assert.equal(a.username, 'lab-user');
 assert.equal(a.logon_type, '3');
 assert.equal(a.rule_id, '60122');
 assert.deepEqual(a.mitre_ids, ['T1110']);
});
test('older backend alerts remain usable without enrichment', () => {
 const a = normalizeOverview(sample).wazuh.alerts[0];
 assert.equal(a.event_id, '');
 assert.equal(a.rule_id, '');
 assert.deepEqual(a.mitre_ids, []);
});
test('enrichment is allowlisted, and values are bounded',()=>{
 const cloned = structuredClone(sample);
 cloned.wazuh.alerts = [{ id:'x', level:3, secret:'dont forward this', username: 'X'.repeat(180), mitre_ids: Array(20).fill('T1110') }];
 const a=normalizeOverview(cloned).wazuh.alerts[0];
 assert.equal(a.username.length,64);
 assert.equal(a.mitre_ids.length,6);
 assert.ok(!JSON.stringify(a).includes('dont forward this'));
});
