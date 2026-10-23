/** Convert CarThing SOC API v1 overview data into a small, display-safe model. */
const text = (v, max = 100) => String(v ?? '').slice(0, max);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);

export function normalizeOverview(data) {
  if (!data || data.schema_version !== 1 || typeof data.server !== 'object' ||
      typeof data.wazuh !== 'object' || typeof data.docker !== 'object' ||
      typeof data.tailscale !== 'object') {
    throw new Error('Unsupported CarThing SOC backend response');
  }
  const {server = {}, docker = {}, tailscale = {}, wazuh = {}} = data;
  const counts = wazuh.severity_in_returned || {};
  return {
    host: {
      status: text(server.status, 24), hostname: text(server.hostname, 48),
      cpu: num(server.cpu_percent), ram: num(server.ram_percent), disk: num(server.disk_percent),
      uptime: num(server.uptime_seconds), free: num(server.disk_free_gb)
    },
    docker: {
      status: text(docker.status, 24), running: num(docker.running), total: num(docker.total),
      containers: (Array.isArray(docker.containers) ? docker.containers : []).slice(0, 30).map(x => ({
        name: text(x.name, 50), state: text(x.state, 25), health: text(x.health, 25)
      }))
    },
    tailscale: {
      status: text(tailscale.status, 24), connected: !!tailscale.connected,
      peers: num(tailscale.peer_count), ip: text((tailscale.tailscale_ips || [])[0], 64)
    },
    wazuh: {
      status: text(wazuh.status, 24), source: text(wazuh.source, 15),
      window: num(wazuh.window_hours), returned: num(wazuh.returned),
      counts: {
        critical: num(counts.critical) ?? 0, high: num(counts.high) ?? 0,
        medium: num(counts.medium) ?? 0, low: num(counts.low) ?? 0
      },
      alerts: (Array.isArray(wazuh.alerts) ? wazuh.alerts : []).slice(0, 15).map(a => ({
        id: text(a.id, 70), level: num(a.level), severity: text(a.severity, 15),
        description: text(a.description, 150), timestamp: text(a.timestamp, 55),
        agent: text(a.agent, 50), source_ip: text(a.source_ip, 64),
        rule_id: text(a.rule_id, 40), event_id: text(a.event_id, 20),
        username: text(a.username, 64), logon_type: text(a.logon_type, 16),
        failure_reason: text(a.failure_reason, 120), workstation: text(a.workstation, 64),
        mitre_ids: (Array.isArray(a.mitre_ids) ? a.mitre_ids : []).slice(0, 6).map(x => text(x, 25))
      }))
    },
    generatedAt: text(data.generated_at, 45)
  };
}

export function validateEndpoint(base) {
  const url = new URL(base);
  if (url.username || url.password || url.search || url.hash) throw new Error('Invalid backend address');
  const localhost = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && localhost)) {
    throw new Error('Use HTTPS (or localhost HTTP only)');
  }
  return new URL('/api/v1/overview', url).toString();
}
