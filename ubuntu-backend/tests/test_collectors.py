import json
from datetime import datetime, timedelta, timezone

from app.collectors import _normalize_alert, _tail_json_lines, wazuh_alerts
from app.config import Settings

KEY = 'test-key-at-least-24-characters-long'


def test_alert_severity_and_safe_fields():
    a = _normalize_alert({"timestamp":"t", "id":"a", "rule":{"level":12,"description":"ssh"},
                          "agent":{"name":"ubuntu"},"data":{"srcip":"192.168.1.2"}})
    assert a["severity"] == "critical"
    assert a["source_ip"] == "192.168.1.2"
    assert a["agent"] == "ubuntu"


def test_file_alerts_and_time_window(tmp_path):
    now = datetime.now(timezone.utc)
    path = tmp_path / 'alerts.json'
    items = [
        {"id":"older", "timestamp":(now-timedelta(days=4)).isoformat(),"rule":{"level":15}},
        {"id":"newer", "timestamp":now.isoformat(),"rule":{"level":8,"description":"Brute force"}},
    ]
    path.write_text('\n'.join(json.dumps(x) for x in items)+'\n')
    s = Settings(api_key=KEY, wazuh_mode='file', wazuh_alerts_file=str(path), alert_window_hours=24)
    out = wazuh_alerts(s)
    assert out['status'] == 'ok'
    assert out['returned'] == 1
    assert out['severity_in_returned']['high'] == 1
    assert out['alerts'][0]['id'] == 'newer'
    assert len(_tail_json_lines(str(path))) == 2


def test_disabled_and_missing_file_not_falsely_zero():
    disabled = wazuh_alerts(Settings(api_key=KEY, wazuh_mode='off'))
    assert disabled['status'] == 'disabled'
    missing = wazuh_alerts(Settings(api_key=KEY, wazuh_mode='file', wazuh_alerts_file='/definitely/not/a/file'))
    assert missing['status'] == 'unavailable'
    assert missing['message']


def test_indexer_https_required():
    s = Settings(api_key=KEY, wazuh_mode='indexer', wazuh_indexer_url='http://127.0.0.1:9200',
                 wazuh_indexer_user='reader', wazuh_indexer_password='secret')
    try:
        s.validate()
        assert False, 'Expected validation failure'
    except ValueError:
        pass


def test_indexer_query_read_only_and_tls(monkeypatch):
    import app.collectors as collectors
    now = datetime.now(timezone.utc).isoformat()
    seen = {}

    class Response:
        def raise_for_status(self): pass
        def json(self):
            return {'hits': {'hits': [{'_source': {'id': 'abc', 'timestamp': now,
                      'rule': {'level': 11, 'description': 'SSH brute force'}}}]}}

    def fake_post(url, **kwargs):
        seen['url'] = url
        seen.update(kwargs)
        return Response()

    monkeypatch.setattr(collectors.requests, 'post', fake_post)
    s = Settings(api_key=KEY, wazuh_mode='indexer', wazuh_indexer_url='https://10.0.0.5:9200',
                 wazuh_indexer_user='reader', wazuh_indexer_password='read-only',
                 wazuh_ca_bundle='/my/trusted/ca.pem')
    out = wazuh_alerts(s, limit=3)
    assert out['status'] == 'ok'
    assert out['alerts'][0]['severity'] == 'high'
    assert seen['url'].endswith('/wazuh-alerts-*/_search')
    assert seen['verify'] == '/my/trusted/ca.pem'
    assert seen['auth'] == ('reader', 'read-only')
    assert seen['json']['size'] == 3
    assert seen['json']['query']['range']['timestamp']['gte'] == 'now-24h'


def test_tailscale_status_json(monkeypatch):
    import app.collectors as collectors
    class Result:
        returncode = 0
        stdout = json.dumps({'BackendState': 'Running', 'Self': {'Online': True,
                'TailscaleIPs': ['100.101.102.103']}, 'Peer': {'a': {}, 'b': {}}})
    monkeypatch.setattr(collectors.subprocess, 'run', lambda *args, **kwargs: Result())
    out = collectors.tailscale_status(Settings(api_key=KEY))
    assert out['connected'] is True
    assert out['peer_count'] == 2


def test_docker_container_inspection(monkeypatch):
    import app.collectors as collectors
    import sys
    import types
    class Container:
        name = 'jellyfin'
        id = 'fake-123'
        status = 'running'
    class ContainerCollection:
        def list(self, all): return [Container()]
    class API:
        def inspect_container(self, container_id):
            return {'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}}
    class DockerClient:
        containers = ContainerCollection()
        api = API()
        def close(self): pass
    monkeypatch.setitem(sys.modules, 'docker', types.SimpleNamespace(from_env=lambda **kwargs: DockerClient()))
    out = collectors.docker_status(Settings(api_key=KEY, monitored_containers=('jellyfin','osticket')))
    assert out['status'] == 'ok'
    assert out['running'] == 1
    assert out['containers'][0] == {'name': 'jellyfin', 'state':'running','health':'healthy'}
    assert out['containers'][1]['state'] == 'missing'


def test_docker_wazuh_live_alerts(monkeypatch):
    import sys
    import types
    now = datetime.now(timezone.utc).isoformat()
    data = {"id":"event-1", "timestamp":now, "rule":{"level":13,"description":"SSH failures"}}
    seen = {}
    class Result:
        exit_code = 0
        output = (json.dumps(data) + "\n").encode()
    class Manager:
        def exec_run(self, cmd, **kwargs):
            seen["cmd"] = cmd
            return Result()
    class Collection:
        def get(self, name):
            seen["manager"] = name
            return Manager()
    class Client:
        containers = Collection()
        def close(self): pass
    monkeypatch.setitem(sys.modules, 'docker', types.SimpleNamespace(from_env=lambda **kw: Client()))
    s = Settings(api_key=KEY, wazuh_mode='docker', wazuh_docker_container='single-node-wazuh.manager-1')
    s.validate()
    out = wazuh_alerts(s, limit=3)
    assert out['status'] == 'ok'
    assert out['returned'] == 1
    assert out['alerts'][0]['severity'] == 'critical'
    assert seen['manager'] == 'single-node-wazuh.manager-1'
    assert seen['cmd'] == ['tail', '-n', '2000', '/var/ossec/logs/alerts/alerts.json']


def test_docker_wazuh_permission_or_missing_file_is_unavailable(monkeypatch):
    import sys
    import types
    class Result:
        exit_code = 1
        output = b'permission denied'
    class Manager:
        def exec_run(self, cmd, **kwargs): return Result()
    class Collection:
        def get(self, name): return Manager()
    class Client:
        containers = Collection()
        def close(self): pass
    monkeypatch.setitem(sys.modules, 'docker', types.SimpleNamespace(from_env=lambda **kw: Client()))
    out = wazuh_alerts(Settings(api_key=KEY, wazuh_mode='docker'))
    assert out['status'] == 'unavailable'
    assert out['returned'] == 0
    assert 'permission denied' not in out['message']
