import os
# A test-only key is needed because app.main intentionally validates its settings at import.
os.environ.setdefault('CARTHING_API_KEY', 'fake-test-key-that-is-long-enough-123')

from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app

KEY = 'fake-test-key-that-is-long-enough-123'


def client():
    return TestClient(create_app(Settings(api_key=KEY, wazuh_mode='off')))


def test_api_key_required():
    with client() as c:
        assert c.get('/api/v1/overview').status_code == 401
        assert c.get('/api/v1/overview', headers={'X-API-Key':'wrong'}).status_code == 401
        assert c.get('/healthz').json()['status'] == 'alive'


def test_overview_schema_and_disabled_alerts():
    with client() as c:
        r = c.get('/api/v1/overview', headers={'X-API-Key':KEY})
        assert r.status_code == 200
        data = r.json()
        assert data['schema_version'] == 1
        assert data['wazuh']['status'] == 'disabled'
        assert all(x in data for x in ('server','docker','tailscale','auth','generated_at'))


def test_alert_limit_validation_and_preview():
    with client() as c:
        assert c.get('/api/v1/alerts?limit=51', headers={'X-API-Key':KEY}).status_code == 422
        assert c.get('/api/v1/alerts?limit=2', headers={'X-API-Key':KEY}).status_code == 200
        assert 'CARTHING // SOC' in c.get('/').text
