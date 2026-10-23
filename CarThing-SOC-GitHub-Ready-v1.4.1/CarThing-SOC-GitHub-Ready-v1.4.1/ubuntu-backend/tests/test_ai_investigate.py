import os
os.environ.setdefault('CARTHING_API_KEY', 'fake-test-key-that-is-long-enough-123')
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.ai_investigate import sanitized, evidence, InvestigationJobs, query_ollama, JobError
from app.config import Settings
from app.main import create_app
import time

EVENT = {
    'id':'1792556737.737417', 'timestamp':'2026-10-21T04:25:37Z',
    'agent': {'name':'STARBOY'},
    'rule': {'id':'60104', 'level':5, 'description':'Windows audit failure event'},
    'data': {'win': {'system': {'eventID': '5038'}, 'eventdata': {
        'param1': r'\\Device\\HarddiskVolume3\\Program Files\\Surfshark\\avamsi.dll'}}}
}


def test_5038_is_code_integrity_not_auth():
    f = sanitized(EVENT)
    assert 'Code Integrity' in f['verified_event_meaning']
    assert 'avamsi.dll' in f['filename']
    assert 'failed login' not in f['verified_event_meaning'].lower()


def test_4688_is_real():
    x = dict(EVENT)
    x['data'] = {'win':{'system':{'eventID':'4688'}}}
    assert 'process' in sanitized(x)['verified_event_meaning']


def test_no_full_log_or_secret_transferred():
    x = dict(EVENT)
    x['full_log'] = 'SECRET IN RAW LOG'
    assert 'full_log' not in sanitized(x)


def test_correlation_sample_scope_and_count():
    e = evidence(EVENT,[EVENT, EVENT])
    assert e['correlation']['same_host_matching_records_in_sample'] == 2
    assert e['correlation']['matching_event_ids']['5038'] == 2
    assert e['correlation']['sample_records'] == 2


def test_invalid_id_rejected():
    jobs = InvestigationJobs(Settings(wazuh_mode='off'))
    for s in ('../../etc/passwd','', 'x'*500):
        try:
            jobs.submit(s)
            assert False, 'Invalid id accepted'
        except JobError as err:
            assert err.code == 400


def test_job_executes_on_demand():
    jobs = InvestigationJobs(Settings(wazuh_mode='docker'))
    fake_analysis = {'verdict':'inconclusive', 'summary':'Test', 'model':'fake'}
    with patch('app.ai_investigate.read_events',return_value=[EVENT]), patch('app.ai_investigate.query_ollama',return_value=fake_analysis):
        start = jobs.submit(EVENT['id'])
        for _ in range(150):
            result = jobs.get(start['job_id'])
            if result['status'] == 'complete': break
            time.sleep(.01)
        assert result['status'] == 'complete'
        assert result['facts']['windows_event_id'] == '5038'
        assert result['ai']['verdict'] == 'inconclusive'


def test_api_is_authenticated():
    app = create_app(Settings(api_key='fake-test-key-that-is-long-enough-123',wazuh_mode='off'))
    with TestClient(app) as c:
        assert c.post('/api/v1/ai/investigate',json={'alert_id':'1'}).status_code == 401
        assert c.get('/api/v1/ai/investigate/123').status_code == 401
        assert c.post('/api/v1/ai/investigate',json={'alert_id':'../../x'},
                      headers={'X-API-Key':'fake-test-key-that-is-long-enough-123'}).status_code == 400


def test_5038_hallucination_never_shown_as_auth_failure():
    from unittest.mock import MagicMock
    import json
    fake = MagicMock()
    fake.read.return_value = json.dumps({'message':{'content':json.dumps({
        'verdict':'likely_false_positive',
        'summary':'Windows event 5038 is a failed login.',
        'supporting_evidence':'Failed authentication from the same user.',
        'next_steps':'Investigate account',
    })}}).encode('utf-8')
    fake_context = MagicMock()
    fake_context.__enter__.return_value = fake
    with patch('app.ai_investigate.urllib.request.urlopen', return_value=fake_context):
        result = query_ollama(evidence(EVENT,[EVENT,EVENT]))
    assert result['verdict'] == 'inconclusive'
    assert 'contradicted' in result['summary']
    assert 'failed login' not in result['summary']
