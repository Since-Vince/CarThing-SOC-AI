import test from 'node:test';
import assert from 'node:assert/strict';
import { buildConfigCandidates } from '../server/config-paths.js';

test('worker with DeskThing-only environment resolves native Windows home directory', () => {
  const candidates = buildConfigCandidates(
    { DESKTHING_URL: 'app.js', DESKTHING_APP_NAME: 'carthing-soc' },
    ['C:\\Users\\ExampleUser'],
    'win32'
  );
  assert.deepEqual(candidates, ['C:\\Users\\ExampleUser\\AppData\\Local\\CarThingSOC\\config.json']);
});

test('explicit LOCALAPPDATA remains supported and duplicate paths collapse', () => {
  const c = buildConfigCandidates(
    { LOCALAPPDATA: 'C:\\Users\\ExampleUser\\AppData\\Local', USERPROFILE: 'C:\\Users\\ExampleUser' },
    ['C:\\Users\\ExampleUser'], 'win32'
  );
  assert.equal(c.length, 1);
});
