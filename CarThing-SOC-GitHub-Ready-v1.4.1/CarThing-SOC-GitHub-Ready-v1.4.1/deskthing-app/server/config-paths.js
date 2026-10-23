/** Resolves the Windows bridge configuration despite DeskThing worker env isolation.
 * DeskThing v0.11.x workers are spawned with only DESKTHING_* environment vars.
 * Node os.homedir() falls back to the Windows profile API when USERPROFILE is absent.
 */
import { win32, posix } from 'node:path';

export function buildConfigCandidates(env = {}, homes = [], platform = 'win32') {
  const path = platform === 'win32' ? win32 : posix;
  const unique = new Set();
  const add = (folder) => {
    if (typeof folder === 'string' && folder.trim()) {
      unique.add(path.join(folder, 'CarThingSOC', 'config.json'));
    }
  };
  add(env.LOCALAPPDATA);
  const homeCandidates = [
    ...(Array.isArray(homes) ? homes : [homes]),
    env.USERPROFILE,
    env.HOMEDRIVE && env.HOMEPATH ? env.HOMEDRIVE + env.HOMEPATH : '',
    env.HOME,
  ];
  for (const home of homeCandidates) {
    if (typeof home === 'string' && home.trim()) {
      add(path.join(home, 'AppData', 'Local'));
    }
  }
  if (env.APPDATA) add(path.join(path.dirname(env.APPDATA), 'Local'));
  return [...unique];
}
