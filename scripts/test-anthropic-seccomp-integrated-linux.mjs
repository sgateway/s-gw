import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'linux' || process.getuid() === 0) {
  throw new Error('Run the integrated seccomp check as a non-root Linux user.');
}

const repo = fileURLToPath(new URL('../', import.meta.url));
const cli = path.join(repo, 'dist', 'cli.js');
const root = mkdtempSync(path.join(os.tmpdir(), 'sgw-seccomp-integrated-'));
const workspace = path.join(root, 'workspace');
const home = path.join(root, 'home');
const payload = path.join(workspace, 'socket-probe.py');
const directMarker = path.join(workspace, 'direct.started');
const sandboxMarker = path.join(workspace, 'sandbox.started');
const env = {
  PATH: process.env.PATH || '/usr/bin:/bin',
  HOME: home,
  TMPDIR: os.tmpdir(),
  LANG: 'C.UTF-8',
  SGW_HOME: path.join(root, 'store'),
  SGW_RECOVERY_HOME: path.join(root, 'recovery'),
  SGW_MASTER_PASSPHRASE: 'synthetic seccomp test passphrase',
  SGW_TEST_MODE: '1',
  SGW_TEST_HOME_ROOT: root,
  SGW_LOGIN_SESSION_ID: 'seccomp-integrated-test',
  SGW_ALLOW_NO_CGROUP: '1',
  SGW_ALLOW_NONINTERACTIVE_OPERATOR: '1',
  SGW_DISABLE_KEYCHAIN: '1',
  SGW_DISABLE_ONEPASSWORD_BACKUP: '1',
  SGW_DISABLE_UPDATE_CHECK: '1',
  SGW_DISABLE_PROCESS_AGENT_DETECTION: '1',
  SGW_SKIP_HOOK_INSTALL: '1'
};

function run(command, args) {
  const result = spawnSync(command, args, { cwd: repo, env, encoding: 'utf8', timeout: 120_000, maxBuffer: 1024 * 1024 });
  if (result.error) throw result.error;
  return result;
}

function details(result) {
  return `exit=${result.status} signal=${result.signal || 'none'}\n${result.stdout}\n${result.stderr}`;
}

try {
  mkdirSync(workspace);
  mkdirSync(home);
  writeFileSync(payload, `import errno, socket, sys
with open(sys.argv[1], 'x') as marker:
    marker.write('started')
print('SGW_PAYLOAD_STARTED', flush=True)
try:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
except OSError as error:
    if error.errno != errno.EPERM:
        raise
    with open(sys.argv[1], 'w') as marker:
        marker.write('AF_UNIX_DENIED')
    print('SGW_AF_UNIX_DENIED', flush=True)
else:
    sock.close()
    with open(sys.argv[1], 'w') as marker:
        marker.write('AF_UNIX_ALLOWED')
    print('SGW_AF_UNIX_ALLOWED', flush=True)
    sys.exit(41)
`);

  const direct = run('/usr/bin/python3', [payload, directMarker]);
  assert.equal(direct.status, 41, `The unfiltered control did not detect AF_UNIX access.\n${details(direct)}`);
  assert.equal(readFileSync(directMarker, 'utf8'), 'AF_UNIX_ALLOWED');
  assert.match(direct.stdout, /SGW_AF_UNIX_ALLOWED/);

  const init = run(process.execPath, [cli, 'init']);
  assert.equal(init.status, 0, `Synthetic store initialization failed.\n${details(init)}`);
  assert.equal(JSON.parse(init.stdout).storePath, path.join(root, 'store', 'store.json'));

  const launched = run(process.execPath, [cli, 'run', 'codex', '--sandbox', 'anthropic',
    '--strict-egress', '--probe-launch', '--cwd', workspace, '--command', '/usr/bin/python3',
    '--', payload, sandboxMarker]);
  assert.equal(launched.status, 0, `The integrated Anthropic launch did not prove filtering.\n${details(launched)}`);
  assert.ok(existsSync(sandboxMarker), 'The sandbox payload did not start.');
  assert.equal(readFileSync(sandboxMarker, 'utf8'), 'AF_UNIX_DENIED');
  assert.match(launched.stdout, /SGW_PAYLOAD_STARTED/);
  assert.match(launched.stdout, /SGW_AF_UNIX_DENIED/);
  assert.doesNotMatch(launched.stdout, /SGW_AF_UNIX_ALLOWED/);
  console.log('SGW_ANTHROPIC_INTEGRATED_SECCOMP_PASSED');
} finally {
  rmSync(root, { recursive: true, force: true });
}
