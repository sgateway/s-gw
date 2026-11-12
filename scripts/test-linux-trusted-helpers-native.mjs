import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync, statfsSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'linux' || process.getuid?.() !== 0 || process.argv[2] !== '--root') {
  throw new Error('Trusted Linux helper acceptance requires root in the delegated CI unit.');
}

const uid = Number(process.argv[3]);
const gid = Number(process.argv[4]);
const user = process.argv[5];
const node = process.argv[6];
if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid <= 0 ||
    !/^[a-z_][a-z0-9_-]*$/.test(user || '') || !path.isAbsolute(node || '')) {
  throw new Error('Trusted Linux helper acceptance needs a non-root CI user and an absolute Node path.');
}

const repo = fileURLToPath(new URL('../', import.meta.url));
const free = statfsSync('/opt', { bigint: true });
if (free.bavail * free.bsize < 5n * 1024n ** 3n) {
  throw new Error('Trusted helper acceptance needs at least 5 GiB free on /opt before staging about 251 MiB.');
}
const staged = await mkdtemp('/opt/sgw-trusted-helper-e2e-');
let agentRoot;
const envKeys = ['PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'SGW_TEST_MODE', 'SGW_TEST_HOME_ROOT',
  'SGW_HOME', 'SGW_RECOVERY_HOME', 'SGW_MASTER_PASSPHRASE', 'SGW_DISABLE_KEYCHAIN',
  'SGW_DISABLE_ONEPASSWORD_BACKUP', 'SGW_DISABLE_UPDATE_CHECK',
  'SGW_DISABLE_PROCESS_AGENT_DETECTION', 'SGW_SKIP_HOOK_INSTALL'];

function runAsAgent(args, env, cwd) {
  const assignments = envKeys.map(key => {
    assert.equal(typeof env[key], 'string', `Missing fixture environment: ${key}`);
    return `${key}=${env[key]}`;
  });
  const result = spawnSync('/usr/sbin/runuser', ['-u', user, '--', '/usr/bin/env', '-i',
    ...assignments, node, ...args], {
    cwd, env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8', timeout: 120_000, maxBuffer: 1024 * 1024
  });
  assert.equal(result.error, undefined, result.error?.message);
  return result;
}

function assertSuccess(result) {
  assert.equal(result.status, 0, `Agent command exited ${result.status}: ${(result.stderr || result.stdout).slice(0, 8000)}`);
}

try {
  agentRoot = await mkdtemp(path.join(os.tmpdir(), 'sgw-trusted-helper-agent-'));
  for (const name of ['dist', 'assets', 'node_modules']) {
    await cp(path.join(repo, name), path.join(staged, name), { recursive: true, dereference: true });
  }
  await cp(path.join(repo, 'package.json'), path.join(staged, 'package.json'));
  const ownershipFix = spawnSync('/usr/bin/chown', ['-R', '0:0', staged], { encoding: 'utf8' });
  assert.equal(ownershipFix.error, undefined, ownershipFix.error?.message);
  assert.equal(ownershipFix.status, 0, ownershipFix.stderr);
  const permissionFix = spawnSync('/usr/bin/chmod', ['-R', 'go-w', staged], { encoding: 'utf8' });
  assert.equal(permissionFix.status, 0, permissionFix.stderr);
  await chmod(staged, 0o755);
  assert(['x64', 'arm64'].includes(process.arch));
  const seccomp = path.join(staged, 'node_modules', '@anthropic-ai', 'sandbox-runtime', 'vendor', 'seccomp',
    process.arch, 'apply-seccomp');
  assert.equal(statSync(seccomp).uid, 0);
  assert.equal(statSync(seccomp).mode & 0o022, 0);

  const selfCgroup = readFileSync('/proc/self/cgroup', 'utf8').split('\n').find(line => line.startsWith('0::'));
  assert(selfCgroup, 'A delegated cgroup v2 is required.');
  const cgroup = path.join('/sys/fs/cgroup', selfCgroup.slice(3).replace(/^\//, ''));
  const delegated = spawnSync('/usr/bin/chown', ['-R', `${uid}:${gid}`, cgroup], { encoding: 'utf8' });
  assert.equal(delegated.status, 0, delegated.stderr);

  const workspace = path.join(agentRoot, 'workspace');
  const fakeBin = path.join(workspace, 'fake-bin');
  const home = path.join(agentRoot, 'home');
  await Promise.all([mkdir(fakeBin, { recursive: true }), mkdir(home)]);
  const marker = path.join(workspace, 'fake-helper-ran');
  for (const name of ['bwrap', 'which']) {
    await writeFile(path.join(fakeBin, name), `#!/bin/sh\nprintf '%s\n' '${name}' >> '${marker}'\nexit 81\n`, { mode: 0o755 });
  }
  const pathResult = path.join(workspace, 'agent-path');
  const agent = path.join(workspace, 'agent.mjs');
  const cli = path.join(staged, 'dist', 'cli.js');
  const baseEnv = {
    PATH: process.env.PATH || '/usr/bin:/bin', HOME: home, USER: user, LOGNAME: user, LANG: 'C.UTF-8',
    SGW_TEST_MODE: '1', SGW_TEST_HOME_ROOT: agentRoot,
    SGW_HOME: path.join(agentRoot, 'store'), SGW_RECOVERY_HOME: path.join(agentRoot, 'recovery'),
    SGW_MASTER_PASSPHRASE: randomUUID(), SGW_DISABLE_KEYCHAIN: '1',
    SGW_DISABLE_ONEPASSWORD_BACKUP: '1', SGW_DISABLE_UPDATE_CHECK: '1',
    SGW_DISABLE_PROCESS_AGENT_DETECTION: '1', SGW_SKIP_HOOK_INSTALL: '1'
  };
  const requestedPath = `${fakeBin}:${baseEnv.PATH}`;
  await writeFile(agent, `import assert from 'node:assert/strict'; import { writeFileSync } from 'node:fs';\nassert.equal(process.env.PATH, ${JSON.stringify(requestedPath)});\nif (!process.argv.includes('--preflight')) writeFileSync(${JSON.stringify(pathResult)}, process.env.PATH);\n`);
  const ownAgentRoot = spawnSync('/usr/bin/chown', ['-R', `${uid}:${gid}`, agentRoot], { encoding: 'utf8' });
  assert.equal(ownAgentRoot.status, 0, ownAgentRoot.stderr);
  await chmod(agentRoot, 0o700);
  assertSuccess(runAsAgent([cli, 'init'], baseEnv, workspace));
  assertSuccess(runAsAgent([agent, '--preflight'], { ...baseEnv, PATH: requestedPath }, workspace));
  const launch = runAsAgent([cli, 'run', 'codex', '--sandbox', 'anthropic', '--trusted-linux-helpers', '--probe-launch',
    '--strict-egress', '--cwd', workspace, '--command', node, '--', agent],
  { ...baseEnv, PATH: requestedPath }, workspace);
  await assert.rejects(readFile(marker), { code: 'ENOENT' });
  assertSuccess(launch);
  assert.equal(await readFile(pathResult, 'utf8'), requestedPath);
  console.log('Trusted Linux helper native acceptance passed: real wrapper, fake helpers untouched, agent PATH restored.');
} finally {
  await Promise.all([
    agentRoot ? rm(agentRoot, { recursive: true, force: true }) : Promise.resolve(),
    rm(staged, { recursive: true, force: true })
  ]);
}
