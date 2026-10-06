import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { createServer as createHttpsServer } from 'node:https';
import { connect } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (!['darwin', 'linux'].includes(process.platform)) throw new Error('Package confinement E2E requires macOS or Linux.');
const repo = fileURLToPath(new URL('../', import.meta.url));
const accountHome = os.homedir();
const realAgent = process.argv.includes('--real-agent') ? process.argv[process.argv.indexOf('--real-agent') + 1] : undefined;
if (realAgent && !['codex', 'claude'].includes(realAgent)) throw new Error('--real-agent must be codex or claude.');
const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'sgw-package-e2e-')));
const oldEnv = process.env;
const home = path.join(root, 'home');
const storeHome = path.join(root, 'store');
const workspace = path.join(root, 'workspace');
const values = [];
const children = new Set();
const clients = new Set();
let consoleServer, https, ssh;
const env = {
  PATH: oldEnv.PATH, HOME: home, TMPDIR: os.tmpdir(), LANG: 'en_US.UTF-8',
  SGW_TEST_MODE: "1", SGW_TEST_HOME_ROOT: root, SGW_RECOVERY_HOME: path.join(root, "recovery"),
  SGW_HOME: storeHome, SGW_MASTER_PASSPHRASE: randomUUID(), SGW_DISABLE_KEYCHAIN: '1',
  SGW_DISABLE_ONEPASSWORD_BACKUP: '1', SGW_DISABLE_UPDATE_CHECK: '1', SGW_ALLOW_TOKEN_FILE: '1',
  SGW_ALLOW_NO_CGROUP: process.argv.includes('--require-cgroup') ? undefined : '1',
  SGW_DISABLE_PROCESS_AGENT_DETECTION: '1', SGW_SKIP_HOOK_INSTALL: '1'
};

function run(command, args, options = {}) {
  return execFileSync(command, args, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 120000, env, ...options });
}
async function waitFor(check, label, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const result = await check();
    if (result) return result;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for ${label}`);
}
async function jsonFile(name) {
  try { return JSON.parse(await readFile(path.join(workspace, name), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
async function api(route, body, method) {
  const target = new URL(consoleServer.url);
  assert.equal(target.hostname, '127.0.0.1');
  assert.match(route, /^api\/[a-zA-Z0-9_/-]+$/);
  target.pathname = '/' + route;
  const response = await fetch(target, {
    method: method || (body === undefined ? 'GET' : 'POST'),
    headers: { 'Content-Type': 'application/json', 'X-SGW-Console-Token': consoleServer.token },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10000)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Console HTTP ${response.status}`);
  return result;
}
async function closedSession() {
  const session = await jsonFile('session.json');
  await assert.rejects(readFile(session.configPath), { code: 'ENOENT' });
  await new Promise((resolve, reject) => {
    const socket = connect(session.brokerPort, '127.0.0.1');
    socket.setTimeout(2000, () => socket.destroy(new Error('Broker cleanup timed out')));
    socket.once('connect', () => { socket.destroy(); reject(new Error('Broker stayed open after exit')); });
    socket.once('error', error => { if (error.code === 'ECONNREFUSED') resolve(); else reject(error); });
  });
}

try {
  await Promise.all([home, workspace].map(dir => mkdir(dir)));
  await writeFile(path.join(root, 'npmrc'), 'registry=https://registry.npmjs.org/\n');
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const packed = JSON.parse(run(npm, ['pack', '--ignore-scripts', '--json', '--pack-destination', root], { cwd: repo }))[0];
  assert(packed.files.some(file => file.path === 'dist/http-executor.js'));
  assert(packed.files.some(file => file.path === 'dist/sandbox-child.js'));
  run(npm, ['install', '--prefix', root, '--ignore-scripts', '--no-audit', '--no-fund', '--userconfig', path.join(root, 'npmrc'), path.join(root, packed.filename)], { cwd: root });
  const installed = path.join(root, 'node_modules', '@s-gw', 's-gw');
  if (process.platform === 'linux' && process.argv.includes('--require-cgroup')) {
    const probe = path.join(repo, 'tests', 'fixtures', 'linux-cgroup-agent.mjs');
    const probeEnv = { PATH: env.PATH, HOME: home };
    const native = JSON.parse(run(process.execPath, [probe, installed, workspace, 'positive'], { env: probeEnv }));
    assert.equal(native.detachedChildKilled, true); assert.equal(native.groupRemoved, true);
    const denied = JSON.parse(run('bwrap', ['--ro-bind', '/', '/', '--bind', workspace, workspace, '--unshare-pid', '--proc', '/proc', '--',
      process.execPath, probe, installed, workspace, 'readonly'], { env: probeEnv }));
    assert.equal(denied.deniedBeforeSpawn, true);
  }
  const cli = path.join(installed, 'dist', 'cli.js');
  const installedRequire = createRequire(path.join(installed, 'package.json'));
  const { Client } = await import(pathToFileURL(installedRequire.resolve('@modelcontextprotocol/sdk/client/index.js')).href);
  const { StdioClientTransport } = await import(pathToFileURL(installedRequire.resolve('@modelcontextprotocol/sdk/client/stdio.js')).href);
  const legacyEnv = { ...env, SGW_HOME: path.join(root, 'legacy-store') };
  const legacyCli = (args, input) => JSON.parse(run(process.execPath, [cli, ...args], {
    cwd: workspace, input, env: { ...legacyEnv, SGW_ALLOW_NONINTERACTIVE_OPERATOR: '1' }
  }));
  legacyCli(['init']); legacyCli(['init']);
  const legacyValue = `synthetic ordinary MCP credential ${randomUUID()}`;
  values.push(legacyValue);
  const legacyHandle = legacyCli(['secret', 'add', '--name', 'Ordinary MCP E2E', '--type', 'api-token', '--value-stdin',
    '--inject-env', 'SGW_LEGACY_CREDENTIAL', '--allow-command', process.execPath], legacyValue);
  const ordinaryMcp = new Client({ name: 'installed ordinary client', version: '1' });
  try {
    await ordinaryMcp.connect(new StdioClientTransport({ command: process.execPath,
      args: [path.join(installed, 'dist', 'mcp-server.js')], cwd: workspace, env: legacyEnv, stderr: 'pipe' }));
    const tools = (await ordinaryMcp.listTools()).tools.map(tool => tool.name);
    assert(tools.includes('sgw_scan_text')); assert(tools.includes('sgw_request_execution'));
    const scanned = await ordinaryMcp.callTool({ name: 'sgw_scan_text', arguments: { text: 'clean input', persist: false } });
    assert(!scanned.isError); assert.equal(legacyCli(['secret', 'list']).length, 1);
    const scanValue = ['sk', '-proj-', 'synthetic_fixture_1234567890abcdef'].join('');
    values.push(scanValue);
    const preview = await ordinaryMcp.callTool({ name: 'sgw_scan_text', arguments: { text: `OPENAI_API_KEY=${scanValue}`, persist: false } });
    assert(!preview.isError); assert(!JSON.stringify(preview).includes(scanValue));
    assert.equal(JSON.parse(preview.content[0].text).findings.length, 1);
    assert.equal(legacyCli(['secret', 'list']).length, 1);
    const scanFile = path.join(workspace, 'scan-fixture.txt'); await writeFile(scanFile, `OPENAI_API_KEY=${scanValue}`);
    const persisted = await ordinaryMcp.callTool({ name: 'sgw_scan_file', arguments: { path: scanFile, persist: true } });
    assert(!persisted.isError); assert(!JSON.stringify(persisted).includes(scanValue));
    assert.equal(legacyCli(['secret', 'list']).length, 2);
    const requestResult = await ordinaryMcp.callTool({ name: 'sgw_request_execution', arguments: {
      handle: legacyHandle.handle, command: process.execPath, injectEnv: 'SGW_LEGACY_CREDENTIAL',
      args: ['-e', 'console.log("ordinary MCP success", process.env.SGW_LEGACY_CREDENTIAL)'], timeoutMs: 10000
    } });
    assert(!requestResult.isError, JSON.stringify(requestResult));
    const request = JSON.parse(requestResult.content[0].text).request;
    assert.equal(request.state, 'pending');
    const execute = () => ordinaryMcp.callTool({ name: 'sgw_execute_request', arguments: { requestId: request.id } });
    assert.equal((await execute()).isError, true);
    legacyCli(['approve', request.id]);
    const executed = await execute(); assert(!executed.isError, JSON.stringify(executed));
    const summary = JSON.parse(executed.content[0].text);
    assert.equal(summary.exitCode, 0); assert.match(summary.stdout, /ordinary MCP success/);
    assert(!summary.stdout.includes(legacyValue)); assert.match(summary.stdout, /SGW_SECRET/);
    assert.equal((await execute()).isError, true);
    assert(!String(await readFile(path.join(legacyEnv.SGW_HOME, 'store.json'))).includes(legacyValue));
  } finally { await ordinaryMcp.close(); }
  for (const handle of legacyCli(['secret', 'list'])) legacyCli(['secret', 'delete', handle.handle]);
  assert.equal(legacyCli(['secret', 'list']).length, 0);
  const runCli = (args, value) => JSON.parse(run(process.execPath, [cli, ...args], {
    cwd: workspace, input: value, env: { ...env, SGW_ALLOW_NONINTERACTIVE_OPERATOR: '1' }
  }));
  runCli(['init']);
  const keyFile = path.join(storeHome, 'server.key'), certFile = path.join(storeHome, 'server.crt');
  run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile,
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost']);
  const httpCredential = `synthetic package HTTPS credential ${randomUUID()}`;
  const sshPassword = `synthetic package SSH password ${randomUUID()}`;
  const issued = randomUUID(); values.push(httpCredential, sshPassword, issued);
  let httpHits = 0, sshAuthentications = 0;
  const commands = [];
  https = createHttpsServer({ key: await readFile(keyFile), cert: await readFile(certFile) }, (request, response) => {
    if (request.headers.authorization !== `Bearer ${httpCredential}` || request.method !== 'GET') {
      response.writeHead(401); response.end('Unexpected E2E authentication or method'); return;
    }
    httpHits++;
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ result: 'HTTPS package E2E success', echo: request.headers.authorization, access_token: issued }));
  });
  await new Promise(resolve => https.listen(0, '127.0.0.1', resolve));
  const url = `https://127.0.0.1:${https.address().port}/operation`;
  const { Server, utils } = createRequire(import.meta.url)('ssh2');
  const hostKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs1' });
  ssh = new Server({ hostKeys: [hostKey] }, client => {
    clients.add(client); client.on('error', () => {}); client.once('close', () => clients.delete(client));
    client.on('authentication', context => {
      if (context.method === 'password' && context.username === 'fixture' && context.password === sshPassword) {
        sshAuthentications++; context.accept();
      } else context.reject(['password']);
    });
    client.on('ready', () => client.on('session', accept => {
      accept().on('exec', (acceptExec, _reject, info) => {
        commands.push(info.command);
        const stream = acceptExec(); stream.write(`SSH package E2E success\n${sshPassword}\n`); stream.exit(0); stream.end();
      });
    }));
  });
  await new Promise(resolve => ssh.listen(0, '127.0.0.1', resolve));
  const sshPort = ssh.address().port;
  const knownHosts = path.join(storeHome, 'known_hosts');
  await writeFile(knownHosts, `[127.0.0.1]:${sshPort} ssh-rsa ${utils.parseKey(hostKey).getPublicSSH().toString('base64')}\n`);
  const helper = path.join(storeHome, 'ssh.cjs');
  await writeFile(helper, `#!${process.execPath}\nconst {spawnSync}=require('node:child_process'); const result=spawnSync('/usr/bin/ssh',['-F','/dev/null','-o',${JSON.stringify(`UserKnownHostsFile=${knownHosts}`)},...process.argv.slice(2)],{stdio:'inherit'}); process.exit(result.status ?? 1);\n`, { mode: 0o700 });
  env.SGW_SSH_CLI = helper; env.NODE_EXTRA_CA_CERTS = certFile;
  env.SGW_E2E_STORE = storeHome; env.SGW_E2E_URL = url; env.SGW_E2E_SSH_PORT = String(sshPort);
  const httpHandle = runCli(['secret', 'add', '--name', 'HTTPS package E2E', '--type', 'api-token', '--value-stdin', '--inject-env', 'SGW_HTTP_CREDENTIAL',
    '--allow-command', 's-gw:https-request', '--allow-destination', `127.0.0.1:${https.address().port}`], httpCredential);
  runCli(['secret', 'add', '--name', 'SSH package E2E', '--type', 'password', '--value-stdin', '--inject-env', 'SGW_SSH_PASSWORD',
    '--allow-command', 's-gw:ssh-session'], sshPassword);
  process.env = env;
  const { startConsoleServer } = await import(pathToFileURL(path.join(installed, 'dist', 'console-server.js')).href);
  consoleServer = await startConsoleServer({ port: 0 });
  assert.equal((await fetch(consoleServer.url)).status, 200);
  const deniedConsole = await fetch(new URL('api/state', consoleServer.url)); assert.equal(deniedConsole.status, 403);
  const probe = path.join(root, 'agent.mjs'); await copyFile(path.join(repo, 'tests', 'fixtures', 'anthropic-e2e-agent.mjs'), probe);
  function launch(fresh = false) {
    const child = spawn(process.execPath, [cli, 'run', 'codex', '--sandbox', 'anthropic', '--strict-egress', '--cwd', workspace,
      '--command', process.execPath, '--', probe], { cwd: workspace, env: { ...env, ...(fresh ? { SGW_E2E_FRESH: '1' } : {}) }, stdio: ['ignore', 'pipe', 'pipe'] });
    children.add(child);
    let output = '';
    child.stdout.on('data', data => output += data); child.stderr.on('data', data => output += data);
    const completion = new Promise((resolve, reject) => {
      child.once('error', reject); child.once('close', code => { children.delete(child); resolve({ code, output }); });
    });
    return { child, completion, output: () => output };
  }
  const first = launch();
  const pending = await Promise.race([
    waitFor(() => jsonFile('pending.json'), 'MCP requests').catch(error => {
      let output = first.output();
      for (const value of values) output = output.replaceAll(value, '[synthetic credential]');
      throw new Error(error.message + '\nSandbox output:\n' + output);
    }),
    first.completion.then(result => { throw new Error('Sandbox exited before requests: ' + result.code + '\n' + result.output); })
  ]);
  assert.equal(httpHits, 0); assert.equal(sshAuthentications, 0);
  const state = await api('api/state'); assert.equal(state.pendingRequests.length, 3);
  await api(`api/requests/${pending.changed}/deny`, {});
  const approved = await api(`api/requests/${pending.http}/approve`, { mode: 'timed-session', durationMs: 60000, agentScope: 'same-agent' });
  await api(`api/requests/${pending.ssh}/approve`, { mode: 'per-transaction', agentScope: 'same-agent' });
  await writeFile(path.join(workspace, 'approved'), 'synthetic operator approved');
  const result = await Promise.race([first.completion, new Promise((_resolve, reject) => { const timer = setTimeout(() => reject(new Error('E2E launcher timed out')), 30000); timer.unref(); })]);
  assert.equal(result.code, 0, result.output);
  assert.equal(httpHits, 2); assert.equal(sshAuthentications, 1); assert.deepEqual(commands, ['hostname']);
  const outputs = await readFile(path.join(workspace, 'results.json'), 'utf8');
  for (const value of values) { assert(!outputs.includes(value)); assert(!result.output.includes(value)); }
  await closedSession(); await waitFor(() => clients.size === 0, 'SSH session cleanup');
  await api(`api/approval/grants/${approved.approvalGrantId}`, undefined, 'DELETE');
  const fresh = launch(true); const freshResult = await fresh.completion;
  assert.equal(freshResult.code, 0, freshResult.output);
  const next = await jsonFile('fresh.json'); assert.equal(next.state, 'pending');
  await api(`api/requests/${next.id}/deny`, {});
  await closedSession(); assert.equal(httpHits, 2);
  if (realAgent) {
    const prompt = `This is a bounded s-gw integration test. Use only the s-gw MCP tools. List handles and find HTTPS package E2E. Request one HTTPS GET to ${url}, auth kind bearer, with no extra headers or body. Execute that request after local approval. Approval is handled by the test operator outside this process; if execution initially reports pending, retry the same request ID up to five times. Do not fetch or read any credential. Return REAL_AGENT_E2E_PASS only when the executed result has exitCode 0 and contains HTTPS package E2E success. Do not use any other services or tools.`;
    const command = realAgent === 'codex' ? (oldEnv.SGW_E2E_CODEX || 'codex') : (oldEnv.SGW_E2E_CLAUDE || 'claude');
    const args = realAgent === 'codex'
      ? ['exec', '--ephemeral', '--ignore-user-config', '--skip-git-repo-check', '--sandbox', 'danger-full-access', '--config', `sqlite_home=${JSON.stringify(path.join(workspace, 'codex-state'))}`, '--config', `log_dir=${JSON.stringify(path.join(workspace, 'codex-log'))}`, '--json', prompt]
      : ['--restricted', '--strict-mcp-config', '--tools', '', '--allowedTools', 'mcp__s-gw__*', '--permission-mode', 'dontAsk', '--no-session-persistence', '--max-budget-usd', '2', '--print', '--output-format', 'json', prompt];
    const runtimeWrites = realAgent === 'codex' ? ['installation_id', 'tmp', 'models_cache.json'].flatMap(file => ['--allow-write', path.join(accountHome, '.codex', file)]) : [];
    const keychainAccess = process.argv.includes('--allow-agent-keychain') ? ['--allow-agent-keychain'] : [];
    const agentEnv = { ...env, HOME: accountHome, USER: os.userInfo().username };
    delete agentEnv.NODE_EXTRA_CA_CERTS;
    if (oldEnv.SGW_E2E_AGENT_CA_FILE) {
      const certificateFile = path.join(root, 'agent-trusted-ca.pem');
      const publicRoots = [await readFile(oldEnv.SGW_E2E_AGENT_CA_FILE, 'utf8'), await readFile(certFile, 'utf8')];
      await writeFile(certificateFile, publicRoots.join('\n'), { mode: 0o600 });
      agentEnv.NODE_EXTRA_CA_CERTS = certificateFile;
      agentEnv.SSL_CERT_FILE = certificateFile;
    }
    const child = spawn(process.execPath, [cli, 'run', realAgent === 'codex' ? 'codex' : 'claude-code', '--sandbox', 'anthropic',
      '--allow-host', 'chatgpt.com', '--allow-host', '*.chatgpt.com', ...runtimeWrites, ...keychainAccess, '--cwd', workspace, '--command', command, '--', ...args], {
      cwd: workspace, env: agentEnv, stdio: ['ignore', 'pipe', 'pipe']
    });
    children.add(child); let output = '', finished = false, code;
    child.stdout.on('data', data => output += data); child.stderr.on('data', data => output += data);
    child.once('error', error => { finished = true; output += error.message; });
    child.once('close', value => { code = value; finished = true; children.delete(child); });
    let approvedId;
    await waitFor(async () => {
      const state = await api('api/state');
      for (const request of state.pendingRequests) {
        assert.equal(request.handle, httpHandle.handle); assert.equal(request.action.kind, 'http_request');
        assert.equal(request.action.http.url, url); assert.equal(request.action.http.method, 'GET');
        assert(!approvedId, 'Real agent requested more than one approved operation');
        await api(`api/requests/${request.id}/approve`, { mode: 'per-transaction', agentScope: 'same-agent' });
        approvedId = request.id;
      }
      return finished;
    }, `${realAgent} live MCP operation`, 120000);
    assert.equal(code, 0, output); assert(approvedId, output);
    assert.match(output, /REAL_AGENT_E2E_PASS/);
    assert.equal((await api('api/state')).requests.find(request => request.id === approvedId).state, 'executed');
    assert.equal(httpHits, 3);
    for (const value of values) assert(!output.includes(value));
  }
  const finalState = await api('api/state');
  assert.equal(finalState.requests.filter(request => request.state === 'executed').length, realAgent ? 4 : 3);
  for (const value of values) assert(!JSON.stringify(finalState).includes(value));
  console.log(JSON.stringify({ packageInstalled: true, ordinaryMcp: true, legacyEnvExecution: true, compiledLauncher: true, realHttps: true, realOpenSsh: true,
    consoleApproval: true, pendingDenied: true, changedActionDenied: true, replayDenied: true,
    exactGrantReused: true, freshRunAfterRevocationDenied: true, credentialsRedacted: true, cleanup: true,
    cgroupRequired: process.platform === 'linux' && process.argv.includes('--require-cgroup'), realAgent: realAgent || 'not requested' }));
} catch (error) {
  let message = error instanceof Error ? error.stack : String(error);
  for (const value of values) message = message.replaceAll(value, '<synthetic credential withheld>');
  process.exitCode = 1; console.error(message);
} finally {
  await Promise.all([...children].map(child => new Promise(resolve => {
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    child.once('close', () => { clearTimeout(timer); resolve(); });
    child.kill('SIGTERM');
  })));
  await consoleServer?.close();
  https?.closeAllConnections(); if (https) await new Promise(resolve => https.close(resolve));
  for (const client of clients) client.end(); if (ssh) await new Promise(resolve => ssh.close(resolve));
  process.env = oldEnv;
  const hash = createHash('sha256').update(storeHome).digest('hex').slice(0, 12);
  await rm(path.join(process.platform === 'darwin' ? '/private/tmp' : '/tmp', `sgw-ssh-${process.getuid?.() ?? 'user'}-${hash}`), { recursive: true, force: true });
  await rm(root, { recursive: true, force: true });
}
