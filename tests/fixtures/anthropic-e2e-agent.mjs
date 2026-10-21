import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { connect } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const configPath = process.env.SGW_SANDBOX_MCP_CONFIG;
const config = JSON.parse(readFileSync(configPath, 'utf8')).mcpServers['s-gw'];
const fixture = JSON.parse(readFileSync('fixture.json', 'utf8'));
assert.equal(process.env.SGW_MASTER_PASSPHRASE, undefined);
assert.equal(process.env.SGW_ALLOW_NONINTERACTIVE_OPERATOR, undefined);
assert.throws(() => readFileSync(fixture.storeHome + '/store.json'), /EPERM|EACCES|ENOENT/);
if (fixture.isolatedAuth) {
  assert.throws(() => readFileSync(fixture.syntheticAuthPath), /EPERM|EACCES|ENOENT/);
  assert.equal(process.env.npm_config_unclassified, undefined);
  assert.equal(process.env.SGW_E2E_UNCLASSIFIED, undefined);
}
assert.throws(() => writeFileSync(configPath, '{}'), /EPERM|EACCES|EROFS/);
const consolePort = Number(new URL(fixture.consoleUrl).port);
const consoleReachable = await new Promise(resolve => {
  const socket = connect(consolePort, '127.0.0.1');
  socket.once('connect', () => { socket.destroy(); resolve(true); });
  socket.once('error', () => resolve(false));
  socket.setTimeout(2000, () => { socket.destroy(); resolve(false); });
});
assert.equal(consoleReachable, false, 'Confined agent reached the operator console listener');
writeFileSync('session.json', JSON.stringify({ configPath, brokerPort: Number(config.env.SGW_SANDBOX_BROKER_PORT) }));

const client = new Client({ name: 'sandbox e2e fixture', version: '1' });
const transport = new StdioClientTransport(config);
async function call(name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  assert(!result.isError, JSON.stringify(result));
  return JSON.parse(result.content[0].text);
}
async function cannotExecute(id, expected) {
  const result = await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: id } });
  assert.equal(result.isError, true);
  if (expected) assert.match(result.content[0].text, expected);
}
try {
  await client.connect(transport);
  const tools = (await client.listTools()).tools.map(tool => tool.name);
  assert(tools.includes('sgw_request_http'));
  assert(!tools.includes('sgw_request_execution'));
  const handles = await call('sgw_list_handles');
  const httpHandle = handles.find(item => item.name === 'HTTPS package E2E').handle;
  const input = { handle: httpHandle, url: fixture.url, auth: { kind: 'bearer' } };
  const first = (await call('sgw_request_http', input)).request;
  assert.equal(first.state, 'pending');
  await cannotExecute(first.id);
  if (existsSync('fresh-mode')) {
    writeFileSync('fresh.json', JSON.stringify({ id: first.id, state: first.state }));
  } else {
    const changed = (await call('sgw_request_http', { ...input, method: 'POST', body: 'unapproved mutation' })).request;
    const ssh = (await call('sgw_request_ssh_session', {
      handle: handles.find(item => item.name === 'SSH package E2E').handle,
      routeId: fixture.sshRouteId, args: ['hostname']
    })).request;
    assert.equal(ssh.action.ssh.managedRouteId, fixture.sshRouteId);
    await cannotExecute(ssh.id);
    writeFileSync('pending.json', JSON.stringify({ http: first.id, ssh: ssh.id, changed: changed.id }));
    const deadline = Date.now() + 30000;
    while (!existsSync('approved')) {
      if (Date.now() > deadline) throw new Error('E2E operator approval timed out');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    await cannotExecute(changed.id);
    await cannotExecute(first.id, /verified agent principal and session/);
    await cannotExecute(ssh.id, /verified agent principal and session/);
    writeFileSync('claims-denied.json', JSON.stringify({ http: first.id, ssh: ssh.id }));
    while (!existsSync('operator-results.json')) {
      if (Date.now() > deadline) throw new Error('E2E operator execution timed out');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    const { http: httpResult, ssh: sshResult } = JSON.parse(readFileSync('operator-results.json', 'utf8'));
    assert.equal(httpResult.exitCode, 0);
    assert.match(httpResult.stdout, /HTTPS package E2E success/);
    assert.match(httpResult.stdout, /SGW_RESPONSE_CREDENTIAL_WITHHELD/);
    assert.match(httpResult.stdout, /SGW_SECRET/);
    await cannotExecute(first.id);
    const repeat = (await call('sgw_request_http', input)).request;
    assert.equal(repeat.state, 'pending');
    writeFileSync('repeat-pending.json', JSON.stringify({ id: repeat.id, state: repeat.state }));
    while (!existsSync('repeat-approved')) {
      if (Date.now() > deadline) throw new Error('E2E repeat approval timed out');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    await cannotExecute(repeat.id, /verified agent principal and session/);
    writeFileSync('repeat-claim-denied.json', JSON.stringify({ id: repeat.id }));
    while (!existsSync('repeat-operator-result.json')) {
      if (Date.now() > deadline) throw new Error('E2E repeat operator execution timed out');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    const repeatResult = JSON.parse(readFileSync('repeat-operator-result.json', 'utf8'));
    assert.equal(repeatResult.exitCode, 0);
    assert.equal(sshResult.exitCode, 0);
    assert.match(sshResult.stdout, /SSH package E2E success/);
    assert.match(sshResult.stdout, /SGW_SECRET/);
    await cannotExecute(ssh.id);
    writeFileSync('results.json', JSON.stringify({ http: httpResult, ssh: sshResult, repeat: repeatResult }));
  }
} finally { await client.close(); }
