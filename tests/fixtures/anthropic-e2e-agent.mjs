import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const configPath = process.env.SGW_SANDBOX_MCP_CONFIG;
const config = JSON.parse(readFileSync(configPath, 'utf8')).mcpServers['s-gw'];
assert.equal(process.env.SGW_MASTER_PASSPHRASE, undefined);
assert.equal(process.env.SGW_ALLOW_NONINTERACTIVE_OPERATOR, undefined);
assert.throws(() => readFileSync(process.env.SGW_E2E_STORE + '/store.json'), /EPERM|EACCES|ENOENT/);
assert.throws(() => writeFileSync(configPath, '{}'), /EPERM|EACCES|EROFS/);
writeFileSync('session.json', JSON.stringify({ configPath, brokerPort: Number(config.env.SGW_SANDBOX_BROKER_PORT) }));

const client = new Client({ name: 'sandbox e2e fixture', version: '1' });
const transport = new StdioClientTransport(config);
async function call(name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  assert(!result.isError, JSON.stringify(result));
  return JSON.parse(result.content[0].text);
}
async function cannotExecute(id) {
  const result = await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: id } });
  assert.equal(result.isError, true);
}
try {
  await client.connect(transport);
  const tools = (await client.listTools()).tools.map(tool => tool.name);
  assert(tools.includes('sgw_request_http'));
  assert(!tools.includes('sgw_request_execution'));
  const handles = await call('sgw_list_handles');
  const httpHandle = handles.find(item => item.name === 'HTTPS package E2E').handle;
  const input = { handle: httpHandle, url: process.env.SGW_E2E_URL, auth: { kind: 'bearer' } };
  const first = (await call('sgw_request_http', input)).request;
  assert.equal(first.state, 'pending');
  await cannotExecute(first.id);
  if (process.env.SGW_E2E_FRESH === '1') {
    writeFileSync('fresh.json', JSON.stringify({ id: first.id, state: first.state }));
  } else {
    const changed = (await call('sgw_request_http', { ...input, method: 'POST', body: 'unapproved mutation' })).request;
    const ssh = (await call('sgw_request_ssh_session', {
      handle: handles.find(item => item.name === 'SSH package E2E').handle,
      target: 'fixture@127.0.0.1', port: Number(process.env.SGW_E2E_SSH_PORT), args: ['hostname']
    })).request;
    await cannotExecute(ssh.id);
    writeFileSync('pending.json', JSON.stringify({ http: first.id, ssh: ssh.id, changed: changed.id }));
    const deadline = Date.now() + 30000;
    while (!existsSync('approved')) {
      if (Date.now() > deadline) throw new Error('E2E operator approval timed out');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    await cannotExecute(changed.id);
    const httpResult = await call('sgw_execute_request', { requestId: first.id });
    assert.equal(httpResult.exitCode, 0);
    assert.match(httpResult.stdout, /HTTPS package E2E success/);
    assert.match(httpResult.stdout, /SGW_RESPONSE_CREDENTIAL_WITHHELD/);
    assert.match(httpResult.stdout, /SGW_SECRET/);
    await cannotExecute(first.id);
    const repeat = (await call('sgw_request_http', input)).request;
    assert.equal(repeat.state, 'approved');
    assert.equal((await call('sgw_execute_request', { requestId: repeat.id })).exitCode, 0);
    const sshResult = await call('sgw_execute_request', { requestId: ssh.id });
    assert.equal(sshResult.exitCode, 0);
    assert.match(sshResult.stdout, /SSH package E2E success/);
    assert.match(sshResult.stdout, /SGW_SECRET/);
    await cannotExecute(ssh.id);
    writeFileSync('results.json', JSON.stringify({ http: httpResult, ssh: sshResult, repeat: repeat.id }));
  }
} finally { await client.close(); }
