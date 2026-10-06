import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { connect } from 'node:net';
import { request } from 'node:http';
import { fileURLToPath } from 'node:url';
import { Client } from '../../node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js';
import { StdioClientTransport } from '../../node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js';

const root = process.env.SGW_TEST_ROOT;
if (process.env.SGW_TEST_NESTED === '1') {
  readFileSync(`${root}/store/store.json`);
  throw new Error('Nested store read unexpectedly succeeded');
}
const checks = [];
assert.equal(process.env.SGW_MASTER_PASSPHRASE, undefined);
assert.equal(process.env.SSH_AUTH_SOCK, undefined);
assert.equal(process.env.BASH_ENV, undefined);
assert.equal(process.env.NODE_OPTIONS, undefined);
checks.push('sensitive launch environment removed');
writeFileSync(`${root}/workspace/output.txt`, 'workspace write');
assert.throws(() => readFileSync(`${root}/store/store.json`), /EPERM|EACCES|ENOENT/);
assert.throws(() => readFileSync(`${root}/workspace/store-link`), /EPERM|EACCES|ENOENT/);
assert.throws(() => writeFileSync(`${root}/outside/output.txt`, 'outside'), /EPERM|EACCES|EROFS/);
assert.throws(() => writeFileSync(fileURLToPath(new URL('../../src/.sandbox-write-probe', import.meta.url)), 'alter trusted executor'), /EPERM|EACCES|EROFS/);
const nested = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--read'], { env: { ...process.env, SGW_TEST_NESTED: '1' }, encoding: 'utf8' });
assert.notEqual(nested.status, 0);
checks.push('workspace writes succeed; store, symlink, outside writes and child reads denied');

await new Promise((resolve, reject) => {
  const socket = connect(Number(process.env.SGW_TEST_PORT), '127.0.0.1');
  socket.setTimeout(3000, () => { socket.destroy(); reject(new Error('direct connection timed out instead of policy denial')); });
  socket.once('connect', () => { socket.destroy(); reject(new Error('direct localhost bypass succeeded')); });
  socket.once('error', error => { assert.match(error.code, /EPERM|EACCES|ECONNREFUSED|ENETUNREACH/); resolve(); });
});
const proxy = new URL(process.env.HTTP_PROXY);
await new Promise((resolve, reject) => {
  const req = request({ hostname: proxy.hostname, port: proxy.port, method: 'CONNECT', path: `127.0.0.1:${process.env.SGW_TEST_PORT}` });
  req.once('error', reject);
  req.once('connect', (response, socket) => { socket.destroy(); assert.equal(response.statusCode, 403); resolve(); });
  req.end();
});
checks.push('direct and proxy routes to unrelated localhost service denied');
await new Promise((resolve, reject) => {
  const req = request({ hostname: proxy.hostname, port: proxy.port, method: 'POST', path: 'http://denied.example.test/fixture', headers: { 'content-length': 65536 } }, response => {
    response.resume(); response.once('end', () => { assert.equal(response.statusCode, 403); resolve(); });
  });
  req.once('error', reject); req.end('x'.repeat(65536));
});

const mcpConfig = JSON.parse(readFileSync(process.env.SGW_SANDBOX_MCP_CONFIG, 'utf8')).mcpServers['s-gw'];
assert.throws(() => writeFileSync(process.env.SGW_SANDBOX_MCP_CONFIG, '{}'), /EPERM|EACCES|EROFS/);
const transport = new StdioClientTransport({ ...mcpConfig, stderr: 'pipe' });
transport.stderr.on('data', chunk => process.stderr.write(chunk));
const client = new Client({ name: 'sandbox fixture', version: '1' });
try {
  await client.connect(transport);
  const tools = (await client.listTools()).tools.map(tool => tool.name);
  assert(tools.includes('sgw_request_ssh_session'));
  assert(tools.includes('sgw_request_http'));
  assert(!tools.includes('sgw_request_execution'));
  assert(!tools.includes('sgw_scan_file'));
  const listed = await client.callTool({ name: 'sgw_list_handles', arguments: {} });
  const records = JSON.parse(listed.content[0].text);
  const handle = records.find(record => record.name === 'sandbox SSH fixture').handle;
  const created = await client.callTool({ name: 'sgw_request_ssh_session', arguments: { handle, target: 'fixture@example.test', args: ['hostname'] } });
  const { request: pending } = JSON.parse(created.content[0].text);
  assert.equal(pending.state, 'pending');
  const denied = await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: pending.id } });
  assert.equal(denied.isError, true);
  const httpHandle = records.find(record => record.name === 'sandbox HTTPS fixture').handle;
  const httpCreated = await client.callTool({ name: 'sgw_request_http', arguments: { handle: httpHandle, url: process.env.SGW_TEST_HTTP_URL, auth: { kind: 'bearer' } } });
  assert(!httpCreated.isError, JSON.stringify(httpCreated));
  const httpPending = JSON.parse(httpCreated.content[0].text).request;
  assert.equal(httpPending.state, 'pending');
  assert.equal((await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: httpPending.id } })).isError, true);
  writeFileSync(`${root}/workspace/request.json`, JSON.stringify({ requestId: pending.id, httpRequestId: httpPending.id }));
  const deadline = Date.now() + 15000;
  while (!existsSync(`${root}/workspace/approval-ready`)) {
    if (Date.now() > deadline) throw new Error('Fixture approval timed out');
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  const executed = await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: pending.id } });
  assert(!executed.isError, JSON.stringify(executed));
  const result = JSON.parse(executed.content[0].text);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /owned SSH fixture complete/);
  checks.push('external broker executes approved SSH action; pending action was denied');
  const httpExecuted = await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: httpPending.id } });
  assert(!httpExecuted.isError, JSON.stringify(httpExecuted));
  const httpOutput = JSON.parse(httpExecuted.content[0].text);
  assert.equal(httpOutput.exitCode, 0);
  assert.match(httpOutput.stdout, /owned HTTPS fixture complete/);
  assert.match(httpOutput.stdout, /SGW_RESPONSE_CREDENTIAL_WITHHELD/);
  assert.match(httpOutput.stdout, /SGW_SECRET/);
  assert.equal((await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: httpPending.id } })).isError, true);
  checks.push('external HTTPS authentication, credential-field redaction and replay denial work after denied POST');
  const changed = await client.callTool({ name: 'sgw_request_ssh_session', arguments: { handle, target: 'fixture@example.test', args: ['uptime'] } });
  assert.equal(JSON.parse(changed.content[0].text).request.state, 'pending');
  const replay = await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: pending.id } });
  assert.equal(replay.isError, true);
  const generic = await client.callTool({ name: 'sgw_execute_request', arguments: { requestId: process.env.SGW_TEST_ENV_REQUEST_ID } });
  assert.equal(generic.isError, true);
  assert.match(generic.content[0].text, /outside this mode|owned SSH and HTTPS/);
  assert(!(await client.callTool({ name: 'sgw_list_handles', arguments: {} })).isError);
  checks.push('changed action needs approval, one-time replay fails, generic TLS-substitution path is inaccessible');
} finally { await client.close(); }
writeFileSync(`${root}/workspace/results.json`, JSON.stringify(checks));
