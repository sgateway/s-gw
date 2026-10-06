import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [installed, workspace, mode] = process.argv.slice(2);
const { spawnIsolated, killProcessTree } = await import(pathToFileURL(path.join(installed, 'dist/process-tree.js')).href);
const marker = path.join(workspace, mode + '-cgroup-pid');
const childEnv = { PATH: process.env.PATH, HOME: process.env.HOME };
if (mode === 'readonly') {
  assert.throws(() => spawnIsolated(process.execPath, ['-e', `require('node:fs').writeFileSync(${JSON.stringify(marker)},'launched')`], { env: childEnv, stdio: 'ignore' }), /writable cgroup v2/);
  await new Promise(resolve => setTimeout(resolve, 250));
  assert(!existsSync(marker), 'A child launched before delegation was rejected');
  console.log(JSON.stringify({ deniedBeforeSpawn: true }));
} else {
  const grandchildCode = `require('node:fs').writeFileSync(${JSON.stringify(marker)},String(process.pid)); setInterval(()=>{},1000);`;
  const childCode = `const child=require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(grandchildCode)}],{detached:true,stdio:'ignore'}); child.unref(); setInterval(()=>{},1000);`;
  const child = spawnIsolated(process.execPath, ['-e', childCode], { env: childEnv, stdio: 'ignore' });
  const closed = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  async function waitFor(check) {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      if (check()) return;
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    throw new Error('Native cgroup check timed out');
  }
  try {
    await waitFor(() => existsSync(marker));
    const pid = Number(readFileSync(marker, 'utf8'));
    const membership = processId => readFileSync(`/proc/${processId}/cgroup`, 'utf8').trim().split('0::')[1];
    const group = membership(child.pid);
    assert(path.basename(group).startsWith('sgw-'));
    assert.equal(membership(pid), group, 'Detached descendants must inherit the owned cgroup');
    killProcessTree(child, 'SIGKILL');
    await closed;
    await waitFor(() => {
      try { return readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1].startsWith('Z '); }
      catch (error) { if (error.code === 'ENOENT') return true; throw error; }
    });
    await waitFor(() => !existsSync(path.join('/sys/fs/cgroup', group)));
    console.log(JSON.stringify({ detachedChildKilled: true, groupRemoved: true }));
  } finally { killProcessTree(child, 'SIGKILL'); await closed; }
}
