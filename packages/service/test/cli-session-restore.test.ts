import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { newEnvelope, seal, type VaultData } from '../../core/src/index.ts';
import { runCli } from '../src/cli.ts';
import { deviceSessionIdentity } from '../src/device-session.ts';

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address();
  assert(address && typeof address === 'object');
  return address.port;
}
async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
async function offlinePort(): Promise<number> {
  const server = createServer();
  const port = await listen(server);
  await close(server);
  return port;
}
async function fixture(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'jjvault-cli-session-'));
  await chmod(directory, 0o700);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const data: VaultData = {
    schema: 1, deviceId: randomUUID(), vaults: [], items: [], activity: [], assistantTokens: [],
    settings: { idleMinutes: 0, travelMode: false, notifyAssistant: false }, revision: 0,
  };
  const key = randomBytes(32);
  const older = seal(data, key, newEnvelope());
  const current = seal({ ...data, revision: 1 }, key, older);
  key.fill(0);
  assert.equal(deviceSessionIdentity(older), deviceSessionIdentity(current));
  assert.notEqual(older.ciphertext, current.ciphertext);
  const currentBytes = JSON.stringify(current);
  const backupBytes = JSON.stringify(older);
  const vaultFile = join(directory, 'vault.json');
  const backupFile = join(directory, 'older-backup.jjvault');
  const cacheFile = join(directory, 'device-session.json');
  const cacheBytes = JSON.stringify({ version: 1, identity: deviceSessionIdentity(current), ciphertext: Buffer.from('Synthetic OS protected session ciphertext').toString('base64') });
  await Promise.all([
    writeFile(vaultFile, currentBytes, { mode: 0o600 }),
    writeFile(backupFile, backupBytes, { mode: 0o600 }),
    writeFile(cacheFile, cacheBytes, { mode: 0o600 }),
  ]);
  return { directory, vaultFile, backupFile, cacheFile, currentBytes, backupBytes, cacheBytes };
}

test('offline restore clears a saved session even for an older backup with the same key identity', async t => {
  const f = await fixture(t);
  const output: string[] = [];
  await runCli(['restore', f.backupFile], { directory: f.directory, port: await offlinePort(), output: text => output.push(text) });
  assert.equal(await readFile(f.vaultFile, 'utf8'), f.backupBytes);
  await assert.rejects(readFile(f.cacheFile), { code: 'ENOENT' });
  const previous = (await readdir(f.directory)).filter(name => /^vault\.before-restore\.\d+\.json$/.test(name));
  assert.equal(previous.length, 1);
  assert.equal(await readFile(join(f.directory, previous[0]), 'utf8'), f.currentBytes);
  assert.deepEqual(output, ['Encrypted backup restored. Unlock in the Mac app with its master password and Secret Key.']);
});

test('invalid encrypted backup preserves the saved session and the current vault', async t => {
  const f = await fixture(t);
  await writeFile(f.backupFile, JSON.stringify({ format: 'invalid' }), { mode: 0o600 });
  await assert.rejects(runCli(['restore', f.backupFile], { directory: f.directory, port: await offlinePort(), output: () => {} }), /Unsupported vault format/);
  assert.equal(await readFile(f.cacheFile, 'utf8'), f.cacheBytes);
  assert.equal(await readFile(f.vaultFile, 'utf8'), f.currentBytes);
  assert.equal((await readdir(f.directory)).some(name => name.startsWith('vault.before-restore.')), false);
});

test('restore while the Mac service is running preserves the saved session', async t => {
  const f = await fixture(t);
  const server = createServer((_request, response) => { response.writeHead(401); response.end('{}'); });
  const port = await listen(server);
  t.after(() => close(server));
  await assert.rejects(runCli(['restore', f.backupFile], { directory: f.directory, port, output: () => {} }), /Close the Mac app/);
  assert.equal(await readFile(f.cacheFile, 'utf8'), f.cacheBytes);
  assert.equal(await readFile(f.vaultFile, 'utf8'), f.currentBytes);
  assert.equal((await readdir(f.directory)).some(name => name.startsWith('vault.before-restore.')), false);
});

test('restore fails before replacement when the saved session cannot be safely forgotten', async t => {
  const f = await fixture(t);
  await chmod(f.cacheFile, 0o644);
  await assert.rejects(runCli(['restore', f.backupFile], { directory: f.directory, port: await offlinePort(), output: () => {} }), /Unable to clear the saved device session/);
  assert.equal(await readFile(f.cacheFile, 'utf8'), f.cacheBytes);
  assert.equal(await readFile(f.vaultFile, 'utf8'), f.currentBytes);
});

test('offline restore works when there is no saved device session', async t => {
  const f = await fixture(t);
  await rm(f.cacheFile);
  await runCli(['restore', f.backupFile], { directory: f.directory, port: await offlinePort(), output: () => {} });
  assert.equal(await readFile(f.vaultFile, 'utf8'), f.backupBytes);
  await assert.rejects(readFile(f.cacheFile), { code: 'ENOENT' });
});
