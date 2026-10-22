import { _electron as electron, type ElectronApplication, type Page } from '@playwright/test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runCli } from '../packages/service/src/cli.ts';

// Entirely disposable data and a synthetic protection key. The Electron entry
// point installs the adapter before app startup, so every cold launch exercises
// startup resume without touching the real Keychain or the system clipboard.
const master = 'Synthetic persistent session fixture master password 2026';
const fixturePassword = 'Synthetic retained login 728913!';
const data = await mkdtemp(path.join(tmpdir(), 'jjvault-session-ui-'));
const bootstrap = path.join(data, 'fixture-bootstrap.cjs');
const sessionFile = path.join(data, 'device-session.json');
const secretFile = path.join(data, 'device-secret.json');
const errors: string[] = [];
let running: ElectronApplication | undefined;
let page!: Page;
let secretKey = '';
const entry = path.resolve('dist/desktop/main.cjs');
await writeFile(bootstrap, `
const electron = require('electron');
const crypto = require('node:crypto');
const key = crypto.createHash('sha256').update('Disposable JJ Vault session UI adapter, never a user secret').digest();
electron.safeStorage.isEncryptionAvailable = () => true;
electron.safeStorage.encryptString = value => {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  return Buffer.concat([nonce, cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()]);
};
electron.safeStorage.decryptString = value => {
  const cipher = crypto.createDecipheriv('aes-256-gcm', key, value.subarray(0, 12));
  cipher.setAuthTag(value.subarray(-16));
  return Buffer.concat([cipher.update(value.subarray(12, -16)), cipher.final()]).toString('utf8');
};
electron.powerMonitor.getSystemIdleTime = () => 0;
let clipboard = '';
electron.clipboard.readText = async () => clipboard;
electron.clipboard.writeText = async value => { clipboard = value; };
electron.clipboard.clear = () => { clipboard = ''; };
const childProcess = require('node:child_process');
const originalSpawn = childProcess.spawn;
childProcess.spawn = (file, args, options) => {
  if (!String(file).endsWith('JJBiometric')) return originalSpawn(file, args, options);
  const child = new (require('node:events').EventEmitter)();
  const PassThrough = require('node:stream').PassThrough;
  child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.kill = () => true;
  child.stdin.on('finish', () => process.nextTick(() => child.emit('close', 0)));
  return child;
};
require(${JSON.stringify(entry)});
`, { mode: 0o600 });

async function bridge(action: string, payload: unknown = {}) {
  return page.evaluate(({ action, payload }) => (window as any).vault.invoke(action, payload), { action, payload });
}
async function launch(expected: 'create' | 'locked' | 'open', remember = true) {
  assert.equal(running, undefined);
  running = await electron.launch({ args: [bootstrap], env: { ...process.env, JJ_VAULT_DATA_DIR: data, JJ_VAULT_PORT: '0', JJ_VAULT_REMEMBER_SECRET: remember ? '1' : '0' }, timeout: 30_000 });
  page = await running.firstWindow({ timeout: 15_000 });
  page.setDefaultTimeout(15_000);
  page.on('pageerror', error => errors.push(error.message));
  if (expected === 'create') await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).waitFor();
  else if (expected === 'locked') await page.getByRole('heading', { name: 'Unlock your vault', exact: true }).waitFor();
  else {
    await page.getByRole('button', { name: 'Lock', exact: true }).waitFor();
    assert.equal((await bridge('state')).locked, false, 'Never resumes before displaying an unlock prompt');
    assert.equal(await page.getByLabel('Master password', { exact: true }).isVisible(), false);
  }
}
async function stop() {
  if (!running) return;
  const app = running; running = undefined;
  let timer: NodeJS.Timeout | undefined;
  await Promise.race([app.close(), new Promise<void>(resolve => { timer = setTimeout(() => { app.process().kill('SIGKILL'); resolve(); }, 5000); })]);
  if (timer) clearTimeout(timer);
}
async function exists(filename: string) {
  try { await stat(filename); return true; } catch (error: any) { if (error.code === 'ENOENT') return false; throw error; }
}
async function settings(minutes: number) {
  await page.locator('.sidebar').getByRole('button', { name: 'Settings', exact: false }).click();
  await page.locator('#idle').selectOption(String(minutes));
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const state = await bridge('state');
    if (state.settings.idleMinutes === minutes && state.hasRememberedSession === (minutes === 0)) break;
    await page.waitForTimeout(25);
  }
  const state = await bridge('state');
  assert.equal(state.settings.idleMinutes, minutes);
  assert.equal(state.hasRememberedSession, minutes === 0, 'Settings finish protecting or forgetting the device session');
}
async function unlock() {
  assert.equal(await page.getByLabel('Secret Key', { exact: true }).isVisible(), false, 'Device Secret Key pairing survives restarts');
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click();
  await page.getByRole('button', { name: 'Lock', exact: true }).waitFor();
  assert.equal((await bridge('state')).locked, false);
}
async function assertProtectedCache() {
  const bytes = await readFile(sessionFile, 'utf8').catch(async error => {
    const current = await bridge('state');
    const metadata = await running!.evaluate(({ app }) => ({ root: app.getPath('userData'), env: process.env.JJ_VAULT_DATA_DIR }));
    throw new Error(`Protected session cache missing (${String(error?.code)}), locked=${current.locked}, remembered=${current.hasRememberedSession}, files=${JSON.stringify(await readdir(data))}, location=${JSON.stringify(metadata)}`);
  });
  assert.equal((await stat(sessionFile)).mode & 0o777, 0o600);
  assert.ok(!bytes.includes(master)); assert.ok(!bytes.includes(secretKey)); assert.ok(!bytes.includes(fixturePassword));
  assert.equal((await stat(secretFile)).mode & 0o777, 0o600);
  return bytes;
}

try {
  await launch('create');
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Confirm master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).click();
  await page.getByRole('heading', { name: 'Your vault is ready.', exact: true }).waitFor();
  secretKey = (await page.locator('.hint.secretkey').textContent())!.trim(); assert.match(secretKey, /^JJ1\./);
  await page.getByRole('button', { name: 'I saved my Secret Key', exact: true }).click();
  const first = await bridge('state');
  const itemId = await bridge('saveItem', { item: { type: 'login', title: 'Retained session fixture', vaultId: first.vaults[0].id, username: 'fixture@example.test', password: fixturePassword, urls: ['https://example.test'] } });
  await settings(0);
  await assertProtectedCache();

  // Closing the last window leaves the vault service running. Activating the app
  // shows the same unlocked window, without another authentication screen.
  await running!.evaluate(({ BrowserWindow }) => { BrowserWindow.getAllWindows()[0].close(); });
  assert.equal(await running!.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length), 1);
  assert.equal(await running!.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].isVisible()), false);
  assert.equal((await bridge('state')).locked, false);
  await running!.evaluate(({ app }) => { app.emit('activate'); });
  assert.equal(await running!.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].isVisible()), true);
  await running!.evaluate(({ powerMonitor }) => { powerMonitor.getSystemIdleTime = () => 365 * 86400; });
  for (const event of ['suspend', 'lock-screen', 'user-did-resign-active']) {
    await running!.evaluate(({ powerMonitor }, name) => { powerMonitor.emit(name); }, event);
    assert.equal((await bridge('state')).locked, false, `Never ignores ${event}`);
  }
  await page.waitForTimeout(1250);
  assert.equal((await bridge('state')).locked, false, 'Never ignores the periodic idle check');
  // Electron may emit before-quit more than once. The second notification must
  // not discard the snapshot after the first notification cleared memory.
  await running!.evaluate(({ app }) => {
    app.emit('before-quit', { preventDefault() {} });
    app.emit('before-quit', { preventDefault() {} });
  });
  await assertProtectedCache();
  await stop();
  await launch('open');
  assert.equal((await bridge('item', { id: itemId })).password, fixturePassword, 'Cold restart preserves the real encrypted vault content');
  await assertProtectedCache();

  // Manual lock is an intentional persistent boundary, including after quitting.
  await page.getByRole('button', { name: 'Lock', exact: true }).click();
  await page.getByRole('heading', { name: 'Unlock your vault', exact: true }).waitFor();
  assert.equal(await exists(sessionFile), false, 'Manual lock immediately removes automatic resume');
  await stop(); await launch('locked'); await unlock();
  await assertProtectedCache();

  // Exercise the owner CLI, rather than a renderer simulation. The lock request
  // must invalidate resume before its response, without waiting for an idle tick.
  const port = (await bridge('state')).servicePort;
  await runCli(['lock'], { directory: data, port, output: () => {} });
  assert.equal(await exists(sessionFile), false, 'Owner CLI lock immediately removes automatic resume');
  assert.equal((await bridge('state')).locked, true);
  await stop(); await launch('locked'); await unlock();

  await settings(5);
  assert.equal(await exists(sessionFile), false, 'Choosing a positive timeout removes automatic resume');
  await stop(); await launch('locked'); await unlock();
  assert.equal((await bridge('state')).settings.idleMinutes, 5);
  assert.equal(await exists(sessionFile), false, 'Positive timeout never creates automatic resume');
  await settings(0);
  const validCache = await assertProtectedCache();
  await stop();

  await writeFile(sessionFile, '{invalid fixture cache', { mode: 0o600 });
  await launch('locked');
  assert.equal((await bridge('state')).hasRememberedSecretKey, true, 'Corrupt resume cache does not discard Secret Key pairing');
  await unlock(); await assertProtectedCache(); await stop();
  const foreignCache = JSON.parse(validCache); foreignCache.identity = 'foreign-vault-session-fixture:' + '0'.repeat(64);
  await writeFile(sessionFile, JSON.stringify(foreignCache), { mode: 0o600 });
  await launch('locked'); await unlock(); await assertProtectedCache(); await stop();

  // Packaged smoke tests opt out of both device caches. Existing cache bytes
  // cannot silently unlock a process that explicitly disables remembering.
  await launch('locked', false);
  assert.equal((await bridge('state')).hasRememberedSecretKey, false);
  await stop();
  await launch('open');

  // Restore authenticates the replacement vault, but must replace any old
  // protected root key. A corrupt preexisting cache cannot survive the action.
  const backup = path.join(data, 'synthetic-restore.jjbackup');
  await runCli(['backup', backup], { directory: data, port: (await bridge('state')).servicePort, output: () => {} });
  const beforeRestore = await readFile(sessionFile, 'utf8');
  await running!.evaluate(({ dialog }, filename) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [filename] }); }, backup);
  assert.equal(await bridge('restore', { password: master, secretKey }), true);
  const afterRestore = await assertProtectedCache();
  assert.notEqual(afterRestore, beforeRestore, 'Owner restore replaces protected session cache');
  await stop(); await launch('open');
  assert.equal((await bridge('item', { id: itemId })).password, fixturePassword);
  assert.deepEqual(errors, []);
  process.stdout.write('Session resume passed: protected cold restart, close hides, activate reopens, Never ignores idle and system events, manual and owner CLI locks persist, positive timeout disables resume, corrupt and foreign caches fail closed, explicit cache opt out, and owner restore replaces the protected session. Real Keychain untouched.\n');
} catch (error) {
  process.stderr.write(`Session resume failed: ${error instanceof Error ? error.message : String(error)}\n`);
  throw error;
} finally {
  await stop();
  await rm(data, { recursive: true, force: true });
}
