import { _electron as electron, expect, type ElectronApplication, type Page } from '@playwright/test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// Disposable vault data and a synthetic OS protection adapter installed before
// app startup. These tests never access the real Keychain or system clipboard.
const master = 'Synthetic PIN fixture master password 2026';
const itemPassword = 'Synthetic retained PIN fixture secret 192745!';
const data = await mkdtemp(path.join(tmpdir(), 'jjvault-pin-ui-'));
const bootstrap = path.join(data, 'fixture-bootstrap.cjs');
const pinFile = path.join(data, 'device-pin.json');
const sessionFile = path.join(data, 'device-session.json');
const errors: string[] = [];
let running: ElectronApplication | undefined;
let page!: Page;
let secretKey = '';
await writeFile(bootstrap, `
const electron = require('electron');
const crypto = require('node:crypto');
const key = crypto.createHash('sha256').update('Disposable JJ Vault PIN UI protection key').digest();
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
const spawn = childProcess.spawn;
childProcess.spawn = (file, args, options) => {
  if (!String(file).endsWith('JJBiometric')) return spawn(file, args, options);
  const child = new (require('node:events').EventEmitter)();
  const PassThrough = require('node:stream').PassThrough;
  child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.kill = () => true;
  child.stdin.on('finish', () => process.nextTick(() => child.emit('close', 0)));
  return child;
};
require(${JSON.stringify(path.resolve('dist/desktop/main.cjs'))});
`, { mode: 0o600 });

async function bridge(action: string, payload: unknown = {}) {
  return page.evaluate(({ action, payload }) => (window as any).vault.invoke(action, payload), { action, payload });
}
async function launch(create = false) {
  assert.equal(running, undefined);
  running = await electron.launch({ args: [bootstrap], env: { ...process.env, JJ_VAULT_DATA_DIR: data, JJ_VAULT_PORT: '0', JJ_VAULT_REMEMBER_SECRET: '1' }, timeout: 30_000 });
  page = await running.firstWindow({ timeout: 15_000 }); page.setDefaultTimeout(15_000);
  page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('button', { name: create ? 'Create JJ Vault' : 'Unlock JJ Vault', exact: true }).waitFor();
  if (!create) {
    assert.equal((await bridge('state')).locked, true, 'Cold launch requires PIN authentication');
    await expect(page.getByLabel('PIN', { exact: true })).toBeVisible();
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
async function exists(file: string): Promise<boolean> {
  try { await stat(file); return true; } catch (error: any) { if (error.code === 'ENOENT') return false; throw error; }
}
async function waitOpen() {
  await page.getByRole('button', { name: 'Lock', exact: true }).waitFor();
  assert.equal((await bridge('state')).locked, false);
}
async function lock() {
  await page.getByRole('button', { name: 'Lock', exact: true }).click();
  await page.getByLabel('PIN', { exact: true }).waitFor();
  assert.equal((await bridge('state')).locked, true);
  assert.equal(await exists(sessionFile), false);
}
async function pinUnlock(pin: string) {
  // The wrong PIN path has a real persisted cooldown. Respect it in the UI.
  const current = await bridge('state');
  if (current.pinRetryAt > Date.now()) await page.waitForTimeout(Math.min(35_000, current.pinRetryAt - Date.now() + 50));
  await page.getByLabel('PIN', { exact: true }).fill(pin);
  await expect(page.getByRole('button', { name: 'Unlock JJ Vault', exact: true })).toBeEnabled({ timeout: 35_000 });
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click();
  await waitOpen();
}
async function masterUnlock() {
  await page.getByRole('button', { name: 'Use master password instead', exact: true }).click();
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click(); await waitOpen();
}
async function settings() {
  await page.locator('.sidebar').getByRole('button', { name: 'Settings', exact: false }).click();
  await page.getByRole('heading', { name: 'Settings & connections', exact: true }).waitFor();
}
async function changePin(currentPin: string, next: string) {
  await settings(); await page.getByRole('button', { name: 'Change PIN', exact: true }).click();
  await page.getByLabel('Current PIN', { exact: true }).fill(currentPin);
  await page.getByLabel('New PIN', { exact: true }).fill(next);
  await page.getByLabel('Confirm PIN', { exact: true }).fill(next);
  await page.getByRole('button', { name: 'Save PIN', exact: true }).click();
  await expect(page.locator('#modal')).not.toBeVisible();
}
async function assertProtected() {
  assert.equal((await stat(pinFile)).mode & 0o777, 0o600);
  const bytes = await readFile(pinFile, 'utf8');
  for (const secret of [master, secretKey, itemPassword]) assert.equal(bytes.includes(secret), false);
  const state = await bridge('state');
  for (const key of ['pin', 'currentPin', 'confirmPin', 'password', 'secretKey']) assert.equal(Object.hasOwn(state, key), false, 'State includes no unlock secrets');
  assert.equal(state.pinEnabled, true);
  assert.equal(state.hasRememberedSession, false);
  assert.equal(await exists(sessionFile), false, 'PIN activation removes automatic resume');
}

try {
  await launch(true);
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Confirm master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).click();
  await page.getByRole('heading', { name: 'Your vault is ready.', exact: true }).waitFor();
  assert.equal(await page.getByRole('heading', { name: 'Choose a PIN', exact: true }).isVisible(), false, 'Emergency Kit is shown before PIN setup');
  secretKey = (await page.locator('.hint.secretkey').textContent())!.trim(); assert.match(secretKey, /^JJ1\./);
  await page.getByRole('button', { name: 'I saved my Secret Key', exact: true }).click();
  await page.getByRole('heading', { name: 'Choose a PIN', exact: true }).waitFor();
  await mkdir(path.resolve('output/qa'), { recursive: true });
  await page.screenshot({ path: path.resolve('output/qa/pin-setup.png') });
  for (const invalid of ['123', '12a4', '１２３４', '1234567']) await assert.rejects(bridge('setPin', { pin: invalid, confirmPin: invalid }), /4 to 6/);
  await page.getByLabel('PIN', { exact: true }).fill('12a4');
  await page.getByLabel('Confirm PIN', { exact: true }).fill('12a4');
  await page.getByRole('button', { name: 'Enable PIN', exact: true }).click();
  await expect(page.locator('#pinerror')).toHaveText('Choose a PIN with 4 to 6 digits.');
  assert.equal(await page.getByLabel('PIN', { exact: true }).inputValue(), '');
  await page.getByLabel('PIN', { exact: true }).fill('0123');
  await page.getByLabel('Confirm PIN', { exact: true }).fill('0124');
  await page.getByRole('button', { name: 'Enable PIN', exact: true }).click();
  await expect(page.locator('#pinerror')).toHaveText('The PINs do not match.');
  await assert.rejects(bridge('setPin', { pin: '0123', confirmPin: '0124' }), /match/);
  assert.equal((await bridge('state')).pinEnabled, false);
  await page.getByLabel('PIN', { exact: true }).fill('0123');
  await page.getByLabel('Confirm PIN', { exact: true }).fill('0123');
  await page.getByRole('button', { name: 'Enable PIN', exact: true }).click();
  await expect(page.locator('#modal')).not.toBeVisible();
  const initial = await bridge('state');
  const itemId = await bridge('saveItem', { item: { type: 'login', title: 'PIN fixture login', vaultId: initial.vaults[0].id, username: 'fixture@example.test', password: itemPassword, urls: ['https://example.test'] } });
  await assertProtected();

  await lock();
  await page.screenshot({ path: path.resolve('output/qa/pin-unlock.png') });
  await page.getByLabel('PIN', { exact: true }).fill('9999');
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click();
  await expect(page.locator('#autherror')).not.toHaveText('');
  assert.equal((await bridge('state')).locked, true);
  assert.equal(await page.getByLabel('PIN', { exact: true }).inputValue(), '', 'PIN input clears after a failed attempt');
  await page.getByRole('button', { name: 'Use master password instead', exact: true }).click();
  await page.getByRole('button', { name: 'Use PIN instead', exact: true }).click();
  await expect(page.getByLabel('PIN', { exact: true })).toBeVisible();
  await masterUnlock();
  assert.equal(await page.getByRole('heading', { name: 'Choose a PIN', exact: true }).isVisible(), false);
  await changePin('0123', '01234');
  await lock(); await assert.rejects(bridge('unlockPin', { pin: '0123' }));
  assert.equal((await bridge('state')).locked, true);
  await pinUnlock('01234');
  assert.equal((await bridge('item', { id: itemId })).password, itemPassword, 'PIN unlock preserves encrypted vault content');
  await changePin('01234', '012345');
  await settings(); await page.locator('#idle').selectOption('0');
  await expect.poll(async () => (await bridge('state')).settings.idleMinutes).toBe(0);
  await assertProtected();

  // Never still locks when a PIN enabled window is closed and reopened.
  await running!.evaluate(({ BrowserWindow }) => { BrowserWindow.getAllWindows()[0].close(); });
  assert.equal((await bridge('state')).locked, true);
  await running!.evaluate(({ app }) => { app.emit('activate'); });
  await pinUnlock('012345'); await assertProtected();
  await stop(); await launch(); await pinUnlock('012345');
  assert.equal((await bridge('state')).settings.idleMinutes, 0);
  assert.equal((await bridge('item', { id: itemId })).password, itemPassword);
  await lock(); await stop(); await launch(); await masterUnlock();

  // Forgotten PIN recovery uses the actual master password and updates the PIN.
  await settings(); await page.getByRole('button', { name: 'Change PIN', exact: true }).click();
  await page.getByRole('button', { name: 'Forgot your PIN? Use master password', exact: true }).click();
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('New PIN', { exact: true }).fill('0042');
  await page.getByLabel('Confirm PIN', { exact: true }).fill('0042');
  await page.getByRole('button', { name: 'Save PIN', exact: true }).click();
  await expect(page.locator('#modal')).not.toBeVisible();
  await lock(); await assert.rejects(bridge('unlockPin', { pin: '012345' })); await pinUnlock('0042');

  // Damaged protected PIN storage keeps the gate closed and can be repaired
  // using the master password without requiring the unreadable current PIN.
  await stop(); await writeFile(pinFile, '{invalid synthetic PIN fixture', { mode: 0o600 }); await launch();
  assert.equal((await bridge('state')).pinEnabled, true);
  assert.equal((await bridge('state')).pinAvailable, false);
  await assert.rejects(bridge('unlockPin', { pin: '0042' }), /unavailable/);
  assert.equal((await bridge('state')).locked, true);
  await masterUnlock(); await settings(); await page.getByRole('button', { name: 'Change PIN', exact: true }).click();
  await expect(page.getByLabel('Master password', { exact: true })).toBeVisible();
  assert.equal(await page.getByLabel('Current PIN', { exact: true }).isVisible(), false);
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('New PIN', { exact: true }).fill('0088');
  await page.getByLabel('Confirm PIN', { exact: true }).fill('0088');
  await page.getByRole('button', { name: 'Save PIN', exact: true }).click(); await expect(page.locator('#modal')).not.toBeVisible();
  await assertProtected(); await lock(); await pinUnlock('0088');

  // PIN access survives a lost Secret Key cache. Recovery changes and removal
  // then ask for both master password and Secret Key instead of trapping users.
  await stop(); await rm(path.join(data, 'device-secret.json')); await launch();
  assert.equal((await bridge('state')).hasRememberedSecretKey, false); await pinUnlock('0088');
  await settings(); await page.getByRole('button', { name: 'Change PIN', exact: true }).click();
  await page.getByRole('button', { name: 'Forgot your PIN? Use master password', exact: true }).click();
  await expect(page.getByLabel('Secret Key', { exact: true })).toBeVisible();
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Secret Key', { exact: true }).fill(secretKey);
  await page.getByLabel('New PIN', { exact: true }).fill('0044');
  await page.getByLabel('Confirm PIN', { exact: true }).fill('0044');
  await page.getByRole('button', { name: 'Save PIN', exact: true }).click(); await expect(page.locator('#modal')).not.toBeVisible();
  await lock(); await pinUnlock('0044');
  await settings(); await page.getByRole('button', { name: 'Remove PIN', exact: true }).click();
  await expect(page.getByLabel('Secret Key', { exact: true })).toBeVisible();
  await page.getByLabel('Secret Key', { exact: true }).fill(secretKey);
  await page.getByLabel('Master password', { exact: true }).fill('Synthetic incorrect master password');
  await page.locator('#confirmRemovePin').click(); await expect(page.locator('#pinerror')).not.toHaveText('');
  assert.equal((await bridge('state')).pinEnabled, true);
  assert.equal(await page.getByLabel('Master password', { exact: true }).inputValue(), '');
  await page.getByLabel('Master password', { exact: true }).fill(master); await page.getByLabel('Secret Key', { exact: true }).fill(secretKey); await page.locator('#confirmRemovePin').click();
  await expect(page.locator('#modal')).not.toBeVisible();
  assert.equal((await bridge('state')).pinEnabled, false); assert.equal(await exists(pinFile), false);
  await page.getByRole('button', { name: 'Lock', exact: true }).click();
  await page.getByLabel('Master password', { exact: true }).waitFor();
  assert.equal(await page.getByLabel('PIN', { exact: true }).isVisible(), false);
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Secret Key', { exact: true }).fill(secretKey);
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click();
  await page.getByRole('heading', { name: 'Choose a PIN', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Not now', exact: true }).click(); await waitOpen();
  assert.deepEqual(errors, []);
  process.stdout.write('PIN unlock passed: initial setup, invalid and mismatched PINs, leading zero 4, 5, and 6 digit PINs, failed attempts stay locked, master recovery, PIN changes reject old values, protected storage, manual lock, close and cold restart with Never, corrupt storage recovery, lost Secret Key cache recovery, and removal with master password. Real Keychain untouched.\n');
} finally {
  await stop(); await rm(data, { recursive: true, force: true });
}
