import { _electron as electron, type Page } from '@playwright/test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// Only disposable synthetic data is used. The OS encryption adapter is replaced
// before vault creation, so the test never reads or writes the real Keychain.
const master = 'Lock usability fixture master password 2026';
const data = await mkdtemp(path.join(tmpdir(), 'jjvault-lock-ui-'));
const running = await electron.launch({
  args: ['dist/desktop/main.cjs'],
  env: { ...process.env, JJ_VAULT_DATA_DIR: data, JJ_VAULT_PORT: '0', JJ_VAULT_REMEMBER_SECRET: '1' },
  timeout: 30_000,
});
const errors: string[] = [];
async function state(page: Page) { return page.evaluate(() => (window as any).vault.invoke('state')); }
async function masterUnlock(page: Page) {
  assert.equal(await page.getByLabel('Secret Key', { exact: true }).isVisible(), false, 'Remembered Secret Key is not requested');
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click();
  await page.getByRole('button', { name: 'Lock', exact: true }).waitFor().catch(async error => {
    const result = await state(page);
    const message = await page.locator('#autherror').textContent().catch(() => null);
    throw new Error(`Master password only unlock failed (locked=${result.locked}, remembered=${result.hasRememberedSecretKey}): ${message || (error instanceof Error ? error.message : String(error))}`);
  });
  assert.equal((await state(page)).locked, false);
}

try {
  const page = await running.firstWindow({ timeout: 15_000 }); page.setDefaultTimeout(15_000);
  page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).waitFor();
  await running.evaluate(({ safeStorage, powerMonitor, clipboard }) => {
    const crypto = process.getBuiltinModule('node:crypto') as typeof import('node:crypto');
    const key = crypto.randomBytes(32);
    safeStorage.isEncryptionAvailable = () => true;
    safeStorage.encryptString = plaintext => {
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
      return Buffer.concat([nonce, cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);
    };
    safeStorage.decryptString = ciphertext => {
      const cipher = crypto.createDecipheriv('aes-256-gcm', key, ciphertext.subarray(0, 12));
      cipher.setAuthTag(ciphertext.subarray(-16));
      return Buffer.concat([cipher.update(ciphertext.subarray(12, -16)), cipher.final()]).toString('utf8');
    };
    powerMonitor.getSystemIdleTime = () => 0;
    clipboard.readText = async () => '';
    clipboard.writeText = async () => {};
    clipboard.clear = () => {};
  });

  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Confirm master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).click();
  await page.getByRole('heading', { name: 'Your vault is ready.' }).waitFor();
  const secretKey = (await page.locator('.hint.secretkey').textContent())!.trim();
  assert.match(secretKey, /^JJ1\./);
  await page.getByRole('button', { name: 'I saved my Secret Key' }).click();
  assert.equal((await state(page)).hasRememberedSecretKey, true);
  const protectedFile = path.join(data, 'device-secret.json');
  const protectedValue = await readFile(protectedFile, 'utf8');
  assert.ok(!protectedValue.includes(secretKey)); assert.ok(!protectedValue.includes(master));
  assert.equal((await stat(protectedFile)).mode & 0o777, 0o600);

  await page.locator('.sidebar').getByRole('button', { name: 'Settings', exact: false }).click();
  await page.getByRole('heading', { name: 'Settings & connections', exact: true }).waitFor();
  await page.locator('#idle').selectOption('0');
  await page.getByText('Never keeps the vault unlocked on this Mac, including after reopening.', { exact: true }).waitFor();
  assert.equal(await page.locator('#idle').inputValue(), '0');
  assert.equal((await state(page)).settings.idleMinutes, 0);
  const preferences = JSON.parse(await readFile(path.join(data, 'device-preferences.json'), 'utf8'));
  assert.equal(preferences.idleMinutes, 0);

  await running.evaluate(({ powerMonitor }) => { powerMonitor.getSystemIdleTime = () => 365 * 86400; });
  for (const event of ['suspend', 'lock-screen', 'user-did-resign-active']) {
    await running.evaluate(({ powerMonitor }, event) => { powerMonitor.emit(event); }, event);
    assert.equal((await state(page)).locked, false, `Never ignores ${event}`);
  }
  // Exercise the app's real periodic idle check, rather than only its event handlers.
  await page.waitForTimeout(1250);
  assert.equal((await state(page)).locked, false, 'Never ignores a huge system idle time');
  await page.getByRole('button', { name: 'Lock', exact: true }).click();
  await page.getByRole('heading', { name: 'Unlock your vault', exact: true }).waitFor();
  assert.equal((await state(page)).locked, true, 'Manual lock still works with Never');
  assert.equal((await state(page)).hasRememberedSecretKey, true);
  // A transient OS protection failure must not discard a valid remembered key.
  await running.evaluate(({ safeStorage }) => {
    safeStorage.encryptString = () => { throw new Error('Synthetic OS encryption temporarily unavailable'); };
  });
  await masterUnlock(page);
  assert.equal((await state(page)).hasRememberedSecretKey, true, 'Transient encryption failure preserves remembered pairing');
  assert.equal((await state(page)).settings.idleMinutes, 0, 'Never survives manual unlock');

  // Explicitly choosing a different key must use that key, rather than silently
  // falling back to the saved value after an incorrect override.
  await page.getByRole('button', { name: 'Lock', exact: true }).click();
  await page.getByRole('button', { name: 'Use a different Secret Key', exact: true }).click();
  await page.getByLabel('Master password', { exact: true }).fill(master);
  const wrongKey = secretKey.slice(0, 4) + (secretKey[4] === 'A' ? 'B' : 'A') + secretKey.slice(5);
  await page.getByLabel('Secret Key', { exact: true }).fill(wrongKey);
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click();
  await page.locator('#autherror').filter({ hasText: /.+/ }).waitFor();
  assert.equal((await state(page)).locked, true);
  await page.getByRole('button', { name: 'Use the saved Secret Key', exact: true }).click();
  await masterUnlock(page);

  // Positive control: enabling an ordinary timeout restores automatic event locking.
  await running.evaluate(({ powerMonitor }) => { powerMonitor.getSystemIdleTime = () => 0; });
  await page.locator('.sidebar').getByRole('button', { name: 'Settings', exact: false }).click();
  await page.locator('#idle').selectOption('5');
  await page.getByText('Locks on idle, sleep, and screen lock. Choose Never to turn automatic locking off.', { exact: true }).waitFor();
  assert.equal((await state(page)).settings.idleMinutes, 5);
  await running.evaluate(({ powerMonitor }) => { powerMonitor.emit('lock-screen'); });
  await page.getByRole('heading', { name: 'Unlock your vault', exact: true }).waitFor();
  assert.equal((await state(page)).locked, true);
  assert.deepEqual(errors, []);
  process.stdout.write('Lock usability passed: Never persisted, huge idle and all automatic events ignored, manual lock preserved, master password only unlock with remembered key, incorrect key override denied, normal automatic lock restored. Real Keychain untouched.\n');
} catch (error) {
  process.stderr.write(`Lock usability failed: ${error instanceof Error ? error.message : String(error)}\n`);
  throw error;
} finally {
  let timeout: NodeJS.Timeout | undefined;
  await Promise.race([running.close(), new Promise<void>(resolve => { timeout = setTimeout(() => { running.process().kill('SIGKILL'); resolve(); }, 5000); })]);
  if (timeout) clearTimeout(timeout);
  await rm(data, { recursive: true, force: true });
}
