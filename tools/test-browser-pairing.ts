import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { _electron as electron, type ElectronApplication, type Page } from '@playwright/test';
import { newItem } from '../packages/core/src/index.ts';

// The real desktop handler and native host use only this disposable synthetic vault.
// Override Electron's home lookup before any pairing so browser manifests cannot
// reach the owner's real home. Protected device storage and notifications are disabled.
const testApp = process.env.JJ_VAULT_TEST_APP;
if (testApp !== undefined && (!path.isAbsolute(testApp) || /[\0\r\n]/.test(testApp))) {
  throw new Error('JJ_VAULT_TEST_APP must be an absolute app executable path.');
}
const fixture = await mkdtemp(path.join(tmpdir(), "jjvault-browser's fixture-"));
const homeDirectory = path.join(fixture, "owner's fake home with spaces");
const dataDirectory = path.join(homeDirectory, 'private vault data');
const extensionId = 'a'.repeat(32);
const wrongExtensionId = 'b'.repeat(32);
const caller = `chrome-extension://${extensionId}/`;
const website = 'https://browser-pairing.example.invalid/login';
const password = 'Synthetic browser pairing password 93572!';
const children = new Set<ChildProcess>();
const bridgeFiles = [
  path.join(dataDirectory, 'native-host.cjs'),
  path.join(dataDirectory, 'jjvault-browser-host'),
  path.join(dataDirectory, 'browser-host.json'),
  path.join(homeDirectory, 'Library', 'Application Support', 'Google', 'Chrome', 'NativeMessagingHosts', 'com.john.jjvault.json'),
];
let running: ElectronApplication | undefined;

async function bridge(page: Page, action: string, payload: unknown = {}): Promise<any> {
  return page.evaluate(({ action, payload }) => (window as any).vault.invoke(action, payload), { action, payload });
}
async function noBridgeFiles() {
  for (const filename of bridgeFiles) await assert.rejects(lstat(filename), { code: 'ENOENT' });
  assert.deepEqual(await readdir(homeDirectory), ['private vault data']);
}
interface NativeExecution { code: number | null; stdout: Buffer; stderr: string }
async function nativeMessages(messages: unknown[], origin = caller): Promise<NativeExecution> {
  const frames = messages.map(message => {
    const body = Buffer.from(JSON.stringify(message));
    const header = Buffer.alloc(4); header.writeUInt32LE(body.length);
    return Buffer.concat([header, body]);
  });
  const input = Buffer.concat(frames);
  return new Promise((resolve, reject) => {
    const child = spawn(bridgeFiles[1]!, [origin], { env: { ...process.env }, stdio: ['pipe', 'pipe', 'pipe'] });
    children.add(child);
    const chunks: Buffer[] = [];
    let stderr = '', outputLength = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Synthetic browser host timed out')); }, 15_000);
    child.stdout.on('data', chunk => {
      const bytes = Buffer.from(chunk); outputLength += bytes.length;
      if (outputLength > 1_048_576) { child.kill('SIGKILL'); reject(new Error('Synthetic browser response exceeded its bound')); }
      else chunks.push(bytes);
    });
    child.stderr.on('data', chunk => {
      stderr += chunk.toString();
      if (stderr.length > 16_384) { child.kill('SIGKILL'); reject(new Error('Synthetic browser diagnostics exceeded their bound')); }
    });
    child.stdin.on('error', error => { if ((error as NodeJS.ErrnoException).code !== 'EPIPE') reject(error); });
    child.once('error', error => { clearTimeout(timer); children.delete(child); reject(error); });
    child.once('close', code => { clearTimeout(timer); children.delete(child); resolve({ code, stdout: Buffer.concat(chunks), stderr }); });
    // Split the first native header across writes, then deliver two frames together.
    child.stdin.write(input.subarray(0, 2));
    setImmediate(() => { if (!child.stdin.destroyed) child.stdin.end(input.subarray(2)); });
  });
}
function responses(execution: NativeExecution): any[] {
  assert.equal(execution.code, 0, execution.stderr);
  const results: any[] = [];
  let offset = 0;
  while (offset < execution.stdout.length) {
    assert.ok(execution.stdout.length - offset >= 4, 'Every native response has a complete header');
    const length = execution.stdout.readUInt32LE(offset); offset += 4;
    assert.ok(length >= 2 && length <= 1_048_576);
    assert.ok(offset + length <= execution.stdout.length, 'Every native response has a complete payload');
    results.push(JSON.parse(execution.stdout.subarray(offset, offset + length).toString('utf8')));
    offset += length;
  }
  return results;
}

try {
  await mkdir(homeDirectory, { mode: 0o700 });
  running = await electron.launch({
    ...(testApp ? { executablePath: testApp } : {}),
    args: testApp ? ['--use-mock-keychain'] : ['dist/desktop/main.cjs', '--use-mock-keychain'],
    env: { ...process.env, JJ_VAULT_DATA_DIR: dataDirectory, JJ_VAULT_PORT: '0', JJ_VAULT_REMEMBER_SECRET: '0' },
    timeout: 30_000,
  });
  const page = await running.firstWindow({ timeout: 15_000 }); page.setDefaultTimeout(15_000);
  const appLayout = await running.evaluate(({ app }) => ({ packaged: app.isPackaged, appPath: app.getAppPath(), runtime: process.execPath }));
  if (testApp) assert.equal(appLayout.packaged, true, 'The configured executable launches the packaged application');
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).waitFor();
  await running.evaluate(({ app, dialog, powerMonitor, Notification, clipboard }, fakeHome) => {
    const originalGetPath = app.getPath.bind(app);
    app.getPath = name => name === 'home' ? fakeHome : originalGetPath(name);
    powerMonitor.getSystemIdleTime = () => 0;
    Notification.prototype.show = () => {};
    clipboard.readText = async () => '';
    clipboard.writeText = async () => {};
    clipboard.clear = () => {};
    (globalThis as any).fixturePairingDialogs = [];
    (globalThis as any).fixturePairingResponse = 0;
    dialog.showMessageBox = (async (...args: any[]) => {
      const options = args.at(-1);
      (globalThis as any).fixturePairingDialogs.push({ message: options.message, buttons: options.buttons, defaultId: options.defaultId });
      return { response: (globalThis as any).fixturePairingResponse, checkboxChecked: false };
    }) as typeof dialog.showMessageBox;
  }, homeDirectory);
  assert.equal(await running.evaluate(({ app }) => app.getPath('home')), homeDirectory);

  const master = 'Synthetic browser pairing master password 2026';
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Confirm master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).click();
  await page.getByRole('heading', { name: 'Your vault is ready.', exact: true }).waitFor();
  await page.getByRole('button', { name: 'I saved my Secret Key', exact: true }).click();
  await bridge(page, 'settings', { idleMinutes: 0, notifyAssistant: false });
  const state = await bridge(page, 'state');
  assert.ok(Number.isInteger(state.servicePort) && state.servicePort > 0);
  const personal = state.vaults.find((vault: any) => vault.name === 'Personal'); assert.ok(personal);
  for (const vault of state.vaults) await bridge(page, 'updateVault', { id: vault.id, allowBrowser: vault.id === personal.id });
  const { id: _unused, ...item } = newItem('login', 'Synthetic browser pairing login', personal.id);
  const itemId = await bridge(page, 'saveItem', { item: { ...item, username: 'synthetic@example.invalid', password, urls: [website] } });
  await page.locator('.sidebar').getByRole('button', { name: 'Settings', exact: false }).click();
  await page.getByRole('heading', { name: 'Settings & connections', exact: true }).waitFor();

  await page.getByLabel('Extension ID', { exact: true }).fill('../invalid extension');
  await page.getByRole('button', { name: 'Pair extension', exact: true }).click();
  await page.locator('#toast').filter({ hasText: 'Invalid extension ID' }).waitFor();
  assert.deepEqual(await running.evaluate(() => (globalThis as any).fixturePairingDialogs), []);
  await noBridgeFiles();

  // Await the actual IPC result for cancellation, which intentionally has no toast.
  await page.getByLabel('Extension ID', { exact: true }).fill(extensionId);
  assert.equal(await bridge(page, 'pairBrowser', { id: extensionId }), false);
  const dialogs = await running.evaluate(() => (globalThis as any).fixturePairingDialogs);
  assert.deepEqual(dialogs, [{ message: 'Allow this browser extension to use JJ Vault?', buttons: ['Cancel', 'Pair extension'], defaultId: 0 }]);
  await noBridgeFiles();

  await running.evaluate(() => { (globalThis as any).fixturePairingResponse = 1; });
  await page.getByRole('button', { name: 'Pair extension', exact: true }).click();
  await page.locator('#toast').filter({ hasText: 'Extension paired' }).waitFor();
  assert.equal((await running.evaluate(() => (globalThis as any).fixturePairingDialogs)).length, 2);
  for (const filename of bridgeFiles) {
    const info = await lstat(filename);
    assert.equal(info.isFile(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.nlink, 1);
    assert.equal(info.uid, process.getuid?.());
    assert.equal(info.mode & 0o777, filename === bridgeFiles[1] ? 0o700 : 0o600);
  }
  assert.equal((await lstat(dataDirectory)).mode & 0o777, 0o700);
  const config = JSON.parse(await readFile(bridgeFiles[2]!, 'utf8'));
  assert.equal(config.port, state.servicePort);
  assert.equal(config.browserTokenFile, path.join(dataDirectory, 'browser-token'));
  assert.deepEqual(config.chromeExtensionIds, [extensionId]); assert.deepEqual(config.firefoxExtensionIds, []);
  const manifest = JSON.parse(await readFile(bridgeFiles[3]!, 'utf8'));
  assert.equal(manifest.name, 'com.john.jjvault'); assert.equal(manifest.type, 'stdio');
  assert.equal(manifest.path, bridgeFiles[1]); assert.deepEqual(manifest.allowed_origins, [caller]);
  const expectedHost = testApp
    ? (createRequire(import.meta.url)('@electron/asar') as { extractFile(archive: string, filename: string): Buffer }).extractFile(appLayout.appPath, 'dist/service/native-host.cjs')
    : await readFile('dist/service/native-host.cjs');
  assert.deepEqual(await readFile(bridgeFiles[0]!), expectedHost);
  const launcher = await readFile(bridgeFiles[1]!, 'utf8');
  assert.ok(launcher.includes("'ELECTRON_RUN_AS_NODE=1'"));
  assert.ok(launcher.includes(`'${appLayout.runtime.replaceAll("'", "'\\''")}'`), 'The launcher uses the actual app runtime');
  assert.ok(launcher.includes("'\\''"), 'The generated launcher quotes the apostrophe in the fixture path');
  assert.equal(launcher.includes(password), false);

  const [listed, filled] = responses(await nativeMessages([{ action: 'list', url: website }, { action: 'get', id: itemId, url: website }]));
  assert.deepEqual(listed, { ok: true, result: [{ id: itemId, title: item.title, username: 'synthetic@example.invalid', type: 'login' }] });
  assert.equal(JSON.stringify(listed).includes(password), false);
  assert.equal(filled.ok, true); assert.equal(filled.result.id, itemId);
  assert.equal(filled.result.username, 'synthetic@example.invalid'); assert.equal(filled.result.password, password);
  const wrongCaller = await nativeMessages([{ action: 'list', url: website }], `chrome-extension://${wrongExtensionId}/`);
  assert.equal(wrongCaller.code, 1); assert.equal(wrongCaller.stdout.length, 0);
  assert.equal(wrongCaller.stderr.includes(password), false);

  await bridge(page, 'updateVault', { id: personal.id, allowBrowser: false });
  const [disabledList, disabledGet] = responses(await nativeMessages([{ action: 'list', url: website }, { action: 'get', id: itemId, url: website }]));
  assert.deepEqual(disabledList, { ok: true, result: [] });
  assert.equal(disabledGet.ok, false); assert.equal(JSON.stringify(disabledGet).includes(password), false);
  await bridge(page, 'updateVault', { id: personal.id, allowBrowser: true });
  await bridge(page, 'lock');
  const [lockedList, lockedGet] = responses(await nativeMessages([{ action: 'list', url: website }, { action: 'get', id: itemId, url: website }]));
  for (const result of [lockedList, lockedGet]) {
    assert.equal(result.ok, false); assert.match(result.error, /locked/i);
    assert.equal(JSON.stringify(result).includes(password), false);
  }
  await assert.rejects(bridge(page, 'pairBrowser', { id: wrongExtensionId }), /Vault is locked/);
  assert.equal((await running.evaluate(() => (globalThis as any).fixturePairingDialogs)).length, 2);
  assert.deepEqual(errors, []);
  process.stdout.write('Browser pairing passed: invalid ID rejected without confirmation, cancellation writes no bridge, accepted owner UI installs four private files with the actual service port, quoted Electron launcher exchanges list and get frames, wrong caller rejected, disabled vault and locked vault deny secrets. Actual Chrome extension loading remains a separate check.\n');
} finally {
  for (const child of children) child.kill('SIGKILL');
  try {
    if (running) {
      const instance = running;
      const processHandle = instance.process();
      let timer: NodeJS.Timeout | undefined;
      try {
        await Promise.race([instance.close(), new Promise<void>(resolve => { timer = setTimeout(() => { processHandle.kill('SIGKILL'); resolve(); }, 5000); })]);
      } finally {
        if (timer) clearTimeout(timer);
        if (processHandle.exitCode === null) processHandle.kill('SIGKILL');
      }
    }
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
}
