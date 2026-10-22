import { _electron as electron, type Page } from '@playwright/test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { newItem } from '../packages/core/src/index.ts';

// This regression uses only a disposable synthetic vault and private fixture tokens.
// It never unlocks the user's vault or contacts the real Keychain, clipboard, or APNs.
const testApp = process.env.JJ_VAULT_TEST_APP;
if (testApp !== undefined && (!path.isAbsolute(testApp) || /[\0\r\n]/.test(testApp))) {
  throw new Error('JJ_VAULT_TEST_APP must be an absolute app executable path.');
}
const data = await mkdtemp(path.join(tmpdir(), "jjvault-agent's fixture-"));
const master = 'Synthetic agent management master password 2026';
const password = 'Synthetic old agent password 82745!';
const replacement = 'Synthetic new agent password 92835!';
const running = await electron.launch({
  ...(testApp ? { executablePath: testApp } : {}),
  args: testApp ? ['--use-mock-keychain'] : ['dist/desktop/main.cjs'],
  env: { ...process.env, JJ_VAULT_DATA_DIR: data, JJ_VAULT_PORT: '0', JJ_VAULT_REMEMBER_SECRET: '0' },
  timeout: 30_000,
});
const errors: string[] = [];
let port = 0;
async function bridge(page: Page, action: string, payload: unknown = {}) {
  return page.evaluate(({ action, payload }) => (window as any).vault.invoke(action, payload), { action, payload });
}
function fixtureItem(type: Parameters<typeof newItem>[0], title: string, vaultId: string) {
  const { id, ...item } = newItem(type, title, vaultId);
  return item;
}
async function helper(args: string[], input?: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    // The token comes from the named fixture file. All write fields enter via stdin.
    const child = spawn(process.execPath, [path.join(data, 'agent-client.mjs'), ...args], {
      env: { ...process.env, JJ_VAULT_AGENT_DIR: path.join(data, 'agent-tokens'), JJ_VAULT_PORT: String(port) },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Fixture agent helper timed out')); }, 20_000);
    child.stdout.on('data', bytes => { stdout += bytes.toString(); if (stdout.length > 1_048_576) child.kill('SIGKILL'); });
    child.stderr.on('data', bytes => { stderr += bytes.toString(); if (stderr.length > 16384) child.kill('SIGKILL'); });
    child.on('error', error => { clearTimeout(timeout); reject(error); });
    child.on('close', code => {
      clearTimeout(timeout);
      if (code !== 0) { reject(new Error(stderr.trim() || 'Fixture agent helper failed')); return; }
      try { resolve(JSON.parse(stdout)); } catch { reject(new Error('Fixture agent helper returned invalid JSON')); }
    });
    child.stdin.end(input === undefined ? undefined : JSON.stringify(input));
  });
}
async function changeAgent(page: Page, permission: string, vaultNames: string[], displayName = 'Grillin renamed') {
  await page.getByTestId('agent-grillin').getByRole('button', { name: 'Edit permissions', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('heading', { name: 'Edit agent', exact: true }).waitFor();
  await dialog.getByLabel('Agent name', { exact: true }).fill(displayName);
  assert.equal(await dialog.getByLabel('Client name', { exact: true }).isEditable(), false);
  await dialog.getByLabel('Permission', { exact: true }).selectOption(permission);
  for (const name of ['Personal', 'Business', 'Social Media']) await dialog.getByLabel(name, { exact: true }).setChecked(vaultNames.includes(name));
  await dialog.getByRole('button', { name: 'Save changes', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
}

try {
  const page = await running.firstWindow({ timeout: 15_000 }); page.setDefaultTimeout(15_000);
  const appLayout = await running.evaluate(({ app }) => ({ packaged: app.isPackaged, appPath: app.getAppPath(), runtime: process.execPath }));
  if (testApp) assert.equal(appLayout.packaged, true, 'The configured executable launches the packaged application');
  page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).waitFor();
  await running.evaluate(({ powerMonitor, Notification, clipboard }) => {
    powerMonitor.getSystemIdleTime = () => 0;
    const notifications: {title: string; body: string}[] = [];
    (globalThis as any).fixtureAgentNotifications = notifications;
    Notification.prototype.show = function () { notifications.push({ title: this.title, body: this.body }); };
    let value = '';
    clipboard.readText = async () => value;
    clipboard.writeText = async text => { value = text; };
    clipboard.clear = () => { value = ''; };
  });
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Confirm master password', { exact: true }).fill(master);
  await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).click();
  await page.getByRole('heading', { name: 'Your vault is ready.', exact: true }).waitFor();
  await page.getByRole('button', { name: 'I saved my Secret Key', exact: true }).click();
  await bridge(page, 'settings', { idleMinutes: 0, notifyAssistant: false });
  const initial = await bridge(page, 'state'); port = initial.servicePort;
  assert.ok(port > 0);
  const personal = initial.vaults.find((v: any) => v.name === 'Personal');
  const business = initial.vaults.find((v: any) => v.name === 'Business');
  for (const vault of initial.vaults) await bridge(page, 'updateVault', { id: vault.id, allowAssistant: true });
  const personalTitle = 'Personal synthetic account';
  const businessTitle = 'Business synthetic account';
  const personalId = await bridge(page, 'saveItem', { item: { ...fixtureItem('login', personalTitle, personal.id), username: 'personal@example.invalid', password, urls: ['https://personal.example.invalid'], allowAssistant: true } });
  await bridge(page, 'saveItem', { item: { ...fixtureItem('login', businessTitle, business.id), username: 'business@example.invalid', password: 'Synthetic business password', urls: ['https://business.example.invalid'], allowAssistant: true } });
  await bridge(page, 'saveItem', { item: { ...fixtureItem('bankAccount', 'Synthetic blocked bank', personal.id), password: 'Synthetic blocked bank password', allowAssistant: true } });
  await bridge(page, 'saveItem', { item: { ...fixtureItem('login', 'X Money synthetic', personal.id), password: 'Synthetic blocked money password', urls: ['https://x.money'], allowAssistant: true } });
  await page.reload();

  await page.locator('.sidebar').getByRole('button', { name: 'Agents', exact: false }).click();
  await page.getByRole('heading', { name: 'Agents', exact: true, level: 1 }).waitFor();
  await page.getByText(/iPhone push is not configured/).waitFor();
  await page.getByRole('button', { name: 'Add agent', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('heading', { name: 'Add agent', exact: true }).waitFor();
  assert.equal(await dialog.getByLabel('Permission', { exact: true }).inputValue(), 'full', 'New agents default to full access');
  await dialog.getByLabel('Agent name', { exact: true }).fill('Grillin fixture');
  await dialog.getByLabel('Client name', { exact: true }).fill('grillin');
  for (const name of ['Personal', 'Business', 'Social Media']) await dialog.getByLabel(name, { exact: true }).setChecked(name === 'Personal');
  await dialog.getByRole('button', { name: 'Create agent', exact: true }).click();
  await dialog.getByRole('heading', { name: 'Agent ready on this Mac', exact: true }).waitFor();
  const tokenFile = path.join(data, 'agent-tokens', 'grillin');
  assert.equal((await stat(path.dirname(tokenFile))).mode & 0o777, 0o700);
  assert.equal((await stat(tokenFile)).mode & 0o777, 0o600);
  const token = (await readFile(tokenFile, 'utf8')).trim();
  assert.match(token, /^jjv_/);
  assert.equal((await page.content()).includes(token), false, 'Agent token is stored privately and absent from the DOM');
  const command = await dialog.getByTestId('agent-helper-command').innerText();
  if (testApp) {
    assert.ok(command.includes('ELECTRON_RUN_AS_NODE=1'));
    assert.ok(command.includes(`'${appLayout.runtime.replaceAll("'", "'\\''")}'`), 'The helper command uses the actual packaged runtime');
  } else {
    assert.equal(command.includes('/Users/john/'), false);
  }
  assert.equal(command.includes(token), false);
  assert.equal((await stat(path.join(data, 'agent-client.mjs'))).mode & 0o777, 0o600);
  const expectedHelper = testApp
    ? (createRequire(import.meta.url)('@electron/asar') as { extractFile(archive: string, filename: string): Buffer }).extractFile(appLayout.appPath, 'dist/service/agent-client.mjs')
    : await readFile('dist/service/agent-client.mjs');
  assert.deepEqual(await readFile(path.join(data, 'agent-client.mjs')), expectedHelper);
  const discovered = await new Promise<any>((resolve, reject) => {
    const child = spawn('/bin/sh', ['-c', command], { env: { ...process.env, PATH: testApp ? '/usr/bin:/bin' : path.dirname(process.execPath) + path.delimiter + (process.env.PATH || '') }, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; let error = '';
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Displayed helper command timed out')); }, 20_000);
    child.stdout.on('data', value => { output += value.toString(); });
    child.stderr.on('data', value => { error += value.toString(); });
    child.once('error', problem => { clearTimeout(timeout); reject(problem); });
    child.once('close', code => { clearTimeout(timeout); if (code !== 0) reject(new Error(error || 'Displayed helper command failed')); else { try { resolve(JSON.parse(output)); } catch { reject(new Error('Displayed helper command returned invalid JSON')); } } });
  });
  assert.deepEqual(discovered.tools, ['add_login', 'delete_login', 'generate_password', 'get_login', 'list_logins', 'search_items', 'update_login']);
  await dialog.getByRole('button', { name: 'Done', exact: true }).click();
  const registered = await bridge(page, 'state');
  assert.deepEqual(registered.phonePush, { enabled: false, configured: false });
  const agent = (registered.agents ?? registered.tokens).find((entry: any) => entry.clientName === 'grillin');
  assert.equal(agent.name, 'Grillin fixture'); assert.equal(agent.permission, 'full'); assert.deepEqual(agent.vaultIds, [personal.id]);
  await page.screenshot({ path: '/private/tmp/jj-vault-agents-ui.png' });
  const checked = await helper(['check', 'grillin']);
  assert.deepEqual(checked.tools, ['add_login', 'delete_login', 'generate_password', 'get_login', 'list_logins', 'search_items', 'update_login']);
  assert.deepEqual((await helper(['list', 'grillin'])).map((item: any) => item.name), [personalTitle]);

  // Use the built agent helper process against the app's actual local MCP endpoint.
  const addedTitle = 'Agent created synthetic login';
  const added = await helper(['add', 'grillin'], { vault: 'Personal', name: addedTitle, website: 'https://agent.example.invalid', username: 'agent@example.invalid', password, notes: 'Synthetic private note', tags: ['Fixture'] });
  assert.deepEqual(added, { name: addedTitle, website: 'https://agent.example.invalid', vault: 'Personal', tags: ['Fixture'] });
  // External writes must appear while the app stays open, without an owner refresh.
  const addedRow = page.locator('.itemrow').filter({ has: page.getByText(addedTitle, { exact: true }) });
  await addedRow.waitFor();
  await addedRow.click();
  await page.getByRole('heading', { name: addedTitle, exact: true }).waitFor();
  await page.getByText('Synthetic private note', { exact: true }).waitFor();
  const changedNote = 'Agent changed this synthetic note';
  await helper(['update', 'grillin'], { name: addedTitle, fields: { password: replacement, notes: changedNote } });
  await page.getByText(changedNote, { exact: true }).waitFor();
  await page.getByText('Password history (1)', { exact: true }).waitFor();
  const updatedState = await bridge(page, 'state');
  const updatedId = updatedState.items.find((item: any) => item.title === addedTitle).id;
  const updated = await bridge(page, 'item', { id: updatedId });
  assert.equal(updated.password, replacement); assert.equal(updated.passwordHistory.at(-1).password, password);

  // Polling must leave the owner's unfinished editing and focus intact.
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  await dialog.getByRole('heading', { name: 'Edit item', exact: true }).waitFor();
  const ownerDraftTitle = 'Owner draft must stay intact';
  const ownerDraftNote = 'Owner has not saved this synthetic draft';
  await dialog.getByLabel('Title', { exact: true }).fill(ownerDraftTitle);
  await dialog.getByLabel('Secure notes', { exact: true }).fill(ownerDraftNote);
  const deleted = await helper(['delete', 'grillin', addedTitle]);
  assert.equal(deleted.deleted, true); assert.equal(deleted.name, addedTitle);
  assert.ok(Date.parse(deleted.restoreUntil) > Date.now() + 29 * 86400_000);
  await page.waitForTimeout(3750);
  assert.equal(await dialog.isVisible(), true, 'External writes do not close an open edit dialog');
  assert.equal(await dialog.getByLabel('Title', { exact: true }).inputValue(), ownerDraftTitle);
  assert.equal(await dialog.getByLabel('Secure notes', { exact: true }).inputValue(), ownerDraftNote);
  assert.equal(await dialog.getByLabel('Secure notes', { exact: true }).evaluate(element => element === document.activeElement), true, 'Polling preserves typing focus');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await addedRow.waitFor({ state: 'detached' });
  await page.locator('.sidebar').getByRole('button', { name: 'Activity', exact: false }).click();
  await page.getByRole('heading', { name: 'Activity', level: 1, exact: true }).waitFor();
  for (const action of ['assistant.add', 'assistant.edit', 'assistant.delete']) {
    await page.locator('.activity').filter({ hasText: action }).filter({ hasText: addedTitle }).filter({ hasText: 'Grillin fixture' }).first().waitFor();
  }
  assert.ok((await bridge(page, 'item', { id: updatedId })).deletedAt);
  await bridge(page, 'restoreItem', { id: updatedId });
  assert.equal((await bridge(page, 'item', { id: updatedId })).deletedAt, undefined);
  const notifications = await running.evaluate(() => (globalThis as any).fixtureAgentNotifications);
  assert.equal(notifications.length, 3, 'Every successful write notifies even when optional read notifications are disabled');
  for (const notification of notifications) {
    assert.equal(JSON.stringify(notification).includes(password), false);
    assert.equal(JSON.stringify(notification).includes(replacement), false);
  }
  const activity = (await bridge(page, 'state')).activity;
  for (const action of ['assistant.add', 'assistant.edit', 'assistant.delete']) {
    const entry = activity.find((entry: any) => entry.action === action && entry.outcome === 'success');
    assert.equal(entry.agentClientName, 'grillin'); assert.equal(entry.agentName, 'Grillin fixture');
    assert.equal(entry.itemName, addedTitle); assert.ok(Number.isFinite(Date.parse(entry.at)));
  }
  assert.equal(JSON.stringify(activity).includes(password), false); assert.equal(JSON.stringify(activity).includes(replacement), false);

  await page.locator('.sidebar').getByRole('button', { name: 'Agents', exact: false }).click();
  await page.getByRole('heading', { name: 'Agents', level: 1, exact: true }).waitFor();
  await changeAgent(page, 'read', ['Personal']);
  const changed = await bridge(page, 'state');
  const renamed = (changed.agents ?? changed.tokens).find((entry: any) => entry.clientName === 'grillin');
  assert.equal(renamed.name, 'Grillin renamed'); assert.equal(renamed.permission, 'read');
  assert.equal((await helper(['get', 'grillin', personalTitle])).password, password);
  await assert.rejects(helper(['add', 'grillin'], { vault: 'Personal', name: 'Denied synthetic add', website: 'https://denied.invalid', username: 'denied', password }), /Agent permission denied/);
  await assert.rejects(helper(['update', 'grillin'], { name: personalTitle, fields: { password: replacement } }), /Agent permission denied/);
  await assert.rejects(helper(['delete', 'grillin', personalTitle]), /Agent permission denied/);
  assert.equal((await bridge(page, 'item', { id: personalId })).password, password);

  await changeAgent(page, 'read', ['Business']);
  assert.deepEqual((await helper(['list', 'grillin'])).map((item: any) => item.name), [businessTitle]);
  await assert.rejects(helper(['get', 'grillin', personalTitle]), /Login not found or not allowed/);
  const beforeRevoke = await fetch(`http://127.0.0.1:${port}/mcp`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) });
  assert.equal(beforeRevoke.status, 200); await beforeRevoke.body?.cancel();
  await page.getByTestId('agent-grillin').getByRole('button', { name: 'Revoke', exact: true }).click();
  await page.getByTestId('agent-grillin').getByText(/^revoked$/i).waitFor();
  const revoked = await fetch(`http://127.0.0.1:${port}/mcp`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) });
  assert.equal(revoked.status, 401); await revoked.body?.cancel();
  await assert.rejects(helper(['check', 'grillin']), /Agent token unavailable|invalid or revoked/);
  await stat(path.join(data, 'admin-token'));
  await assert.rejects(helper(['check', 'missing']), /Agent token unavailable/);
  assert.equal((await running.evaluate(() => (globalThis as any).fixtureAgentNotifications)).length, 3, 'Denied writes do not emit success notifications');
  assert.deepEqual(errors, []);
  process.stdout.write('Agents UI passed: full default, private client token, vault scope, live helper add and selected edit refresh, draft and focus preserved during external delete, visible activity audit, history, soft delete and restore, mandatory write notifications, rename, permission reduction, changed vault scope, and immediate revocation. Real vault and Keychain untouched.\n');
} catch (error) {
  process.stderr.write(`Agents UI failed: ${error instanceof Error ? error.message : String(error)}\n`);
  throw error;
} finally {
  let timeout: NodeJS.Timeout | undefined;
  await Promise.race([running.close(), new Promise<void>(resolve => { timeout = setTimeout(() => { running.process().kill('SIGKILL'); resolve(); }, 5000); })]);
  if (timeout) clearTimeout(timeout);
  await rm(data, { recursive: true, force: true });
}
