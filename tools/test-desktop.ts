import { _electron as electron, type Page } from '@playwright/test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { Readable, Writable } from 'node:stream';
import path from 'node:path';
import { runNativeHost } from '../packages/service/src/native-host.ts';
import { atomicOwnerWrite } from '../packages/service/src/security.ts';
import { decryptData } from '../packages/core/src/index.ts';
import { PDFDocument, PDFArray, PDFRawStream, decodePDFRawStream } from 'pdf-lib';

// These values are synthetic. No existing vault, profile, or browser setting is read or changed.
const master = 'UI fixture master password 2026';
const oldPassword = 'Fixture password 82673!';
const changedPassword = 'New fixture password 91827!';
const email = 'fixture@example.test';
const loginTitle = 'Example personal account';
const data = await mkdtemp(path.join(tmpdir(), 'jjvault-ui-'));
const errors: string[] = [];
const checkpoint = (value: string) => process.stdout.write(`Desktop: ${value}\n`);
const running = await electron.launch({ args: ['dist/desktop/main.cjs'], env: { ...process.env, JJ_VAULT_DATA_DIR: data, JJ_VAULT_PORT: '0', JJ_VAULT_REMEMBER_SECRET: '0' }, timeout: 30_000 });

async function bridge(page: Page, action: string, payload: unknown = {}) {
  return page.evaluate(({ action, payload }) => (window as any).vault.invoke(action, payload), { action, payload });
}
async function newItem(page: Page, title: string, type = 'login', extra: { password?: string; vault?: string; totp?: string } = {}) {
  await page.getByRole('button', { name: 'New item', exact: true }).click();
  if (type !== 'login') await page.getByLabel('Item type', { exact: true }).selectOption(type);
  if (extra.vault) await page.getByLabel('Vault', { exact: true }).selectOption({ label: extra.vault });
  await page.getByLabel('Title', { exact: true }).fill(title);
  await page.getByLabel('Username', { exact: true }).fill(email);
  await page.getByLabel('Password', { exact: true }).fill(extra.password ?? oldPassword);
  if (type === 'login') await page.getByLabel('Websites (one per line)').fill(title.includes('X Money') ? 'https://x.money' : 'https://example.test');
  if (extra.totp) await page.getByLabel('Authenticator secret or otpauth URL').fill(extra.totp);
  await page.getByLabel('Tags, separated by commas').fill('Fixture, Personal');
  await page.getByRole('button', { name: 'Save item', exact: true }).click();
  await page.getByRole('heading', { name: title, exact: true }).waitFor();
}
async function selectItem(page: Page, title: string) {
  await page.locator('.itemrow').filter({ has: page.getByText(title, { exact: true }) }).click();
  await page.getByRole('heading', { name: title, exact: true }).waitFor();
}
async function sidebar(page: Page, name: string) {
  await page.locator('.sidebar').getByRole('button', { name, exact: false }).click();
}
async function tool(port: number, token: string, name: string, args = {}) {
  const response = await fetch(`http://127.0.0.1:${port}/mcp`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
  return { status: response.status, body: await response.json() };
}
async function native(configFile: string, message: unknown, caller = `chrome-extension://${'a'.repeat(32)}/`) {
  const payload = Buffer.from(JSON.stringify(message)); const header = Buffer.alloc(4); header.writeUInt32LE(payload.length);
  const chunks: Buffer[] = [];
  await runNativeHost({ configFile, caller, input: Readable.from([Buffer.concat([header, payload])]), output: new Writable({ write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); } }) });
  const response = Buffer.concat(chunks); assert.ok(response.length >= 4);
  assert.equal(response.readUInt32LE(0), response.length - 4);
  return JSON.parse(response.subarray(4).toString('utf8'));
}

try {
  // Keep host desktop inactivity from making fixture timing depend on the human's mouse.
  // The sleep event itself is still exercised below on this isolated Electron process.
  const page = await running.firstWindow({ timeout: 15_000 }); page.setDefaultTimeout(15_000);
  page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('button', { name: 'Create JJ Vault' }).waitFor();
  await running.evaluate(({ powerMonitor, clipboard }) => {
    powerMonitor.getSystemIdleTime = () => 0;
    // The fixture does not interact with the human's system clipboard.
    let fixtureClipboard = 'Unrelated fixture clipboard';
    clipboard.readText = async () => fixtureClipboard;
    clipboard.writeText = async value => { fixtureClipboard = value; };
    clipboard.clear = () => { fixtureClipboard = ''; };
  });
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Confirm master password').fill(master);
  await page.getByRole('button', { name: 'Create JJ Vault' }).click();
  await page.getByRole('heading', { name: 'Your vault is ready.' }).waitFor();
  const secretKey = (await page.locator('.hint.secretkey').textContent())!.trim(); assert.match(secretKey, /^JJ1\./);
  const kitFile = path.join(data, 'Synthetic Emergency Kit.pdf');
  await running.evaluate(({ dialog }, filename) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: filename }); }, kitFile);
  await page.getByRole('button', { name: 'Save Emergency Kit PDF', exact: true }).click();
  await page.getByRole('heading', { name: 'Your vault is ready.' }).waitFor({ state: 'detached' });
  await skipPinSetup(page);
  const kit = await PDFDocument.load(await readFile(kitFile)); assert.equal(kit.getPageCount(), 1);
  const contents = kit.getPage(0).node.Contents();
  const streams = contents instanceof PDFArray ? contents.asArray().map(ref => kit.context.lookup(ref)).filter((stream): stream is PDFRawStream => stream instanceof PDFRawStream) : contents instanceof PDFRawStream ? [contents] : [];
  const commands = streams.map(stream => Buffer.from(decodePDFRawStream(stream).decode()).toString('latin1')).join('\n').toUpperCase();
  const encoded = (value: string) => Buffer.from(value, 'latin1').toString('hex').toUpperCase();
  assert.ok(commands.includes(encoded(secretKey)), 'Emergency Kit contains the actual Secret Key');
  assert.ok(!commands.includes(encoded(master)), 'Emergency Kit never contains the master password');
  await mkdir('output/qa', { recursive: true }); await atomicOwnerWrite('output/qa/synthetic-emergency-kit.pdf', await readFile(kitFile));
  await newItem(page, loginTitle, 'login', { totp: 'JBSWY3DPEHPK3PXP' });
  checkpoint('created synthetic vault and first login');
  const initialState = await bridge(page, 'state'); const login = initialState.items.find((item: any) => item.title === loginTitle);
  assert.equal(initialState.vaults.find((vault: any) => vault.id === login.vaultId).allowAssistant, false, 'Vault assistant availability starts paused');
  assert.match(await page.locator('#totpcode').innerText(), /^\d{6}$/);
  assert.equal(await page.getByText(oldPassword, { exact: true }).count(), 0, 'Password is masked until revealed');

  // Exercise editing, custom sections, history, search, and favorite behavior through the actual UI.
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  await page.getByLabel('Password', { exact: true }).fill(changedPassword);
  await page.getByRole('button', { name: 'Add field', exact: true }).click();
  await page.getByLabel('Field label', { exact: true }).fill('Recovery phrase');
  await page.getByLabel('Field value', { exact: true }).fill('Synthetic recovery phrase');
  await page.getByLabel('Field section', { exact: true }).fill('Account recovery');
  await page.getByLabel('Field type', { exact: true }).selectOption('password');
  await page.getByRole('button', { name: 'Save item', exact: true }).click();
  await page.getByText('Password history (1)', { exact: true }).click();
  await page.locator('.history').filter({ hasText: oldPassword }).waitFor();
  const edited = await bridge(page, 'item', { id: login.id });
  assert.equal(edited.password, changedPassword); assert.equal(edited.passwordHistory[0].password, oldPassword);
  assert.equal(edited.fields[0].section, 'Account recovery');
  const attachmentFile = path.join(data, 'synthetic-attachment.txt'); const attachmentText = 'Synthetic attachment content 27301';
  await atomicOwnerWrite(attachmentFile, attachmentText);
  await running.evaluate(({ dialog }, filename) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [filename] }); }, attachmentFile);
  await page.getByRole('button', { name: 'Attach a file', exact: true }).click();
  await page.getByText('synthetic-attachment.txt', { exact: true }).waitFor();
  assert.equal((await bridge(page, 'item', { id: login.id })).attachments[0].data, undefined, 'Attachment body is not exposed to renderer');
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  await page.getByLabel('Secure notes', { exact: true }).fill('Synthetic note after attachment');
  await page.getByRole('button', { name: 'Save item', exact: true }).click();
  await page.getByText('Synthetic note after attachment', { exact: true }).waitFor();
  const attachmentDownload = path.join(data, 'downloaded-attachment.txt');
  await running.evaluate(({ dialog }, filename) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: filename }); }, attachmentDownload);
  await page.getByRole('button', { name: 'Save file', exact: true }).click();
  await assert.doesNotReject(async () => {
    for (let attempt = 0; attempt < 40; attempt++) {
      try { assert.equal(await readFile(attachmentDownload, 'utf8'), attachmentText); return; }
      catch (error: any) { if (error.code !== 'ENOENT') throw error; await new Promise(resolve => setTimeout(resolve, 50)); }
    }
    throw new Error('Attachment download did not finish');
  });
  await page.locator('#favorite').click();
  await sidebar(page, 'Favorites'); await page.locator('.itemrow').filter({ hasText: loginTitle }).waitFor();
  await sidebar(page, 'All items');
  await page.getByLabel('Search items').fill('fixture@example.test');
  assert.equal(await page.locator('.itemrow').count(), 1);
  await page.getByLabel('Search items').fill('no match fixture'); assert.equal(await page.locator('.itemrow').count(), 0);
  await page.getByLabel('Search items').fill(''); await selectItem(page, loginTitle);
  checkpoint('editing, history, custom sections, favorites, and search passed');

  // The separate Agents regression covers creation UI. This owner fixture exercises
  // the real MCP server and owner controlled vault scopes without rendering a token.
  await sidebar(page, 'Settings');
  await page.getByRole('heading', { name: 'Settings & connections' }).waitFor();
  const backupFile = path.join(data, 'synthetic-backup.jjbackup');
  await running.evaluate(({ dialog }, filename) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath: filename }); }, backupFile);
  await page.getByRole('button', { name: 'Encrypted backup', exact: true }).click();
  await page.getByText('Encrypted backup saved', { exact: true }).waitFor();
  const backupRaw = await readFile(backupFile, 'utf8'); const backup = JSON.parse(backupRaw);
  assert.equal(backup.format, 'jjvault');
  for (const value of [master, secretKey, email, oldPassword, changedPassword, attachmentText]) assert.ok(!backupRaw.includes(value));
  const restored = await decryptData(backup, master, secretKey);
  assert.equal(restored.items.find(item => item.id === login.id)!.attachments[0].data, Buffer.from(attachmentText).toString('base64'));
  checkpoint('Emergency Kit, encrypted backup, and attachment preservation passed');
  const created = await bridge(page, 'createAgent', { name: 'Fixture agent', clientName: 'fixture_agent', permission: 'full', vaultIds: [] });
  const token = created.token; assert.match(token, /^jjv_/);
  assert.equal((await page.content()).includes(token), false);
  assert.equal((await stat(path.join(data, 'agent-tokens', 'fixture_agent'))).mode & 0o777, 0o600);
  const { servicePort: port } = await bridge(page, 'state'); assert.ok(port > 0);
  const agent = (await bridge(page, 'state')).tokens.find((entry: any) => entry.name === 'Fixture agent');
  assert.equal(agent.permission, 'full'); assert.deepEqual(agent.vaultIds, []);
  let response = await tool(port, token, 'list_logins'); assert.equal(response.status, 200); assert.deepEqual(JSON.parse(response.body.result.content[0].text), []);
  response = await tool(port, token, 'get_login', { name: loginTitle }); assert.equal(response.body.result.isError, true);
  await page.locator(`[data-vault="${login.vaultId}"][data-rule="allowAssistant"]`).check();
  await page.waitForFunction(async id => (await (window as any).vault.invoke('state')).vaults.find((vault: any) => vault.id === id).allowAssistant, login.vaultId);
  // Making a vault available does not silently expand an existing agent's scope.
  response = await tool(port, token, 'list_logins'); assert.deepEqual(JSON.parse(response.body.result.content[0].text), []);
  await bridge(page, 'updateAgent', { id: agent.id, changes: { vaultIds: [login.vaultId] } });
  await page.reload();
  await sidebar(page, 'All items'); await selectItem(page, loginTitle);
  await page.getByText('Agents assigned to this vault can use this login according to their permissions.', { exact: true }).waitFor();
  response = await tool(port, token, 'list_logins');
  assert.deepEqual(JSON.parse(response.body.result.content[0].text), [{ name: loginTitle, website: 'https://example.test', vault: 'Personal', tags: ['Fixture', 'Personal'] }]);
  response = await tool(port, token, 'get_login', { name: loginTitle });
  assert.equal(response.body.result.isError, undefined);
  const assistantLogin = JSON.parse(response.body.result.content[0].text);
  assert.equal(assistantLogin.password, changedPassword); assert.match(assistantLogin.totp, /^\d{6}$/);
  assert.deepEqual(Object.keys(assistantLogin).sort(), ['password', 'totp', 'username']);
  checkpoint('real MCP per agent permission and vault rules passed');

  await newItem(page, 'Fixture bank account', 'bankAccount');
  assert.equal((await bridge(page, 'state')).items.find((item: any) => item.title === 'Fixture bank account').allowAssistant, false);
  await newItem(page, 'X Money fixture account', 'login');
  assert.equal((await bridge(page, 'state')).items.find((item: any) => item.title === 'X Money fixture account').allowAssistant, false);
  for (const title of ['Fixture bank account', 'X Money fixture account']) {
    response = await tool(port, token, 'get_login', { name: title }); assert.equal(response.body.result.isError, true);
    assert.ok(!response.body.result.content[0].text.includes(oldPassword));
  }

  // Use a temporary native host config with real framing and the same unlocked desktop service.
  const hostConfig = path.join(data, 'fixture-browser-host.json');
  await atomicOwnerWrite(hostConfig, JSON.stringify({ port, browserTokenFile: path.join(data, 'browser-token'), chromeExtensionIds: ['a'.repeat(32)] }));
  await assert.rejects(native(hostConfig, { action: 'list', url: 'https://example.test/login' }, `chrome-extension://${'b'.repeat(32)}/`), /not paired/);
  const nativeList = await native(hostConfig, { action: 'list', url: 'https://example.test/login' });
  assert.equal(nativeList.ok, true); assert.ok(nativeList.result.some((item: any) => item.id === login.id));
  const nativeItem = await native(hostConfig, { action: 'get', id: login.id, url: 'https://example.test/login' });
  assert.equal(nativeItem.ok, true); assert.equal(nativeItem.result.password, changedPassword);
  assert.match(nativeItem.result.totp, /^\d{6}$/); assert.equal(nativeItem.result.passwordHistory, undefined);
  assert.equal(nativeItem.result.attachments, undefined);
  assert.ok(!JSON.stringify(nativeItem).includes('JBSWY3DPEHPK3PXP'));
  assert.equal((await native(hostConfig, { action: 'get', id: login.id, url: 'https://example.test.evil.test' })).ok, false);
  const nativeSaved = await native(hostConfig, { action: 'save', url: 'https://example.test/signup', item: { type: 'login', title: 'Browser captured fixture', username: email, password: 'Browser fixture password 712', urls: ['https://example.test/signup'] } });
  assert.equal(nativeSaved.ok, true);
  const capturedLogin = await bridge(page, 'item', { id: nativeSaved.result.id });
  assert.equal(capturedLogin.password, 'Browser fixture password 712');
  const browserAgent = (await bridge(page, 'state')).tokens.find((entry: any) => entry.id === agent.id);
  assert.deepEqual(browserAgent.vaultIds, [login.vaultId], 'Browser saves cannot change owner granted agent scope');
  assert.equal(browserAgent.permission, 'full');
  checkpoint('real native messaging framing, matching, and save passed');

  // Archive and trash remove access. Owner restore returns the item to its assigned vault rules.
  await sidebar(page, 'All items'); await selectItem(page, loginTitle);
  await page.getByRole('button', { name: 'Archive', exact: true }).click();
  await sidebar(page, 'Archive'); await selectItem(page, loginTitle);
  assert.equal((await tool(port, token, 'get_login', { name: loginTitle })).body.result.isError, true);
  await page.getByRole('button', { name: 'Unarchive', exact: true }).click();
  await sidebar(page, 'All items'); await selectItem(page, loginTitle);
  await page.getByRole('button', { name: 'Move to Recently deleted', exact: true }).click();
  await sidebar(page, 'Recently deleted'); await selectItem(page, loginTitle);
  assert.equal((await tool(port, token, 'get_login', { name: loginTitle })).body.result.isError, true);
  await page.getByRole('button', { name: 'Restore item', exact: true }).click();
  await page.getByRole('button', { name: 'Restore item', exact: true }).waitFor({ state: 'detached' });
  await page.getByText('Agents assigned to this vault can use this login according to their permissions.', { exact: true }).waitFor();
  response = await tool(port, token, 'get_login', { name: loginTitle });
  assert.equal(JSON.parse(response.body.result.content[0].text).password, changedPassword);

  await sidebar(page, 'Watchtower'); await page.getByRole('button', { name: 'Check vault', exact: true }).click();
  await page.locator('.issue').first().waitFor();
  await sidebar(page, 'Activity');
  await page.locator('.activity').filter({ hasText: 'assistant.get' }).first().waitFor();
  await sidebar(page, 'Agents');
  await page.getByTestId('agent-fixture_agent').getByRole('button', { name: 'Revoke', exact: true }).click();
  await page.getByTestId('agent-fixture_agent').getByText(/^revoked$/i).waitFor();
  assert.equal((await tool(port, token, 'list_logins')).status, 401);
  checkpoint('archive, trash, restore, activity, Watchtower, and revocation passed');

  await sidebar(page, 'All items'); await selectItem(page, loginTitle);
  await mkdir('output/qa', { recursive: true });
  await atomicOwnerWrite('output/qa/mac-vault.png', await page.screenshot());
  const passwordCopy = () => page.locator('.fieldrow').filter({ has: page.getByText('Password', { exact: true }) }).getByRole('button', { name: 'Copy', exact: true });
  await passwordCopy().click();
  assert.equal(await running.evaluate(({ clipboard }) => clipboard.readText()), changedPassword, 'Copy uses the asynchronous Electron clipboard API');
  await running.evaluate(({ clipboard }) => clipboard.writeText('Unrelated fixture clipboard'));
  await page.getByRole('button', { name: 'Lock', exact: true }).click();
  await page.getByRole('heading', { name: 'Unlock your vault' }).waitFor();
  assert.equal(await running.evaluate(({ clipboard }) => clipboard.readText()), 'Unrelated fixture clipboard', 'Lock preserves clipboard content copied elsewhere');
  for (const value of [oldPassword, changedPassword, email, 'Synthetic recovery phrase']) assert.ok(!(await page.locator('body').innerText()).includes(value));
  assert.equal((await native(hostConfig, { action: 'get', id: login.id, url: 'https://example.test/login' })).ok, false);
  const locked = await tool(port, token, 'list_logins'); assert.equal(locked.status, 423); assert.equal(locked.body.error, 'Vault is locked');
  await page.getByLabel('Master password', { exact: true }).fill('Wrong fixture master password');
  await page.getByLabel('Secret Key', { exact: true }).fill(secretKey);
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click();
  await page.locator('#autherror').filter({ hasText: /.+/ }).waitFor();
  assert.equal((await bridge(page, 'state')).locked, true);
  await page.getByLabel('Master password', { exact: true }).fill(master);
  await page.getByLabel('Secret Key', { exact: true }).fill(secretKey);
  await page.getByRole('button', { name: 'Unlock JJ Vault', exact: true }).click();
  await skipPinSetup(page);
  await page.locator('.itemrow').filter({ hasText: loginTitle }).waitFor();
  await selectItem(page, loginTitle);
  assert.equal((await bridge(page, 'item', { id: login.id })).password, changedPassword);
  await passwordCopy().click();
  assert.equal(await running.evaluate(({ clipboard }) => clipboard.readText()), changedPassword);
  await running.evaluate(({ powerMonitor }) => { powerMonitor.emit('suspend'); });
  await page.getByRole('heading', { name: 'Unlock your vault' }).waitFor();
  assert.equal((await bridge(page, 'state')).locked, true, 'Sleep event locks the app');
  assert.equal(await running.evaluate(({ clipboard }) => clipboard.readText()), '', 'Sleep clears only the managed vault copy');
  checkpoint('asynchronous clipboard copy, unrelated clipboard preservation, and managed copy clearing passed');

  const disk = await readFile(path.join(data, 'vault.json'), 'utf8');
  for (const value of [master, secretKey, oldPassword, changedPassword, email, token, 'Synthetic recovery phrase', 'Fixture agent']) assert.ok(!disk.includes(value), 'No plaintext secrets or token metadata on disk');
  assert.equal((await stat(path.join(data, 'vault.json'))).mode & 0o777, 0o600);
  assert.deepEqual(errors, [], 'No renderer errors');
  process.stdout.write('Desktop verification passed: create, edit, history, custom sections, search, favorites, TOTP, real MCP rules, bank and X Money exclusions, native host framing, archive, trash, restore, Watchtower, activity, token revocation, lock, failed unlock, successful unlock, and ciphertext permissions.\n');
} catch (error) {
  process.stderr.write(`Desktop check failed: ${error instanceof Error ? error.message : String(error)}\n`);
  throw error;
} finally {
  let timeout: NodeJS.Timeout | undefined;
  await Promise.race([running.close(), new Promise<void>(resolve => { timeout = setTimeout(() => { running.process().kill('SIGKILL'); resolve(); }, 5000); })]);
  if (timeout) clearTimeout(timeout);
  await rm(data, { recursive: true, force: true });
}


async function skipPinSetup(page: import('@playwright/test').Page) {
  const state = await page.evaluate(() => (window as any).vault.invoke('state'));
  if (state.pinAvailable && !state.pinEnabled) await page.getByRole('button', { name: 'Not now', exact: true }).click();
}
