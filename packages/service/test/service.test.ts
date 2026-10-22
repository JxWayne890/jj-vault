import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { request as httpRequest } from 'node:http';
import { VaultEngine, type Envelope, newItem } from '../../core/src/index.ts';
import { startLocalService } from '../src/local-service.ts';
import { startSyncServer } from '../src/sync-server.ts';
import { createShare, openShare, revokeShare, syncVault } from '../src/clients.ts';
import { randomToken, atomicOwnerWrite, readOwnerFile } from '../src/security.ts';
import { verifyBrowserCaller, runNativeHost } from '../src/native-host.ts';
import { runCli } from '../src/cli.ts';

async function fixture() {
  let envelope: Envelope | null = null;
  const engine = new VaultEngine({ read: async () => envelope && structuredClone(envelope), write: async e => { envelope = structuredClone(e); } });
  await engine.initialize('fictional master passphrase 742!');
  const vault = engine.data().vaults[0]; vault.allowAssistant = true;
  const login = await engine.upsertItem({ ...newItem('login', 'Example test', vault.id), username: 'fake@example.invalid', password: 'fictionalTestPassword13!', urls: ['https://example.invalid'], totp: 'JBSWY3DPEHPK3PXP', allowAssistant: true });
  const token = await engine.createToken('Test assistant');
  return { engine, login, token: token.token, envelope: () => structuredClone(envelope!) };
}
async function localFixture() { const f = await fixture(); const admin = randomToken(); const service = await startLocalService(f.engine, { port: 0, adminToken: admin }); return { ...f, admin, service, base: `http://127.0.0.1:${service.port}` }; }
function headers(token: string) { return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }; }
async function request(base: string, path: string, token: string, body: unknown, extra: Record<string, string> = {}) { return fetch(base + path, { method: 'POST', headers: { ...headers(token), ...extra }, body: JSON.stringify(body) }); }
async function tool(f: Awaited<ReturnType<typeof localFixture>>, name: string, args = {}) {
  const r = await request(f.base, '/mcp', f.token, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
  return { response: r, body: await r.json() };
}

test('MCP SDK handshake and tools reveal only explicitly allowed logins, never private history', async t => {
  const f = await localFixture(); t.after(() => f.service.close());
  const init = await request(f.base, '/mcp', f.token, { jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'JJ test', version: '1' } } });
  assert.equal(init.status, 200); assert.equal((await init.json()).result.serverInfo.name, 'JJ Vault');
  const list = await tool(f, 'list_logins'); assert.deepEqual(JSON.parse(list.body.result.content[0].text), [{ name: 'Example test', website: 'https://example.invalid', vault: f.engine.data().vaults[0].name, tags: [] }]);
  const result = await tool(f, 'get_login', { name: f.login.title });
  const login = JSON.parse(result.body.result.content[0].text);
  assert.equal(login.password, f.login.password); assert.match(login.totp, /^\d{6}$/); assert.deepEqual(Object.keys(login).sort(), ['password', 'totp', 'username']);
  assert(f.engine.data().activity.some(a => a.action === 'assistant.get'));
});

test('assistant token, browser token, admin token, origin, revocation and locked rules are enforced', async t => {
  const f = await localFixture(); t.after(() => f.service.close());
  assert.equal((await request(f.base, '/mcp', f.admin, {})).status, 401);
  assert.equal((await request(f.base, '/mcp', f.service.browserToken, {})).status, 401);
  assert.equal((await request(f.base, '/admin', f.token, { action: 'status' })).status, 401);
  assert.equal((await request(f.base, '/browser', f.admin, { action: 'list', url: 'https://example.invalid' })).status, 401);
  assert.equal((await request(f.base, '/mcp', f.token, {}, { Origin: 'https://malicious.invalid' })).status, 403);
  assert.equal((await request(f.base, '/admin', f.admin, { action: 'unlock', masterPassword: 'ignored' })).status, 400);
  await f.engine.revokeToken(f.engine.data().assistantTokens[0].id);
  assert.equal((await request(f.base, '/mcp', f.token, {})).status, 401);
  f.engine.lock(); const locked = await request(f.base, '/mcp', f.token, {}); assert.equal(locked.status, 423); assert.equal((await locked.json()).error, 'Vault is locked');
  assert.equal((await request(f.base, '/admin', f.admin, { action: 'status' })).status, 200);
});

test('MCP denies bank and X Money items, respects vault grants, and rate limits agents independently', async t => {
  const f = await localFixture(); t.after(() => f.service.close());
  const vaultId = f.login.vaultId;
  await f.engine.upsertItem({ ...newItem('bankAccount', 'Bank test', vaultId), password: 'fake bank', allowAssistant: true });
  await f.engine.upsertItem({ ...newItem('login', 'X Money test', vaultId), password: 'fake money', urls: ['https://x.money'], allowAssistant: true });
  const hidden = await f.engine.upsertItem({ ...newItem('login', 'Hidden test', vaultId), password: 'fake hidden', urls: [], allowAssistant: false });
  for (const name of ['Bank test', 'X Money test']) {
    const r = await tool(f, 'get_login', { name }); assert.equal(r.body.result.isError, true); assert(!r.body.result.content[0].text.includes('fake '));
  }
  f.engine.data().vaults[0].allowAssistant = false;
  assert.deepEqual(JSON.parse((await tool(f, 'list_logins')).body.result.content[0].text), []);
  f.engine.data().vaults[0].allowAssistant = true;
  for (let i = 0; i < 8; i++) assert.equal((await tool(f, 'get_login', { name: f.login.title })).body.result.isError, undefined);
  assert.match((await tool(f, 'get_login', { name: f.login.title })).body.result.content[0].text, /Rate limit/);
  const other = await f.engine.createToken('Second token'); f.token = other.token;
  assert.equal((await tool(f, 'get_login', { name: hidden.title })).body.result.isError, undefined);
});

test('browser matching, save and projection never return TOTP seed or password history', async t => {
  const f = await localFixture(); t.after(() => f.service.close());
  const browser = (body: unknown) => request(f.base, '/browser', f.service.browserToken, body);
  await f.engine.upsertItem({ ...f.login, fields: [{ id: 'unrelated', label: 'Recovery phrase', value: 'unshared words', kind: 'password' }] });
  const list = await (await browser({ action: 'list', url: 'https://example.invalid/login' })).json(); assert.equal(list.result[0].id, f.login.id);
  assert.deepEqual((await (await browser({ action: 'list', url: 'https://example.invalid.evil.invalid' })).json()).result, []);
  assert.equal((await browser({ action: 'get', id: f.login.id, url: 'http://example.invalid' })).status, 400);
  const item = (await (await browser({ action: 'get', id: f.login.id, url: 'https://example.invalid' })).json()).result;
  assert.match(item.totp, /^\d{6}$/); assert.deepEqual(item.fields, []); assert(!JSON.stringify(item).includes('unshared words')); assert.equal(item.passwordHistory, undefined); assert.equal(item.passkey, undefined); assert(!JSON.stringify(item).includes('JBSWY3DPEHPK3PXP'));
  const card = await f.engine.upsertItem({ ...newItem('creditCard', 'Fictional card', f.login.vaultId), password: 'unshared card password', fields: [{ id: 'card', label: 'Card number', value: '4111111111111111', kind: 'password' }, { id: 'other', label: 'Recovery phrase', value: 'unshared card phrase', kind: 'password' }] });
  const cardResult = (await (await browser({ action: 'get', id: card.id, url: 'https://example.invalid' })).json()).result; assert.equal(cardResult.fields.length, 1); assert.equal(cardResult.password, undefined); assert(!JSON.stringify(cardResult).includes('unshared card'));
  const saved = await (await browser({ action: 'save', url: 'https://new.invalid', item: { type: 'login', title: 'New fake', username: 'test', password: 'unreal', urls: ['https://new.invalid'] } })).json(); assert.equal(saved.ok, true);
  const fresh = f.engine.data().items.find(i => i.id === saved.result.id)!; assert.equal(fresh.allowAssistant, false);
  assert.equal((await browser({ action: 'save', url: 'https://evil.invalid', item: { ...fresh, id: f.login.id } })).status, 400);
  assert.equal((await browser({ action: 'save', url: 'https://new.invalid', item: { ...fresh, urls: ['https://evil.invalid'] } })).status, 400);
});

test('relay CAS persists ciphertext atomically and concurrent writers cannot lose a revision', async t => {
  const f = await fixture(); const dir = await mkdtemp(join(tmpdir(), 'jjrelay-')); const token = randomToken(); const file = join(dir, 'relay.json');
  let relay = await startSyncServer({ token, file, port: 0 }); t.after(() => relay.close());
  await assert.rejects(startSyncServer({ token, file, port: 0 }), /already locked/);
  const base = () => `http://127.0.0.1:${relay.port}`;
  const put = (expectedRevision: number) => fetch(base() + '/vault', { method: 'PUT', headers: headers(token), body: JSON.stringify({ expectedRevision, envelope: f.envelope() }) });
  assert.equal((await fetch(base() + '/vault')).status, 401);
  assert.equal((await put(0)).status, 200);
  const results = await Promise.all([put(1), put(1)]); assert.deepEqual(results.map(r => r.status).sort(), [200, 409]);
  const persisted = await readFile(file, 'utf8'); assert(!persisted.includes(f.login.password!)); assert.equal(JSON.parse(persisted).revision, 2);
  await relay.close(); relay = await startSyncServer({ token, file, port: 0 });
  assert.equal((await (await fetch(base() + '/vault', { headers: headers(token) })).json()).revision, 2);
  await assert.rejects(readOwnerFile(file + '.missing'));
  await chmod(file, 0o644); await assert.rejects(readOwnerFile(file), /0600/); await chmod(file, 0o600);
});

test('encrypted sync transports no assistant tokens and merges another paired device', async t => {
  const f = await fixture(); const dir = await mkdtemp(join(tmpdir(), 'jjsync-')); const token = randomToken();
  const relay = await startSyncServer({ token, file: join(dir, 'relay.json'), port: 0 }); t.after(() => relay.close());
  const options = { url: `http://127.0.0.1:${relay.port}`, token };
  await syncVault(f.engine, options);
  let remoteEnvelope = f.envelope(); const device = new VaultEngine({ read: async () => remoteEnvelope, write: async e => { remoteEnvelope = e; } }); await device.load(); await device.unlockWithKey(f.engine.exportSessionKey());
  await device.upsertItem({ ...newItem('secureNote', 'Paired note', device.data().vaults[0].id), notes: 'fictional note content' });
  await syncVault(device, options); await syncVault(f.engine, options);
  assert(f.engine.data().items.some(i => i.title === 'Paired note'));
  const wire = await (await fetch(options.url + '/vault', { headers: headers(token) })).json();
  assert(!JSON.stringify(wire).includes('fictional note'));
  const clean = new VaultEngine({ read: async () => wire.envelope, write: async () => {} }); await clean.unlockWithKey(f.engine.exportSessionKey()); assert.deepEqual(clean.data().assistantTokens, []);
});

test('shares encrypt independently, put key only in fragment, expire and revoke', async t => {
  const f = await fixture(); const dir = await mkdtemp(join(tmpdir(), 'jjshare-')); const token = randomToken(); let time = Date.now(); const file = join(dir, 'relay.json');
  const relay = await startSyncServer({ token, file, port: 0, now: () => time }); t.after(() => relay.close());
  const options = { url: `http://127.0.0.1:${relay.port}`, token, expiresAt: new Date(time + 10000).toISOString() };
  f.login.passwordHistory = [{ password: 'do not share past secret', changedAt: new Date().toISOString() }];
  f.login.attachments = [{ id: 'unshared', name: 'file', mime: 'text/plain', data: Buffer.from('unshared file').toString('base64') }];
  f.login.passkey = { credentialId: 'unshared', rpId: 'example.invalid', userHandle: 'user', userName: 'test', privateKey: 'unshared private key', publicKey: 'public', signCount: 0 };
  const link = await createShare(f.login, options); assert.equal(new URL(link.url).hash.length, 44);
  const shared = await openShare(link.url); assert.equal(shared.password, f.login.password); assert.deepEqual(shared.passwordHistory, []); assert.deepEqual(shared.attachments, []); assert.equal(shared.passkey, undefined);
  assert(!(await readFile(file, 'utf8')).includes(f.login.password!)); assert(!(await readFile(file, 'utf8')).includes(new URL(link.url).hash.slice(1)));
  await assert.rejects(openShare(link.url.slice(0, -1) + (link.url.endsWith('A') ? 'B' : 'A')));
  time += 20000; assert.equal((await fetch(options.url + '/share/' + link.id)).status, 404);
  time -= 20000; await revokeShare(link.id, options); await assert.rejects(openShare(link.url), /expired or revoked/);
});

test('native host validates caller IDs, owner only credentials, framing and scoped browser proxy', async t => {
  const f = await localFixture(); t.after(() => f.service.close()); const dir = await mkdtemp(join(tmpdir(), 'jjhost-'));
  const id = 'abcdefghijklmnopabcdefghijklmnop';
  assert.equal(verifyBrowserCaller(`chrome-extension://${id}/`, { chromeExtensionIds: [id] }), true);
  assert.equal(verifyBrowserCaller('chrome-extension://pppppppppppppppppppppppppppppppp/', { chromeExtensionIds: [id] }), false);
  assert.equal(verifyBrowserCaller(undefined, { firefoxExtensionIds: ['jjvault@john.local'] }), false);
  const tokenFile = join(dir, 'browser-token'); const configFile = join(dir, 'browser-host.json');
  await atomicOwnerWrite(tokenFile, f.service.browserToken); await atomicOwnerWrite(configFile, JSON.stringify({ chromeExtensionIds: [id], browserTokenFile: tokenFile, port: f.service.port }));
  const payload = Buffer.from(JSON.stringify({ action: 'list', url: 'https://example.invalid' })); const header = Buffer.alloc(4); header.writeUInt32LE(payload.length);
  const output: Buffer[] = [];
  await runNativeHost({ configFile, caller: `chrome-extension://${id}/`, input: Readable.from([header.subarray(0, 2), Buffer.concat([header.subarray(2), payload])]), output: new Writable({ write(chunk, _, callback) { output.push(Buffer.from(chunk)); callback(); } }) });
  const result = Buffer.concat(output); assert.equal(result.readUInt32LE(), result.length - 4); assert.equal(JSON.parse(result.subarray(4).toString()).result[0].title, f.login.title);
  await assert.rejects(runNativeHost({ configFile, caller: 'evil' }), /not paired/);
});

test('CLI gets one field using owner file auth, does not expose unlock API, backs up ciphertext', async t => {
  const f = await localFixture(); t.after(() => f.service.close()); const dir = await mkdtemp(join(tmpdir(), 'jjcli-')); const output: string[] = [];
  await atomicOwnerWrite(join(dir, 'admin-token'), f.admin); await atomicOwnerWrite(join(dir, 'vault.json'), JSON.stringify(f.envelope()));
  await runCli(['get', f.login.id, 'password'], { directory: dir, port: f.service.port, output: text => output.push(text) }); assert.deepEqual(output, [f.login.password]);
  await assert.rejects(runCli(['unlock', 'bad password'], { directory: dir }), /Unknown command/);
  const backup = join(dir, 'backup.jjvault'); await runCli(['backup', backup], { directory: dir, output: () => {} }); assert(!String(await readFile(backup)).includes(f.login.password!));
  await assert.rejects(runCli(['restore', backup], { directory: dir, port: f.service.port }), /Close the Mac app/);
});

test('Host validation and Travel Mode exclude unsafe vaults from browser, CLI and assistant access', async t => {
  const f = await localFixture(); t.after(() => f.service.close());
  const hostStatus = await new Promise<number>(resolve => { const req = httpRequest(f.base + '/admin', { method: 'POST', headers: { ...headers(f.admin), Host: 'attacker.invalid' } }, res => { res.resume(); resolve(res.statusCode!); }); req.end(JSON.stringify({ action: 'status' })); });
  assert.equal(hostStatus, 403);
  f.engine.data().settings.travelMode = true; await f.engine.save();
  assert.deepEqual((await (await request(f.base, '/browser', f.service.browserToken, { action: 'list', url: 'https://example.invalid' })).json()).result, []);
  assert.deepEqual((await (await request(f.base, '/admin', f.admin, { action: 'search', query: 'Example' })).json()).result, []);
  assert.deepEqual(JSON.parse((await tool(f, 'list_logins')).body.result.content[0].text), []);
  f.engine.data().vaults[0].travelSafe = true;
  assert.equal(JSON.parse((await tool(f, 'list_logins')).body.result.content[0].text).length, 1);
});

test('pending browser, CLI and assistant replies never return secrets after a concurrent lock', async t => {
  const f = await localFixture(); t.after(() => f.service.close());
  const record = f.engine.record.bind(f.engine);
  const lockAction = 'browser.fill';
  f.engine.record = async (...args: Parameters<VaultEngine['record']>) => { await record(...args); if (args[0] === lockAction) f.engine.lock(); };
  const browser = await request(f.base, '/browser', f.service.browserToken, { action: 'get', id: f.login.id, url: 'https://example.invalid' });
  assert.equal(browser.status, 423); assert(!JSON.stringify(await browser.json()).includes(f.login.password!));
  const cli = await localFixture(); t.after(() => cli.service.close()); const cliRecord = cli.engine.record.bind(cli.engine);
  cli.engine.record = async (...args: Parameters<VaultEngine['record']>) => { await cliRecord(...args); if (args[0] === 'cli.read') cli.engine.lock(); };
  const read = await request(cli.base, '/admin', cli.admin, { action: 'get', id: cli.login.id }); assert.equal(read.status, 423); assert(!JSON.stringify(await read.json()).includes(cli.login.password!));
  const assistant = await localFixture(); await assistant.service.close();
  assistant.engine.data().settings.notifyAssistant = true;
  assistant.service = await startLocalService(assistant.engine, { port: 0, adminToken: assistant.admin, notify: async () => { assistant.engine.lock(); } }); assistant.base = `http://127.0.0.1:${assistant.service.port}`; t.after(() => assistant.service.close());
  const response = await tool(assistant, 'get_login', { name: assistant.login.title }); assert.equal(response.body.result.isError, true); assert(!JSON.stringify(response.body).includes(assistant.login.password!));
});

test('a lock cancels biometric unlock queued behind an existing encrypted write', async () => {
  let envelope: Envelope | null = null; let pause = false; let resume!: () => void;
  const blocked = new Promise<void>(resolve => { resume = resolve; });
  const engine = new VaultEngine({ read: async () => envelope, write: async value => { if (pause) { pause = false; await blocked; } envelope = structuredClone(value); } });
  await engine.initialize('fictional biometric race password'); const key = engine.exportSessionKey();
  pause = true; const saving = engine.save(); const unlocking = engine.unlockWithKey(key); engine.lock();
  const rejected = assert.rejects(unlocking, /cancel|locked/i); resume(); await saving; await rejected; key.fill(0); assert.equal(engine.status().locked, true);
});

test('a lock during encrypted backup key derivation cancels restore and keeps the vault locked', async () => {
  let envelope: Envelope | null = null;
  const engine = new VaultEngine({ read: async () => envelope, write: async value => { envelope = value; } });
  const password = 'fictional restore race password'; const created = await engine.initialize(password); const exported = await engine.exportEncrypted();
  const restoring = engine.importEncrypted(exported, password, created.secretKey); engine.lock();
  await assert.rejects(restoring, /locked|cancel/i); assert.equal(engine.status().locked, true);
});

test('paired sync preserves local assistant policy, explicit restores and losing password history', async t => {
  const f = await fixture(); const dir = await mkdtemp(join(tmpdir(), 'jjsync-policy-')); const token = randomToken();
  const relay = await startSyncServer({ token, file: join(dir, 'relay.json'), port: 0 }); t.after(() => relay.close());
  const options = { url: `http://127.0.0.1:${relay.port}`, token };
  let pairedEnvelope = f.envelope(); const device = new VaultEngine({ read: async () => pairedEnvelope, write: async value => { pairedEnvelope = structuredClone(value); } });
  await device.unlockWithKey(f.engine.exportSessionKey()); device.data().items[0].allowAssistant = false; await device.save();
  for (let i = 0; i < 3; i++) { await syncVault(f.engine, options); await syncVault(device, options); }
  assert.equal(f.engine.data().items.length, 1); assert.equal(device.data().items.length, 1);
  assert.equal(f.engine.data().items[0].allowAssistant, true); assert.equal(device.data().items[0].allowAssistant, false);
  await f.engine.deleteItem(f.login.id); await syncVault(f.engine, options); await syncVault(device, options); assert(device.data().items[0].deletedAt);
  await device.restoreItem(f.login.id); await syncVault(device, options); await syncVault(f.engine, options); assert.equal(f.engine.data().items[0].deletedAt, undefined);
  const a = f.engine.data().items[0]; const b = device.data().items[0];
  await f.engine.upsertItem({ ...a, password: 'fictional newest version' });
  await device.upsertItem({ ...b, password: 'fictional other device version' }); device.data().items[0].updatedAt = '2020-01-01T00:00:00.000Z'; await device.save();
  await syncVault(device, options); await syncVault(f.engine, options);
  assert.equal(f.engine.data().items[0].password, 'fictional newest version'); assert(f.engine.data().items[0].passwordHistory.some(entry => entry.password === 'fictional other device version'));
});
