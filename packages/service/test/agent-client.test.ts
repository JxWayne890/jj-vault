import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, mkdir, symlink, writeFile, link, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Readable } from 'node:stream';
import { spawn } from 'node:child_process';
import { VaultEngine, newItem, type Envelope } from '../../core/src/index.ts';
import { startLocalService } from '../src/local-service.ts';
import { randomToken, atomicOwnerWrite } from '../src/security.ts';
import { AGENT_TOOLS, readAgentToken, runAgentClient } from '../src/agent-client.ts';

async function fixture() {
  let envelope: Envelope | null = null;
  const engine = new VaultEngine({ read: async () => envelope, write: async next => { envelope = structuredClone(next); } });
  await engine.initialize('fictional agent helper master password');
  const vault = engine.data().vaults[0]; vault.allowAssistant = true;
  const login = await engine.upsertItem({ ...newItem('login', 'Allowed synthetic login', vault.id), username: 'synthetic@example.invalid', password: 'synthetic helper password', urls: ['https://example.invalid'], totp: 'JBSWY3DPEHPK3PXP', allowAssistant: true });
  await engine.upsertItem({ ...newItem('login', 'Hidden synthetic login', vault.id), username: 'hidden@example.invalid', password: 'do not expose', urls: ['https://hidden.invalid'], allowAssistant: false });
  await engine.upsertItem({ ...newItem('bankAccount', 'Synthetic bank', vault.id), password: 'do not expose bank', allowAssistant: true });
  await engine.upsertItem({ ...newItem('login', 'X Money', vault.id), password: 'do not expose money', urls: ['https://x.money'], allowAssistant: true });
  const token = await engine.createToken('Synthetic codex');
  const directory = await mkdtemp(join(tmpdir(), 'jj-agent-helper-')); await chmod(directory, 0o700);
  await atomicOwnerWrite(join(directory, 'codex'), token.token);
  const service = await startLocalService(engine, { adminToken: randomToken(), port: 0 });
  const output: string[] = [];
  const run = async (...args: string[]) => { output.length = 0; await runAgentClient(args, { directory, port: service.port, output: text => output.push(text) }); return output; };
  const stdin = async (command: string, value: unknown, client = 'codex') => { output.length = 0; await runAgentClient([command, client], { directory, port: service.port, input: Readable.from([JSON.stringify(value)]), output: text => output.push(text) }); return output; };
  return { engine, login, token, directory, service, run, stdin, output };
}

test('assistant helper checks MCP tools without reading or listing credentials and emits only explicit headers', async t => {
  const f = await fixture(); t.after(() => f.service.close());
  const activity = f.engine.data().activity.filter(entry => entry.action.startsWith('assistant.')).length;
  const result = JSON.parse((await f.run('check', 'codex'))[0]);
  assert.deepEqual(result, { connected: true, client: 'codex', endpoint: `http://127.0.0.1:${f.service.port}/mcp`, tools: AGENT_TOOLS });
  assert.equal(f.engine.data().activity.filter(entry => entry.action.startsWith('assistant.')).length, activity);
  assert(!JSON.stringify(result).includes(f.login.title)); assert(!JSON.stringify(result).includes(f.login.password!));
  assert.deepEqual(JSON.parse((await f.run('headers', 'codex'))[0]), { Authorization: `Bearer ${f.token.token}` });
});

test('assistant helper uses only permitted MCP list and get projections and obeys vault and item allow rules', async t => {
  const f = await fixture(); t.after(() => f.service.close());
  assert.deepEqual(JSON.parse((await f.run('list', 'codex'))[0]), [{ name: f.login.title, website: 'https://example.invalid', vault: f.engine.data().vaults[0].name, tags: [] }, { name: 'Hidden synthetic login', website: 'https://hidden.invalid', vault: f.engine.data().vaults[0].name, tags: [] }]);
  const credentials = JSON.parse((await f.run('get', 'codex', f.login.title))[0]);
  assert.equal(credentials.username, f.login.username); assert.equal(credentials.password, f.login.password); assert.match(credentials.totp, /^\d{6}$/);
  assert.deepEqual(Object.keys(credentials).sort(), ['password', 'totp', 'username']);
  // The server intentionally sanitizes its internal "Allowed login not found"
  // error to "Request failed". Assert rejection and no credential output.
  for (const name of ['Synthetic bank', 'X Money']) {
    await assert.rejects(f.run('get', 'codex', name), /^Error: Login not found or not allowed$/); assert.deepEqual(f.output, []);
  }
  f.engine.data().vaults[0].allowAssistant = false;
  assert.deepEqual(JSON.parse((await f.run('list', 'codex'))[0]), []);
  await assert.rejects(f.run('get', 'codex', f.login.title), /^Error: Login not found or not allowed$/); assert.deepEqual(f.output, []);
});

test('assistant helper never echoes sensitive text in MCP tool errors', async t => {
  const f = await fixture(); t.after(() => f.service.close());
  f.engine.getAssistantLogin = async () => { throw new Error('Not allowed: synthetic confidential error suffix'); };
  await assert.rejects(f.run('get', 'codex', f.login.title), /^Error: Login not found or not allowed$/); assert.deepEqual(f.output, []);
  f.engine.getAssistantLogin = async () => { throw new Error('Unexpected failure: synthetic confidential error suffix'); };
  await assert.rejects(f.run('get', 'codex', f.login.title), /^Error: JJ Vault request failed$/); assert.deepEqual(f.output, []);
});

test('assistant helper refuses revoked and invalid tokens, returns exact locked error, and never falls back to admin auth', async t => {
  const f = await fixture(); t.after(() => f.service.close());
  await f.engine.revokeToken(f.engine.data().assistantTokens[0].id);
  await assert.rejects(f.run('check', 'codex'), /^Error: JJ Vault agent token is invalid or revoked$/); assert.deepEqual(f.output, []);
  await atomicOwnerWrite(join(f.directory, 'admin-token'), randomToken());
  await assert.rejects(f.run('check', 'dots'), /Agent token unavailable/);
  await atomicOwnerWrite(join(f.directory, 'dots'), randomToken());
  await assert.rejects(f.run('check', 'dots'), /invalid or revoked/);
  f.engine.lock();
  await assert.rejects(f.run('check', 'codex'), /^Error: Vault is locked$/);
  await assert.rejects(f.run('get', 'codex', f.login.title), /^Error: Vault is locked$/); assert.deepEqual(f.output, []);
});

test('assistant helper token reader rejects symlinks, broad permissions, malformed bytes and oversized files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'jj-agent-token-')); await chmod(directory, 0o700);
  const token = randomToken(); const path = join(directory, 'codex');
  await atomicOwnerWrite(path, token); assert.equal(await readAgentToken('codex', { directory }), token);
  await chmod(path, 0o644); await assert.rejects(readAgentToken('codex', { directory }), /0600/); await chmod(path, 0o600);
  await chmod(path, 0o400); await assert.rejects(readAgentToken('codex', { directory }), /0600/); await chmod(path, 0o600);
  await chmod(directory, 0o750); await assert.rejects(readAgentToken('codex', { directory }), /0700/); await chmod(directory, 0o700);
  await symlink(path, join(directory, 'dots')); await assert.rejects(readAgentToken('dots', { directory }), /Agent token unavailable/);
  const linkDirectory = join(directory, 'linked'); await symlink(directory, linkDirectory); await assert.rejects(readAgentToken('codex', { directory: linkDirectory }), /Agent token unavailable/);
  for (const value of ['x'.repeat(1025), token + '\nAuthorization: injected', token.slice(1) + '\u00ff']) {
    await writeFile(path, value, { mode: 0o600 }); await assert.rejects(readAgentToken('codex', { directory }), /Agent token unavailable/);
  }
  await mkdir(join(directory, 'grok'), { mode: 0o700 }); await assert.rejects(readAgentToken('grok', { directory }), /Agent token unavailable/);
});

test('assistant helper rejects unknown clients, traversal, extra arguments and nonloopback port values before token access', async () => {
  const directory = '/nonexistent-synthetic-helper-directory';
  for (const client of ['admin', 'owner', 'cli', 'browser', 'provider', '../admin-token', '', 'Codex', 'grok/../../owner', 'grok\u0000']) await assert.rejects(runAgentClient(['headers', client], { directory }), /Invalid agent client name/);
  await assert.rejects(runAgentClient(['unlock', 'codex'], { directory }), /Usage/);
  await assert.rejects(runAgentClient(['get', 'codex'], { directory }), /Usage/);
  await assert.rejects(runAgentClient(['list', 'codex', 'unexpected'], { directory }), /Usage/);
  for (const port of [0, -1, 65536, NaN, 17373.5]) await assert.rejects(runAgentClient(['headers', 'codex'], { directory, port }), /Invalid local port/);
});


test('assistant helper accepts registered arbitrary clients and sends writes only through bounded stdin', async t => {
  const f = await fixture(); t.after(() => f.service.close());
  const token = await f.engine.createToken('Grok eighteen', { clientName: 'grok18', permission: 'full', vaultIds: [f.login.vaultId] });
  await atomicOwnerWrite(join(f.directory, 'grok18'), token.token);
  assert.equal(JSON.parse((await f.run('check', 'grok18'))[0]).client, 'grok18');
  const input = { vault: f.engine.data().vaults[0].name, name: 'Added through stdin', website: 'https://added.invalid', username: 'example', notes: 'private synthetic note', totp_secret: 'JBSWY3DPEHPK3PXP', tags: ['test'] };
  const added = JSON.parse((await f.stdin('add', input, 'grok18'))[0]);
  assert.deepEqual(added, { name: input.name, website: input.website, vault: input.vault, tags: ['test'] });
  const stored = f.engine.data().items.find(item => item.title === input.name)!;
  assert(stored.password && stored.password.length >= 24); assert(!JSON.stringify(added).includes(stored.password!)); assert(!JSON.stringify(added).includes(input.notes));
  await f.stdin('update', { name: input.name, fields: { password: 'fictional new password', name: 'Renamed through stdin' } }, 'grok18');
  assert.equal(f.engine.data().items.find(item => item.id === stored.id)!.passwordHistory.some(entry => entry.password === stored.password), true);
  const searched = JSON.parse((await f.run('search', 'grok18', 'Renamed'))[0]); assert.deepEqual(searched, [{ name: 'Renamed through stdin', website: input.website }]);
  const generated = JSON.parse((await f.stdin('generate', { length: 38, options: { symbols: true } }, 'grok18'))[0]); assert.equal(generated.password.length, 38);
  const deleted = JSON.parse((await f.run('delete', 'grok18', 'Renamed through stdin'))[0]); assert.equal(deleted.deleted, true); assert(Number.isFinite(Date.parse(deleted.restoreUntil)));
  assert.deepEqual(JSON.parse((await f.run('search', 'grok18', 'Renamed'))[0]), []);
});

test('stdin commands reject secrets as arguments, oversized or invalid JSON and permission or token fields', async () => {
  const directory = '/nonexistent-synthetic-helper-directory';
  for (const command of ['add','update','generate']) await assert.rejects(runAgentClient([command,'grok18','sensitive-argument'], { directory }), /Usage/);
  const input = (value: string) => Readable.from([value]);
  for (const text of ['bad sensitive JSON', '[]', '"secret"', ' '.repeat(128 * 1024 + 1)]) await assert.rejects(runAgentClient(['add','grok18'], { directory, input: input(text) }), /^Error: Invalid stdin JSON/);
  for (const value of [{ vault:'Personal',name:'test',website:'https://example.invalid',username:'x',permission:'full' },{ token:'synthetic secret' },{ name:'test', fields:{allowAssistant:true} }]) {
    await assert.rejects(runAgentClient([value.fields ? 'update' : 'add','grok18'], { directory, input: input(JSON.stringify(value)) }), /^Error: Invalid stdin fields$/);
  }
});

test('helper rejects hardlinked token files and never emits confidential server errors', async t => {
  const f = await fixture(); t.after(() => f.service.close());
  await link(join(f.directory,'codex'),join(f.directory,'grok18')); await assert.rejects(readAgentToken('grok18',{directory:f.directory}), /Agent token unavailable/); await unlink(join(f.directory,'grok18'));
  f.engine.addAssistantLogin = async () => { throw new Error('secret error body fictional confidential password'); };
  await assert.rejects(f.stdin('add',{vault:'Personal',name:'test',website:'https://example.invalid',username:'x'}), /^Error: JJ Vault request failed$/); assert.deepEqual(f.output,[]);
});

test('actual helper process rejects argument payloads without echoing them', async () => {
  const result = await new Promise<{code:number|null;stdout:string;stderr:string}>((resolve,reject) => {
    const child=spawn(process.execPath,['--import','tsx','packages/service/src/agent-client.ts','add','grok18','fictional secret payload'],{cwd:process.cwd(),stdio:['pipe','pipe','pipe']});
    let stdout='',stderr='';child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));child.stdin.end();
  });
  assert.equal(result.code,1);assert.equal(result.stdout,'');assert.match(result.stderr,/Usage/);assert(!result.stderr.includes('fictional secret payload'));
});
