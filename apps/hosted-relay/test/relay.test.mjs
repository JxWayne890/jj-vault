import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes, webcrypto } from 'node:crypto';
import { createServer } from 'node:http';
import { createContext, runInContext } from 'node:vm';
import { createRelay } from '../src/relay.mjs';
import { MAX_JSON_BYTES, MAX_CIPHERTEXT_BYTES, readBoundedJson } from '../src/validation.mjs';
import { readConfig, createSupabaseStore } from '../src/store.mjs';
import { viewer } from '../src/viewer.mjs';
import { env, token, envelope, share, syntheticStore } from './fixtures.mjs';

function request(path, { method = 'GET', body, auth = token, headers = {} } = {}) {
  return new Request(`https://relay.example${path}`, { method,
    headers: { ...(auth ? { Authorization: `Bearer ${auth}` } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
    ...(body !== undefined ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}) });
}

test('private API requires the independent bearer and denies every browser origin', async () => {
  let calls = 0;
  const handler = createRelay({ env, store: { read: () => { calls += 1; } } });
  for (const path of ['/vault', '/status', '/share/' + 'a'.repeat(32)]) {
    for (const method of path.startsWith('/share') ? ['PUT', 'DELETE'] : ['GET', 'PUT']) {
      assert.equal((await handler(request(path, { method, auth: null }))).status, 401);
      assert.equal((await handler(request(path, { method, auth: randomBytes(32).toString('base64url') }))).status, 401);
      for (const origin of ['https://malicious.example', 'null', ''])
        assert.equal((await handler(request(path, { method, headers: { Origin: origin } }))).status, 403);
    }
  }
  assert.equal(calls, 0);
});

test('valid encrypted vault round trip, stale revisions and simultaneous writers', async () => {
  const handler = createRelay({ env, store: syntheticStore() });
  assert.deepEqual(await (await handler(request('/vault'))).json(), { revision: 0, envelope: null });
  const value = envelope();
  const writes = await Promise.all(Array.from({ length: 12 }, () => handler(request('/vault', { method: 'PUT', body: { expectedRevision: 0, envelope: value } }))));
  assert.equal(writes.filter(response => response.status === 200).length, 1);
  assert.equal(writes.filter(response => response.status === 409).length, 11);
  assert.deepEqual(await (await handler(request('/vault'))).json(), { revision: 1, envelope: value });
  assert.deepEqual(await (await handler(request('/status'))).json(), { revision: 1, vaultId: value.id,
    limits: { ciphertextBytes: MAX_CIPHERTEXT_BYTES, jsonBytes: MAX_JSON_BYTES } });
  const stale = await handler(request('/vault', { method: 'PUT', body: { expectedRevision: 0, envelope: envelope() } }));
  assert.deepEqual(await stale.json(), { error: 'Revision conflict', revision: 1 });
});

test('strict encrypted envelope shape, KDF and request validation before storage', async () => {
  let writes = 0;
  const handler = createRelay({ env, store: { write() { writes += 1; } } });
  const value = envelope();
  const bad = [null, [], {}, { ...value, plaintext: 'forbidden' }, { ...value, ciphertext: 'AA' },
    { ...value, iv: 'invalid' }, { ...value, id: '../escape' }, { ...value, format: null },
    { ...value, kdf: { ...value.kdf, algorithm: null } },
    { ...value, kdf: { ...value.kdf, memoryKiB: 65535 } },
    { ...value, kdf: { ...value.kdf, iterations: 2 } },
    { ...value, kdf: { ...value.kdf, parallelism: 2 } }];
  for (const candidate of bad) assert.equal((await handler(request('/vault', { method: 'PUT', body: { expectedRevision: 0, envelope: candidate } }))).status, 400);
  for (const revision of [-1, 1.5, '0', null, Number.MAX_SAFE_INTEGER])
    assert.equal((await handler(request('/vault', { method: 'PUT', body: { expectedRevision: revision, envelope: value } }))).status, 400);
  assert.equal((await handler(request('/vault', { method: 'PUT', body: '{' }))).status, 400);
  assert.equal((await handler(request('/vault', { method: 'PUT', body: {}, headers: { 'Content-Type': 'text/plain' } }))).status, 415);
  assert.equal(writes, 0);
});

test('payload limits apply to declared lengths, streams and encrypted ciphertext', async () => {
  const handler = createRelay({ env, store: syntheticStore() });
  assert.equal((await handler(request('/vault', { method: 'PUT', body: {}, headers: { 'Content-Length': String(MAX_JSON_BYTES + 1) } }))).status, 413);
  assert.equal((await handler(request('/vault', { method: 'PUT', body: ' '.repeat(MAX_JSON_BYTES + 1) }))).status, 413);
  const value = envelope(); value.ciphertext = Buffer.alloc(MAX_CIPHERTEXT_BYTES + 1).toString('base64');
  assert.equal((await handler(request('/vault', { method: 'PUT', body: { expectedRevision: 0, envelope: value } }))).status, 413);
  // Reject an actual oversized upstream stream before JSON parse or serialization.
  await assert.rejects(readBoundedJson(new Response(' '.repeat(MAX_JSON_BYTES + 1))), { status: 413 });
});

test('storage failures and corrupt responses never leak upstream details or report success', async () => {
  const secret = env.SUPABASE_SERVICE_ROLE_KEY + ' synthetic private SQL';
  const handler = createRelay({ env, store: { write: async () => { throw Error(secret); }, read: async () => ({ revision: 0, envelope: { secret } }) } });
  for (const req of [request('/vault'), request('/vault', { method: 'PUT', body: { expectedRevision: 0, envelope: envelope() } })]) {
    const response = await handler(req); assert.equal(response.status, 503);
    assert.equal(await response.text(), '{"error":"Relay unavailable"}');
  }
  const result = await createRelay({ env: { ...env, JJ_VAULT_RELAY_TOKEN: 'weak' } })(request('/vault'));
  assert.equal(result.status, 503);
  assert.equal((await result.text()).includes(secret), false);
});

test('encrypted shares support create, duplicate rejection, public retrieval, expiry and revocation', async () => {
  let time = Date.now();
  const handler = createRelay({ env, store: syntheticStore(), now: () => time });
  const id = randomBytes(24).toString('base64url'); const value = share();
  assert.equal((await handler(request('/share/' + id, { auth: null }))).status, 404);
  assert.equal((await handler(request('/share/' + id, { method: 'PUT', body: value }))).status, 201);
  assert.equal((await handler(request('/share/' + id, { method: 'PUT', body: value }))).status, 409);
  const response = await handler(request('/share/' + id, { auth: null }));
  assert.deepEqual(await response.json(), value);
  const view = await handler(request('/s/' + id, { auth: null }));
  assert.equal(view.status, 200); assert.match(view.headers.get('content-security-policy'), /sha256-/);
  assert.match(await view.text(), /location.hash.slice/);
  time = Date.parse(value.expiresAt) + 1;
  assert.equal((await handler(request('/share/' + id, { auth: null }))).status, 404);
  time = Date.now();
  assert.equal((await handler(request('/share/' + id, { method: 'DELETE' }))).status, 200);
  assert.equal((await handler(request('/share/' + id, { auth: null }))).status, 404);
});

test('share ciphertext interoperates with current AES GCM format and browser decryption', async () => {
  const key = randomBytes(32); const id = randomBytes(24).toString('base64url'); const iv = randomBytes(12);
  const item = { title: 'Synthetic item', fields: [{ name: 'username', value: 'synthetic' }] };
  const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from('JJVaultShare:v1:' + id));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(item)), cipher.final(), cipher.getAuthTag()]);
  const handler = createRelay({ env, store: syntheticStore() });
  const value = { version: 1, iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64'), expiresAt: share().expiresAt };
  assert.equal((await handler(request('/share/' + id, { method: 'PUT', body: value }))).status, 201);
  const remote = await (await handler(request('/share/' + id, { auth: null }))).json();
  const webKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const plain = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(remote.iv, 'base64'), additionalData: Buffer.from('JJVaultShare:v1:' + id) }, webKey, Buffer.from(remote.ciphertext, 'base64'));
  assert.deepEqual(JSON.parse(Buffer.from(plain).toString()), item);
});

test('share viewer retries after transient failure without restoring or sending the fragment key', async () => {
  const key = randomBytes(32); const id = randomBytes(24).toString('base64url'); const iv = randomBytes(12);
  const keyText = key.toString('base64url');
  const item = { title: 'Synthetic retry fixture' };
  const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from('JJVaultShare:v1:' + id));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(item)), cipher.final(), cipher.getAuthTag()]);
  const value = { version: 1, iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64'), expiresAt: share().expiresAt };
  const nodes = { open: { hidden: false, disabled: false }, item: { hidden: true, textContent: '' }, status: { textContent: '' } };
  const location = { hash: '#' + keyText, pathname: '/s/' + id };
  let requests = 0; let finishFirst;
  const firstRequest = new Promise(resolve => { finishFirst = resolve; });
  const urls = [];
  const context = createContext({
    document: { getElementById: id => nodes[id] }, location,
    history: { replaceState: () => { location.hash = ''; } },
    crypto: webcrypto, Uint8Array, TextEncoder, TextDecoder, atob,
    fetch: async url => {
      urls.push(url); requests += 1;
      if (requests === 1) { await firstRequest; return new Response('', { status: 503 }); }
      return Response.json(value);
    }
  });
  runInContext(viewer.match(/<script>([\s\S]*)<\/script>/)[1], context);
  const first = nodes.open.onclick();
  assert.equal(nodes.open.disabled, true);
  await nodes.open.onclick(); assert.equal(requests, 1);
  finishFirst(); await first;
  assert.equal(location.hash, ''); assert.match(nodes.status.textContent, /Try again/);
  assert.equal(nodes.open.disabled, false); assert.equal(nodes.open.hidden, false);
  await nodes.open.onclick();
  assert.equal(requests, 2); assert.equal(location.hash, '');
  assert.deepEqual(JSON.parse(nodes.item.textContent), item);
  assert.equal(nodes.item.hidden, false); assert.equal(nodes.open.hidden, true);
  assert.equal(runInContext('shareKeyText', context), '');
  assert.ok(urls.every(url => !url.includes(keyText)));
});

test('configuration rejects arbitrary origins and weak tokens', () => {
  assert.equal(readConfig(env).url.origin, env.SUPABASE_URL);
  for (const url of ['http://abcdefghijklmnopqrst.supabase.co', 'https://attacker.example', 'https://abcdefghijklmnopqrst.supabase.co/extra', 'https://user:pass@abcdefghijklmnopqrst.supabase.co', 'https://abcdefghijklmnopqrst.supabase.co?token=secret', 'https://abcdefghijklmnopqrst.supabase.co:444', 'https://abcdefghijklmnopqrst.supabase.co#fragment'])
    assert.throws(() => readConfig({ ...env, SUPABASE_URL: url }), /configuration unavailable/);
  for (const weak of ['', 'a'.repeat(43), 'short', randomBytes(31).toString('base64url')])
    assert.throws(() => readConfig({ ...env, JJ_VAULT_RELAY_TOKEN: weak }), /configuration unavailable/);
  assert.throws(() => readConfig({ ...env, SUPABASE_SERVICE_ROLE_KEY: 'anon' }), /configuration unavailable/);
});

test('Supabase adapter uses service credentials only upstream, bounded response and no redirects', async () => {
  let captured;
  const store = createSupabaseStore(readConfig(env), async (url, options) => {
    captured = { url, options }; return Response.json({ revision: 0, envelope: null });
  });
  assert.deepEqual(await store.read(), { revision: 0, envelope: null });
  assert.equal(captured.url.href, env.SUPABASE_URL + '/rest/v1/rpc/jj_relay_read');
  assert.equal(captured.options.headers.apikey, env.SUPABASE_SERVICE_ROLE_KEY);
  assert.equal(captured.options.headers.Authorization, undefined);
  assert.equal(captured.options.redirect, 'error'); assert.equal(captured.options.cache, 'no-store');
  assert.equal(captured.options.body.includes(token), false);
  const broken = createSupabaseStore(readConfig(env), async () => new Response('upstream service key and SQL error', { status: 500 }));
  await assert.rejects(broken.read(), /Storage unavailable/);
  const huge = createSupabaseStore(readConfig(env), async () => new Response(' '.repeat(MAX_JSON_BYTES + 1)));
  await assert.rejects(huge.read(), /Storage unavailable/);
});

test('HTTP server exercises the Web Request function with actual network requests', async t => {
  const handler = createRelay({ env, store: syntheticStore() });
  const server = createServer(async (incoming, outgoing) => {
    try {
      const body = []; for await (const chunk of incoming) body.push(chunk);
      const request = new Request('http://127.0.0.1' + incoming.url, { method: incoming.method, headers: incoming.headers,
        ...(['GET', 'HEAD'].includes(incoming.method) ? {} : { body: Buffer.concat(body) }) });
      const response = await handler(request); outgoing.writeHead(response.status, Object.fromEntries(response.headers)); outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch { outgoing.writeHead(500); outgoing.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(url + '/vault')).status, 401);
  const written = await fetch(url + '/vault', { method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ expectedRevision: 0, envelope: envelope() }) });
  assert.equal(written.status, 200);
  const response = await fetch(url + '/status', { headers: { Authorization: `Bearer ${token}` } });
  const status = await response.json();
  assert.equal(status.revision, 1);
  assert.deepEqual(status.limits, { ciphertextBytes: MAX_CIPHERTEXT_BYTES, jsonBytes: MAX_JSON_BYTES });
  for (const name of ['cache-control', 'cdn-cache-control', 'vercel-cdn-cache-control']) assert.match(response.headers.get(name), /no-store/);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal((await fetch(url + '/pair', { method: 'POST', headers: { Authorization: `Bearer ${token}` } })).status, 404);
});
