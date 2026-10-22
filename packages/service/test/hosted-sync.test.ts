import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { VaultEngine, decryptData, newItem, type Envelope } from '../../core/src/index.ts';
import { syncVault } from '../src/clients.ts';

// Load the optional plain JavaScript package without adding it to desktop builds.
const { createRelay } = await import(new URL('../../../apps/hosted-relay/src/relay.mjs', import.meta.url).href);
const { env, token, syntheticStore } = await import(new URL('../../../apps/hosted-relay/test/fixtures.mjs', import.meta.url).href);
const masterPassword = 'Synthetic hosted sync integration master password';

async function localVault(t: TestContext, initial?: Envelope, secretKey?: string) {
  let disk: Envelope | null = initial ? structuredClone(initial) : null;
  let writes = 0;
  const engine = new VaultEngine({
    read: async () => disk && structuredClone(disk),
    write: async value => { disk = structuredClone(value); writes += 1; }
  });
  if (initial) {
    assert.ok(secretKey);
    await engine.load();
    await engine.unlock(masterPassword, secretKey);
  } else {
    ({ secretKey } = await engine.initialize(masterPassword));
  }
  t.after(() => engine.lock());
  return { engine, secretKey: secretKey!, disk: () => structuredClone(disk!), writes: () => writes };
}

async function relayHttp(t: TestContext, options: { initial?: Envelope; limits?: unknown } = {}) {
  const store = syntheticStore();
  if (options.initial) assert.equal((await store.write(0, options.initial)).ok, true);
  let writes = 0;
  let statusOverride = options.limits;
  const originalWrite = store.write;
  store.write = async (...args: unknown[]) => { writes += 1; return originalWrite(...args); };
  const handle = createRelay({ env, store });
  const requests: { method: string; path: string; body: string }[] = [];
  const serverErrors: unknown[] = [];
  const server = createServer(async (incoming, outgoing) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
      const body = Buffer.concat(chunks);
      const method = incoming.method || 'GET';
      const path = incoming.url || '/';
      requests.push({ method, path, body: body.toString('utf8') });
      const request = new Request(`http://127.0.0.1${path}`, {
        method, headers: incoming.headers as Record<string, string>,
        ...(['GET', 'HEAD'].includes(method) ? {} : { body })
      });
      let response: Response = await handle(request);
      if (method === 'GET' && path === '/status' && statusOverride !== undefined && response.ok) {
        const status = await response.json();
        response = new Response(JSON.stringify({ ...status, limits: statusOverride }), {
          status: response.status, headers: response.headers
        });
      }
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      serverErrors.push(error);
      outgoing.writeHead(500); outgoing.end();
    }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  t.after(async () => {
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    assert.deepEqual(serverErrors, []);
  });
  return {
    options: { url: `http://127.0.0.1:${address.port}`, token }, store, requests,
    writes: () => writes,
    setLimits: (limits: unknown) => { statusOverride = limits; }
  };
}

test('current sync client exchanges actual encrypted vaults through the hosted HTTP handler', async t => {
  const first = await localVault(t);
  const second = await localVault(t, first.disk(), first.secretKey);
  const relay = await relayHttp(t);
  const firstPassword = 'Synthetic first device hosted credential';
  const secondPassword = 'Synthetic second device hosted credential';
  const firstItem = await first.engine.upsertItem({
    ...newItem('login', 'Hosted first device', first.engine.data().vaults[0].id), password: firstPassword
  });
  assert.deepEqual(await syncVault(first.engine, relay.options), { revision: 1 });
  assert.deepEqual(await syncVault(second.engine, relay.options), { revision: 2 });
  assert.equal(second.engine.data().items.find(item => item.id === firstItem.id)?.password, firstPassword);
  const secondItem = await second.engine.upsertItem({
    ...newItem('login', 'Hosted second device', second.engine.data().vaults[0].id), password: secondPassword
  });
  assert.deepEqual(await syncVault(second.engine, relay.options), { revision: 3 });
  assert.deepEqual(await syncVault(first.engine, relay.options), { revision: 4 });
  assert.equal(first.engine.data().items.find(item => item.id === secondItem.id)?.password, secondPassword);
  const stored = await relay.store.read();
  const decrypted = await decryptData(stored.envelope, masterPassword, first.secretKey);
  assert.deepEqual(new Set(decrypted.items.map(item => item.id)), new Set([firstItem.id, secondItem.id]));
  assert.deepEqual(decrypted.assistantTokens, []);
  assert.deepEqual(decrypted.activity, []);
  assert.equal(relay.writes(), 4);
  assert.deepEqual(relay.requests.map(({ method, path }) => `${method} ${path}`),
    Array.from({ length: 4 }, () => ['GET /status', 'GET /vault', 'PUT /vault']).flat());
  for (const request of relay.requests.filter(value => value.method === 'PUT')) {
    assert.equal(request.body.includes(firstPassword), false);
    assert.equal(request.body.includes(secondPassword), false);
    assert.equal(request.body.includes(masterPassword), false);
    assert.equal(request.body.includes(first.secretKey), false);
  }
});

test('hosted limits reject an oversized local snapshot before vault retrieval or any write', async t => {
  const local = await localVault(t);
  await local.engine.upsertItem({
    ...newItem('secureNote', 'Synthetic oversized local note', local.engine.data().vaults[0].id), notes: 'x'.repeat(16000)
  });
  const beforeData = structuredClone(local.engine.data());
  const beforeDisk = local.disk();
  const beforeWrites = local.writes();
  const relay = await relayHttp(t);
  for (const limits of [
    { ciphertextBytes: 8192, jsonBytes: 32768 },
    { ciphertextBytes: 65536, jsonBytes: 8192 }
  ]) {
    relay.setLimits(limits); relay.requests.length = 0;
    await assert.rejects(syncVault(local.engine, relay.options), /Vault exceeds this sync service size limit/);
    assert.deepEqual(relay.requests.map(({ method, path }) => `${method} ${path}`), ['GET /status']);
    assert.equal(relay.writes(), 0);
    assert.equal(local.writes(), beforeWrites);
    assert.deepEqual(local.engine.data(), beforeData);
    assert.deepEqual(local.disk(), beforeDisk);
  }
});

test('individually fitting encrypted vaults cannot commit an oversized merged union', async t => {
  const local = await localVault(t);
  const remote = await localVault(t, local.disk(), local.secretKey);
  await local.engine.upsertItem({
    ...newItem('secureNote', 'Synthetic local merge note', local.engine.data().vaults[0].id), notes: 'a'.repeat(5000)
  });
  await remote.engine.upsertItem({
    ...newItem('secureNote', 'Synthetic remote merge note', remote.engine.data().vaults[0].id), notes: 'b'.repeat(5000)
  });
  const localEnvelope = await local.engine.exportForSync();
  const remoteEnvelope = await remote.engine.exportForSync();
  const beforeData = structuredClone(local.engine.data());
  const beforeDisk = local.disk();
  const beforeWrites = local.writes();
  const relay = await relayHttp(t, { initial: remoteEnvelope });
  for (const limits of [
    { ciphertextBytes: 8192, jsonBytes: 32768 },
    { ciphertextBytes: 65536, jsonBytes: 12288 }
  ]) {
    for (const envelope of [localEnvelope, remoteEnvelope]) {
      assert.ok(Buffer.from(envelope.ciphertext, 'base64').length <= limits.ciphertextBytes);
      assert.ok(Buffer.byteLength(JSON.stringify({ expectedRevision: Number.MAX_SAFE_INTEGER, envelope })) <= limits.jsonBytes);
    }
    relay.setLimits(limits); relay.requests.length = 0;
    await assert.rejects(syncVault(local.engine, relay.options), /Merged vault exceeds the sync service size limit/);
    assert.deepEqual(relay.requests.map(({ method, path }) => `${method} ${path}`), ['GET /status', 'GET /vault']);
    assert.equal(relay.writes(), 0);
    assert.equal(local.writes(), beforeWrites);
    assert.deepEqual(local.engine.data(), beforeData);
    assert.deepEqual(local.disk(), beforeDisk);
    assert.deepEqual(await relay.store.read(), { revision: 1, envelope: remoteEnvelope });
  }
});

test('malformed hosted limit capabilities fail closed before retrieval or mutation', async t => {
  const local = await localVault(t);
  const relay = await relayHttp(t);
  const beforeData = structuredClone(local.engine.data());
  const beforeDisk = local.disk();
  const beforeWrites = local.writes();
  const malformed = [null, {}, [], 'invalid',
    { ciphertextBytes: 0, jsonBytes: 8192 },
    { ciphertextBytes: 1.5, jsonBytes: 8192 },
    { ciphertextBytes: '8192', jsonBytes: 8192 },
    { ciphertextBytes: 100000001, jsonBytes: 8192 },
    { ciphertextBytes: 8192, jsonBytes: 32 },
    { ciphertextBytes: 8192, jsonBytes: null },
    { ciphertextBytes: 8192, jsonBytes: 100000001 }
  ];
  for (const limits of malformed) {
    relay.setLimits(limits); relay.requests.length = 0;
    await assert.rejects(syncVault(local.engine, relay.options), /Invalid sync service size limits/);
    assert.deepEqual(relay.requests.map(({ method, path }) => `${method} ${path}`), ['GET /status']);
    assert.equal(relay.writes(), 0);
    assert.equal(local.writes(), beforeWrites);
    assert.deepEqual(local.engine.data(), beforeData);
    assert.deepEqual(local.disk(), beforeDisk);
  }
});
