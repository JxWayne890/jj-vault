import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createContext, runInContext } from 'node:vm';
import { newItem } from '../../core/src/index.ts';
import { createShare } from '../src/clients.ts';
import { randomToken } from '../src/security.ts';
import { startSyncServer } from '../src/sync-server.ts';

test('local share viewer retries a transient HTTP failure and decrypts without sending its fragment key', { timeout: 10000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'jj-vault-share-viewer-'));
  const token = randomToken();
  const relay = await startSyncServer({ token, file: join(directory, 'relay.json'), port: 0 });
  const relayUrl = `http://127.0.0.1:${relay.port}`;
  const item = { ...newItem('login', 'Synthetic share retry', 'synthetic-vault'), username: 'synthetic@example.invalid', password: 'Synthetic retry fixture password' };
  const link = await createShare(item, { url: relayUrl, token, expiresAt: new Date(Date.now() + 60000).toISOString() });
  const linkUrl = new URL(link.url);
  const keyText = linkUrl.hash.slice(1);
  let releaseFirst!: () => void;
  const firstResponse = new Promise<void>(resolve => { releaseFirst = resolve; });
  let firstArrived!: () => void;
  const firstRequest = new Promise<void>(resolve => { firstArrived = resolve; });
  const requests: { path: string; headers: unknown; body: string }[] = [];
  const serverErrors: unknown[] = [];
  let shareRequests = 0;
  const proxy = createServer((incoming, outgoing) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
      const path = incoming.url || '/';
      requests.push({ path, headers: incoming.headers, body: Buffer.concat(chunks).toString('utf8') });
      if (path.startsWith('/share/') && ++shareRequests === 1) {
        firstArrived(); await firstResponse;
        outgoing.writeHead(503); outgoing.end(); return;
      }
      const response = await fetch(new URL(path, relayUrl), { redirect: 'error' });
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    })().catch(error => { serverErrors.push(error); outgoing.writeHead(500); outgoing.end(); });
  });
  t.after(async () => {
    releaseFirst(); proxy.closeAllConnections();
    if (proxy.listening) await new Promise<void>((resolve, reject) => proxy.close(error => error ? reject(error) : resolve()));
    await relay.close();
    await rm(directory, { recursive: true, force: true });
    assert.deepEqual(serverErrors, []);
  });
  await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
  const address = proxy.address();
  assert.ok(address && typeof address === 'object');
  const proxyUrl = `http://127.0.0.1:${address.port}`;
  const page = await fetch(proxyUrl + linkUrl.pathname + linkUrl.hash);
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy') || '', /connect-src 'self'/);
  const html = await page.text();
  const script = /<script>([\s\S]*)<\/script>/.exec(html)?.[1];
  assert.ok(script);
  const nodes = {
    open: { hidden: false, disabled: false, onclick: undefined as undefined | (() => Promise<void>) },
    item: { hidden: true, textContent: '' }, status: { textContent: '' }
  };
  const location = { hash: linkUrl.hash, pathname: linkUrl.pathname };
  const fetchOptions: RequestInit[] = [];
  const context = createContext({
    document: { getElementById: (id: keyof typeof nodes) => nodes[id] }, location,
    history: { replaceState: (_state: unknown, _unused: string, path: string) => { assert.equal(path, linkUrl.pathname); location.hash = ''; } },
    crypto: webcrypto, Uint8Array, TextEncoder, TextDecoder, atob,
    fetch: async (path: string, options: RequestInit) => {
      assert.equal(location.hash, ''); fetchOptions.push(options);
      return fetch(new URL(path, proxyUrl), options);
    }
  });
  runInContext(script, context);
  assert.ok(nodes.open.onclick);
  const first = nodes.open.onclick();
  await firstRequest;
  assert.equal(nodes.open.disabled, true);
  await nodes.open.onclick();
  assert.equal(shareRequests, 1);
  releaseFirst(); await first;
  assert.equal(location.hash, '');
  assert.equal(nodes.open.disabled, false); assert.equal(nodes.open.hidden, false);
  assert.match(nodes.status.textContent, /Try again/);
  await nodes.open.onclick();
  assert.equal(shareRequests, 2); assert.equal(location.hash, '');
  const decrypted = JSON.parse(nodes.item.textContent);
  assert.equal(decrypted.title, item.title); assert.equal(decrypted.password, item.password);
  assert.equal(decrypted.username, item.username);
  assert.equal(nodes.item.hidden, false); assert.equal(nodes.open.hidden, true);
  assert.equal(nodes.status.textContent, 'Decrypted on this device');
  assert.equal(runInContext('shareKeyText', context), '');
  assert.equal(JSON.stringify(requests).includes(keyText), false);
  assert.deepEqual(requests.map(request => request.path), [linkUrl.pathname, `/share/${link.id}`, `/share/${link.id}`]);
  assert.equal(fetchOptions.length, 2);
  for (const options of fetchOptions) {
    assert.equal(options.credentials, 'omit'); assert.equal(options.referrerPolicy, 'no-referrer'); assert.equal(options.cache, 'no-store');
  }
});
