import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as createSecureServer } from 'node:https';
import type { TLSSocket } from 'node:tls';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { isDirectExecution } from './entrypoint.ts';
import { acquireOwnerLock, atomicOwnerWrite, bearer, json, randomToken, readJson, readOwnerFile, requireStrongToken, safeError, tokenEqual } from './security.ts';
import type { Envelope } from '../../core/src/index.ts';

export interface ShareEnvelope { version: 1; iv: string; ciphertext: string; expiresAt: string; }
export interface PairingLease { valid(): boolean; issued?(): void; vaultId?: string; }
export interface SyncServerOptions {
  token: string; file: string; port?: number; host?: string; allowedHosts?: string[]; now?: () => number;
  tls?: { key: string; cert: string; host: string; port?: number; names: string[] };
  consumePairingNonce?: (nonce: string) => PairingLease | false;
  /** Dependency injection for disposable storage and queued write regression tests. */
  writeState?: (file: string, data: string) => Promise<void>;
}
interface RelayState { version: 1; revision: number; envelope: Envelope | null; shares: Record<string, ShareEnvelope>; }
export function validateEnvelope(value: any): asserts value is Envelope {
  if (!value || value.format !== 'jjvault' || value.version !== 1 || typeof value.id !== 'string' || !/^[A-Za-z0-9-]{8,80}$/.test(value.id) || value.kdf?.algorithm !== 'argon2id' || !Number.isSafeInteger(value.kdf.memoryKiB) || value.kdf.memoryKiB < 65536 || value.kdf.memoryKiB > 262144 || !Number.isSafeInteger(value.kdf.iterations) || value.kdf.iterations < 3 || value.kdf.iterations > 10 || !Number.isSafeInteger(value.kdf.parallelism) || value.kdf.parallelism !== 1 || !base64(value.kdf.salt, 16, 16) || !base64(value.iv, 12, 12) || !base64(value.ciphertext, 16, 64 * 1024 * 1024)) throw new Error('Invalid encrypted vault');
}
function base64(value: unknown, minimum: number, maximum: number): boolean {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length >= minimum && decoded.length <= maximum && decoded.toString('base64') === value;
}
function validShare(value: any): value is ShareEnvelope {
  return value?.version === 1 && base64(value.iv, 12, 12) && base64(value.ciphertext, 16, 16 * 1024 * 1024) && typeof value.expiresAt === 'string' && Number.isFinite(Date.parse(value.expiresAt));
}
const viewerScript = `let shareKeyText=location.hash.slice(1);
let opening=false;
document.getElementById('open').onclick=async()=>{
  if(opening)return;
  opening=true;document.getElementById('open').disabled=true;
  try{
    const keyText=shareKeyText;
    if(!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(keyText))throw Error('Missing share key');
    history.replaceState(null,'',location.pathname);
    const id=location.pathname.split('/').pop();
    const response=await fetch('/share/'+id,{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
    if(!response.ok)throw Error('Share expired or revoked');
    const value=await response.json();
    if(Date.parse(value.expiresAt)<=Date.now())throw Error('Share expired or revoked');
    const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
    const raw=decode(keyText.replace(/-/g,'+').replace(/_/g,'/')+'=');
    const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);raw.fill(0);
    const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(value.iv),additionalData:new TextEncoder().encode('JJVaultShare:v1:'+id)},key,decode(value.ciphertext));
    try{
      const item=document.getElementById('item');
      item.textContent=JSON.stringify(JSON.parse(new TextDecoder().decode(plaintext)),null,2);item.hidden=false;
    }finally{new Uint8Array(plaintext).fill(0);}
    document.getElementById('status').textContent='Decrypted on this device';
    document.getElementById('open').hidden=true;shareKeyText='';
  }catch{
    document.getElementById('status').textContent=shareKeyText?'Unable to open this share. Try again. It may be expired, revoked or invalid.':'Reopen the original complete share link to restore its key.';
  }finally{opening=false;document.getElementById('open').disabled=false;}
};`;
const viewer = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>JJ Vault shared item</title><style>body{font:16px system-ui;max-width:44rem;margin:4rem auto;padding:1rem;background:#101724;color:#eef3fa}pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #546780;padding:1rem}button{padding:.6rem 1rem}h1{font-size:1.7rem}</style><h1>JJ Vault shared item</h1><p id="status">The decryption key stays in this browser.</p><button id="open">Open shared item</button><pre id="item" hidden></pre><script>${viewerScript}</script></html>`;
export async function startSyncServer(options: SyncServerOptions): Promise<{ port: number; tlsPort?: number; close(): Promise<void> }> {
  requireStrongToken(options.token, 'Relay token');
  const releaseLock = await acquireOwnerLock(options.file + '.lock');
  const now = options.now || Date.now;
  let state: RelayState = { version: 1, revision: 0, envelope: null, shares: {} };
  try {
    const parsed = JSON.parse(await readOwnerFile(options.file));
    if (parsed.version !== 1 || !Number.isSafeInteger(parsed.revision) || parsed.revision < 0 || typeof parsed.shares !== 'object' || !parsed.shares) throw new Error('Invalid relay state');
    if (parsed.envelope !== null) validateEnvelope(parsed.envelope);
    for (const [id, share] of Object.entries(parsed.shares)) if (!/^[A-Za-z0-9_-]{32,64}$/.test(id) || !validShare(share)) throw new Error('Invalid relay share state');
    state = parsed;
  } catch (error: any) { if (error.code !== 'ENOENT') { await releaseLock(); throw error; } }
  let queue: Promise<unknown> = Promise.resolve();
  function serial<T>(operation: () => Promise<T>): Promise<T> { const task = queue.then(operation); queue = task.catch(() => {}); return task; }
  async function persist(next: RelayState) { await (options.writeState || atomicOwnerWrite)(options.file, JSON.stringify(next)); state = next; }
  async function pruneExpired() {
    await serial(async () => {
      const shares = Object.fromEntries(Object.entries(state.shares).filter(([, share]) => Date.parse(share.expiresAt) > now()));
      if (Object.keys(shares).length !== Object.keys(state.shares).length) await persist({ ...state, shares });
    });
  }
  let port = options.port ?? 17374;
  let tlsPort = options.tls?.port ?? 17375;
  const handler = (req: IncomingMessage, res: ServerResponse) => { void (async () => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Content-Type-Options', 'nosniff');
    const encrypted = (req.socket as TLSSocket).encrypted === true;
    const allowedHosts = new Set(encrypted ? (options.tls?.names || []).map(name => `${name.toLowerCase()}:${tlsPort}`) : [`127.0.0.1:${port}`, `localhost:${port}`, ...(options.allowedHosts || [])]);
    if (!req.headers.host || !allowedHosts.has(req.headers.host.toLowerCase()) || req.headers.origin) { json(res, 403, { error: 'Forbidden' }); return; }
    const path = new URL(req.url || '/', `http://127.0.0.1:${port}`).pathname;
    if (path === '/pair' && req.method === 'POST') {
      if (!encrypted || !options.consumePairingNonce) { json(res, 403, { error: 'Pairing requires the configured TLS connection' }); return; }
      const body = await readJson(req, 4096);
      if (Object.keys(body).length !== 1 || typeof body.nonce !== 'string' || body.nonce.length > 100) { json(res, 401, { error: 'Pairing is unavailable or expired' }); return; }
      // Consume synchronously before the queue wait so concurrent requests cannot replay the nonce.
      const lease = options.consumePairingNonce(body.nonce);
      if (!lease) { json(res, 401, { error: 'Pairing is unavailable or expired' }); return; }
      await queue;
      if (!state.envelope) { json(res, 409, { error: 'Sync the Mac vault before pairing' }); return; }
      // Owner cancellation, locking, session changes and expiry can happen while persistence is queued.
      // Keep this final lease validation adjacent to the synchronous response write.
      if (lease.vaultId && lease.vaultId !== state.envelope.id || !lease.valid()) { json(res, 401, { error: 'Pairing is unavailable or expired' }); return; }
      json(res, 200, { token: options.token, revision: state.revision, envelope: state.envelope });
      try { lease.issued?.(); } catch { /* Credential delivery must not become a failed write response. */ }
      return;
    }
    const shareMatch = /^\/share\/([A-Za-z0-9_-]{32,64})$/.exec(path);
    const viewMatch = /^\/s\/([A-Za-z0-9_-]{32,64})$/.exec(path);
    if (viewMatch && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'", 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()' }); res.end(viewer); return;
    }
    if (shareMatch && req.method === 'GET') {
      await queue;
      const share = state.shares[shareMatch[1]];
      if (!share || Date.parse(share.expiresAt) <= now()) { if (share) await pruneExpired(); json(res, 404, { error: 'Share expired or revoked' }); return; }
      json(res, 200, share); return;
    }
    if (!bearer(req) || !tokenEqual(bearer(req), options.token)) { json(res, 401, { error: 'Unauthorized' }); return; }
    if (path === '/status' && req.method === 'GET') { await queue; json(res, 200, { revision: state.revision, vaultId: state.envelope?.id || null }); return; }
    if (path === '/vault' && req.method === 'GET') { await queue; json(res, 200, { revision: state.revision, envelope: state.envelope }); return; }
    if (path === '/vault' && req.method === 'PUT') {
      const body = await readJson(req, 90 * 1024 * 1024); validateEnvelope(body.envelope);
      if (!Number.isSafeInteger(body.expectedRevision) || body.expectedRevision < 0) throw new Error('Invalid expected revision');
      await serial(async () => {
        if (body.expectedRevision !== state.revision) { json(res, 409, { error: 'Revision conflict', revision: state.revision }); return; }
        await persist({ ...state, revision: state.revision + 1, envelope: body.envelope }); json(res, 200, { revision: state.revision });
      }); return;
    }
    if (shareMatch && req.method === 'PUT') {
      const body = await readJson(req, 23 * 1024 * 1024);
      if (!validShare(body) || Date.parse(body.expiresAt) <= now() || Date.parse(body.expiresAt) > now() + 30 * 86400000) throw new Error('Invalid share, expiry must be within thirty days');
      await serial(async () => {
        if (state.shares[shareMatch[1]]) { json(res, 409, { error: 'Share already exists' }); return; }
        const live = Object.fromEntries(Object.entries(state.shares).filter(([, share]) => Date.parse(share.expiresAt) > now()));
        if (Object.keys(live).length >= 1000) throw new Error('Invalid share count');
        await persist({ ...state, shares: { ...live, [shareMatch[1]]: body } }); json(res, 201, { id: shareMatch[1], expiresAt: body.expiresAt });
      }); return;
    }
    if (shareMatch && req.method === 'DELETE') {
      await serial(async () => { const shares = { ...state.shares }; delete shares[shareMatch[1]]; await persist({ ...state, shares }); json(res, 200, { revoked: true }); }); return;
    }
    json(res, 404, { error: 'Not found' });
  })().catch(error => { if (!res.headersSent) json(res, 400, { error: safeError(error) }); else res.end(); }); };
  const server = createServer(handler);
  let secureServer: ReturnType<typeof createSecureServer> | undefined;
  try { secureServer = options.tls ? createSecureServer({ key: options.tls.key, cert: options.tls.cert, minVersion: 'TLSv1.2' }, handler) : undefined; } catch (error) { await releaseLock(); throw error; }
  const sockets = new Set<import('node:net').Socket>();
  for (const listener of [server, ...(secureServer ? [secureServer] : [])]) { listener.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); }); listener.maxHeadersCount = 40; }
  server.headersTimeout = 10000; server.requestTimeout = 60000;
  try {
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, options.host || '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
    port = (server.address() as { port: number }).port;
    if (secureServer) {
      secureServer.headersTimeout = 10000; secureServer.requestTimeout = 60000;
      await new Promise<void>((resolve, reject) => { secureServer.once('error', reject); secureServer.listen(tlsPort, options.tls!.host, () => { secureServer.off('error', reject); resolve(); }); });
      tlsPort = (secureServer.address() as { port: number }).port;
    }
  } catch (error) { for (const socket of sockets) socket.destroy(); if (server.listening) await new Promise<void>(resolve => server.close(() => resolve())); if (secureServer?.listening) await new Promise<void>(resolve => secureServer.close(() => resolve())); await releaseLock(); throw error; }
  port = (server.address() as { port: number }).port;
  const cleanup = setInterval(() => { void pruneExpired().catch(() => {}); }, 60000); cleanup.unref();
  return { port, ...(secureServer ? { tlsPort } : {}), async close() { clearInterval(cleanup); await queue; for (const socket of sockets) socket.destroy(); await Promise.all([server, ...(secureServer ? [secureServer] : [])].map(listener => new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve())))); await releaseLock(); } };
}
export async function runSyncServer() {
  const directory = process.env.JJ_VAULT_RELAY_DIR || join(homedir(), 'Library', 'Application Support', 'JJ Vault Relay');
  const tokenFile = join(directory, 'relay-token');
  let token: string;
  try { token = (await readOwnerFile(tokenFile)).trim(); } catch (error: any) { if (error.code !== 'ENOENT') throw error; token = randomToken(); await atomicOwnerWrite(tokenFile, token + '\n'); }
  const relay = await startSyncServer({ token, file: join(directory, 'relay.json'), port: Number(process.env.JJ_VAULT_RELAY_PORT || 17374), host: process.env.JJ_VAULT_RELAY_HOST || '127.0.0.1', allowedHosts: (process.env.JJ_VAULT_RELAY_HOSTS || '').split(',').filter(Boolean) });
  process.stderr.write(`JJ Vault encrypted relay listening on port ${relay.port}. Token file: ${tokenFile}\n`);
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => { void relay.close().then(() => process.exit(0)); });
}
if (isDirectExecution(import.meta.url) && /(?:^|[\\/])sync-server\.(?:ts|mjs|cjs)$/.test(process.argv[1])) void runSyncServer().catch(() => { process.stderr.write('Relay failed to start. Check configuration and owner file permissions.\n'); process.exitCode = 1; });
