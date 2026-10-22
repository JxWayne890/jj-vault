import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { type VaultEngine, type Item, type Envelope, type SyncLimits } from '../../core/src/index.ts';
import type { ShareEnvelope } from './sync-server.ts';
import { requireStrongToken } from './security.ts';

export function validateRelayUrl(input: string): URL {
  const url = new URL(input);
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) throw new Error('Invalid relay URL, use the server origin');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))) throw new Error('Invalid relay URL, TLS is required outside loopback');
  return url;
}
async function relayRequest(base: URL, path: string, token: string | undefined, method = 'GET', body?: unknown): Promise<any> {
  const response = await fetch(new URL(path, base), { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}), redirect: 'error', signal: AbortSignal.timeout(30000) });
  if (!response.ok) { const error: any = new Error(response.status === 409 ? 'Revision conflict' : response.status === 404 ? 'Share expired or revoked' : `Relay request failed (${response.status})`); error.status = response.status; throw error; }
  return response.json();
}
export async function syncVault(engine: VaultEngine, options: { url: string; token: string }): Promise<{ revision: number }> {
  const base = validateRelayUrl(options.url); requireStrongToken(options.token, 'Relay token');
  if (engine.status().locked) throw new Error('Vault is locked');
  const status = await relayRequest(base, '/status', options.token);
  let limits: SyncLimits | undefined;
  if (status?.limits !== undefined) {
    const { ciphertextBytes, jsonBytes } = status.limits || {};
    const wrapperBytes = Buffer.byteLength(JSON.stringify({ expectedRevision: Number.MAX_SAFE_INTEGER, envelope: null })) - 4;
    if (!Number.isSafeInteger(ciphertextBytes) || ciphertextBytes < 1 || ciphertextBytes > 100_000_000 || !Number.isSafeInteger(jsonBytes) || jsonBytes <= wrapperBytes || jsonBytes > 100_000_000) throw new Error('Invalid sync service size limits');
    limits = { maxCiphertextBytes: ciphertextBytes, maxEnvelopeBytes: jsonBytes - wrapperBytes };
  }
  const checkSize = (envelope: Envelope) => {
    if (limits && (Buffer.from(envelope.ciphertext, 'base64').length > limits.maxCiphertextBytes || Buffer.byteLength(JSON.stringify(envelope)) > limits.maxEnvelopeBytes)) throw new Error('Vault exceeds this sync service size limit. Remove large attachments or use another sync service before syncing.');
  };
  for (let retry = 0; retry < 3; retry++) {
    if (limits) checkSize(await engine.exportForSync());
    const remote = await relayRequest(base, '/vault', options.token);
    if (remote.envelope) {
      await engine.mergeEncrypted(remote.envelope, limits);
    }
    const envelope = await engine.exportForSync();
    checkSize(envelope);
    try {
      const result = await relayRequest(base, '/vault', options.token, 'PUT', { expectedRevision: remote.revision, envelope });
      await engine.record('sync.completed', undefined, `Relay revision ${result.revision}`);
      return result;
    } catch (error: any) { if (error.status !== 409 || retry === 2) throw error; }
  }
  throw new Error('Revision conflict');
}
export async function createShare(item: Item, options: { url: string; token: string; expiresAt: string }): Promise<{ id: string; url: string; expiresAt: string }> {
  const base = validateRelayUrl(options.url); requireStrongToken(options.token, 'Relay token');
  const expiry = Date.parse(options.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now() + 30 * 86400000) throw new Error('Invalid share expiry');
  const id = randomBytes(24).toString('base64url'); const key = randomBytes(32); const iv = randomBytes(12);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from(`JJVaultShare:v1:${id}`));
    const { passwordHistory: _history, passkey: _passkey, attachments: _attachments, ...currentItem } = item;
    const shareItem = { ...currentItem, passwordHistory: [], attachments: [], allowAssistant: false };
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(shareItem), 'utf8'), cipher.final(), cipher.getAuthTag()]);
    const envelope: ShareEnvelope = { version: 1, iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64'), expiresAt: new Date(expiry).toISOString() };
    await relayRequest(base, `/share/${id}`, options.token, 'PUT', envelope);
    return { id, url: new URL(`/s/${id}#${key.toString('base64url')}`, base).href, expiresAt: envelope.expiresAt };
  } finally { key.fill(0); }
}
export async function openShare(link: string): Promise<Item> {
  const url = new URL(link); const base = validateRelayUrl(url.origin);
  const match = /^\/s\/([A-Za-z0-9_-]{32,64})$/.exec(url.pathname);
  if (!match || !/^#[A-Za-z0-9_-]{43}$/.test(url.hash)) throw new Error('Invalid share link');
  const key = Buffer.from(url.hash.slice(1), 'base64url');
  if (key.length !== 32 || key.toString('base64url') !== url.hash.slice(1)) { key.fill(0); throw new Error('Invalid share key'); }
  url.hash = '';
  const share = await relayRequest(base, `/share/${match[1]}`, undefined);
  try {
    if (share.version !== 1 || Date.parse(share.expiresAt) <= Date.now()) throw new Error('Share expired or revoked');
    const ciphertext = Buffer.from(share.ciphertext, 'base64');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(share.iv, 'base64')); decipher.setAAD(Buffer.from(`JJVaultShare:v1:${match[1]}`)); decipher.setAuthTag(ciphertext.subarray(-16));
    const plaintext = Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
    try { return JSON.parse(plaintext.toString('utf8')); } finally { plaintext.fill(0); }
  } finally { key.fill(0); }
}
export async function revokeShare(id: string, options: { url: string; token: string }): Promise<void> {
  if (!/^[A-Za-z0-9_-]{32,64}$/.test(id)) throw new Error('Invalid share ID');
  requireStrongToken(options.token, 'Relay token'); await relayRequest(validateRelayUrl(options.url), `/share/${id}`, options.token, 'DELETE');
}
