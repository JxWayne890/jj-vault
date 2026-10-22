import { createHash, timingSafeEqual } from 'node:crypto';
import { HttpError, MAX_CIPHERTEXT_BYTES, MAX_JSON_BYTES, MAX_REVISION, objectWithKeys, validRevision, validateEnvelope, validateShare, readBoundedJson } from './validation.mjs';
import { readConfig, createSupabaseStore } from './store.mjs';
import { landing, viewer, viewerPolicy } from './viewer.mjs';

const securityHeaders = {
  'Cache-Control': 'no-store, private, max-age=0',
  'CDN-Cache-Control': 'no-store', 'Vercel-CDN-Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
};
function json(status, value) {
  return new Response(JSON.stringify(value), { status, headers: { ...securityHeaders, 'Content-Type': 'application/json; charset=utf-8' } });
}
function html(value, policy) {
  return new Response(value, { headers: { ...securityHeaders, ...(policy ? { 'Content-Security-Policy': policy } : {}), 'Content-Type': 'text/html; charset=utf-8' } });
}
function authorized(header, token) {
  if (!header || header.length > 256 || !/^Bearer [A-Za-z0-9_-]{43}$/.test(header)) return false;
  const hash = value => createHash('sha256').update(value).digest();
  return timingSafeEqual(hash(header.slice(7)), hash(token));
}
function storageRevision(value) {
  if (!validRevision(value)) throw new Error('Storage unavailable');
}

// The injected store is used only by tests. Production always creates a stateless
// Supabase adapter from its private environment, never an in memory vault store.
export function createRelay({ env, store: injectedStore, fetcher, now = Date.now } = {}) {
  return async request => {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      if (url.search) return json(400, { error: 'Query parameters are not supported' });
      if (request.method === 'GET' && path === '/') return html(landing);
      const viewMatch = /^\/s\/([A-Za-z0-9_-]{32,64})$/.exec(path);
      if (viewMatch && request.method === 'GET') return html(viewer, viewerPolicy);
      // This is a native client API. Browser origins cannot read the vault or write
      // shares, even if someone mistakenly supplies an otherwise valid token.
      if (request.headers.has('origin')) return json(403, { error: 'Forbidden' });
      const config = readConfig(env || process.env);
      const shareMatch = /^\/share\/([A-Za-z0-9_-]{32,64})$/.exec(path);
      const publicShareRead = shareMatch && request.method === 'GET';
      if (!publicShareRead && !authorized(request.headers.get('authorization'), config.token))
        return json(401, { error: 'Unauthorized' });
      const store = injectedStore || createSupabaseStore(config, fetcher);
      if (path === '/status' && request.method === 'GET') {
        const state = await store.status();
        storageRevision(state.revision);
        if (state.vaultId !== null && (typeof state.vaultId !== 'string' || !/^[A-Za-z0-9-]{8,80}$/.test(state.vaultId))) throw new Error('Storage unavailable');
        return json(200, { revision: state.revision, vaultId: state.vaultId,
          limits: { ciphertextBytes: MAX_CIPHERTEXT_BYTES, jsonBytes: MAX_JSON_BYTES } });
      }
      if (path === '/vault' && request.method === 'GET') {
        const state = await store.read(); storageRevision(state.revision);
        if (state.envelope !== null) { try { validateEnvelope(state.envelope); } catch { throw new Error('Storage unavailable'); } }
        return json(200, { revision: state.revision, envelope: state.envelope });
      }
      if (path === '/vault' && request.method === 'PUT') {
        if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') || ''))
          return json(415, { error: 'Use application/json' });
        const body = await readBoundedJson(request);
        if (!objectWithKeys(body, ['expectedRevision', 'envelope']) || !validRevision(body.expectedRevision) || body.expectedRevision >= MAX_REVISION)
          throw new HttpError(400, 'Invalid expected revision');
        validateEnvelope(body.envelope);
        const result = await store.write(body.expectedRevision, body.envelope); storageRevision(result.revision);
        if (result.ok === false) return json(409, { error: 'Revision conflict', revision: result.revision });
        if (result.ok !== true || result.revision !== body.expectedRevision + 1) throw new Error('Storage unavailable');
        return json(200, { revision: result.revision });
      }
      if (publicShareRead) {
        const share = await store.getShare(shareMatch[1]);
        if (share === null) return json(404, { error: 'Share expired or revoked' });
        try { validateShare(share); } catch { throw new Error('Storage unavailable'); }
        if (Date.parse(share.expiresAt) <= now()) return json(404, { error: 'Share expired or revoked' });
        return json(200, share);
      }
      if (shareMatch && request.method === 'PUT') {
        if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') || ''))
          return json(415, { error: 'Use application/json' });
        const share = await readBoundedJson(request); validateShare(share, { future: true, now: now() });
        const result = await store.putShare(shareMatch[1], share);
        if (result.ok === false && result.reason === 'exists') return json(409, { error: 'Share already exists' });
        if (result.ok === false && result.reason === 'limit') return json(409, { error: 'Share limit reached' });
        if (result.ok !== true) throw new Error('Storage unavailable');
        return json(201, { id: shareMatch[1], expiresAt: share.expiresAt });
      }
      if (shareMatch && request.method === 'DELETE') {
        const result = await store.deleteShare(shareMatch[1]);
        if (result.revoked !== true) throw new Error('Storage unavailable');
        return json(200, { revoked: true });
      }
      return json(404, { error: 'Not found' });
    } catch (error) {
      // Upstream errors can contain keys, SQL arguments or ciphertext. Never return
      // or log their message. Validation messages are fixed strings owned here.
      return error instanceof HttpError ? json(error.status, { error: error.message }) : json(503, { error: 'Relay unavailable' });
    }
  };
}
