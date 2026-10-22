import { readBoundedJson } from './validation.mjs';

// Only the canonical cloud project origin is accepted. No redirects, URL credentials,
// alternate ports, paths or arbitrary hosts can receive the privileged service key.
export function readConfig(env) {
  let url;
  try { url = new URL(env.SUPABASE_URL); } catch { throw new Error('Relay configuration unavailable'); }
  if (url.protocol !== 'https:' || !/^[a-z0-9]{20}\.supabase\.co$/.test(url.hostname) ||
      url.username || url.password || url.port || url.search || url.hash || url.pathname !== '/')
    throw new Error('Relay configuration unavailable');
  const key = env.SUPABASE_SERVICE_ROLE_KEY;
  let validKey = typeof key === 'string' && /^sb_secret_[A-Za-z0-9_-]{20,200}$/.test(key);
  if (!validKey && typeof key === 'string' && key.length <= 2048 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(key)) {
    try { validKey = JSON.parse(Buffer.from(key.split('.')[1], 'base64url')).role === 'service_role'; } catch { /* Invalid key. */ }
  }
  const token = env.JJ_VAULT_RELAY_TOKEN;
  if (!validKey || typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token) ||
      Buffer.from(token, 'base64url').toString('base64url') !== token ||
      new Set(token).size < 16 || key === token)
    throw new Error('Relay configuration unavailable');
  return { url, key, token };
}

export function createSupabaseStore(config, fetcher = fetch) {
  async function rpc(name, args = {}) {
    const response = await fetcher(new URL(`/rest/v1/rpc/jj_relay_${name}`, config.url), {
      method: 'POST', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(12000),
      headers: { apikey: config.key, ...(config.key.startsWith('sb_secret_') ? {} : { Authorization: `Bearer ${config.key}` }),
        'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(args)
    });
    if (!response.ok) { await response.body?.cancel().catch(() => {}); throw new Error('Storage unavailable'); }
    try { return await readBoundedJson(response); } catch { throw new Error('Storage unavailable'); }
  }
  return {
    status: () => rpc('status'),
    read: () => rpc('read'),
    write: (expectedRevision, envelope) => rpc('write', { p_expected_revision: expectedRevision, p_envelope: envelope }),
    getShare: id => rpc('share_read', { p_id: id }),
    putShare: (id, envelope) => rpc('share_create', { p_id: id, p_envelope: envelope }),
    deleteShare: id => rpc('share_delete', { p_id: id })
  };
}
