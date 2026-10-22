import { randomBytes } from 'node:crypto';

export const token = randomBytes(32).toString('base64url');
export const env = {
  SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: `sb_secret_${randomBytes(32).toString('base64url')}`,
  JJ_VAULT_RELAY_TOKEN: token
};
export function envelope(id = 'synthetic-vault') {
  return {
    format: 'jjvault', version: 1, id,
    kdf: { algorithm: 'argon2id', salt: randomBytes(16).toString('base64'), memoryKiB: 65536, iterations: 3, parallelism: 1 },
    iv: randomBytes(12).toString('base64'), ciphertext: randomBytes(32).toString('base64')
  };
}
export function share() {
  return { version: 1, iv: randomBytes(12).toString('base64'), ciphertext: randomBytes(32).toString('base64'), expiresAt: new Date(Date.now() + 3600000).toISOString() };
}
export function syntheticStore() {
  let revision = 0;
  let vault = null;
  const shares = new Map();
  return {
    status: async () => ({ revision, vaultId: vault?.id || null }),
    read: async () => ({ revision, envelope: structuredClone(vault) }),
    write: async (expected, value) => {
      if (expected !== revision) return { ok: false, revision };
      vault = structuredClone(value); revision += 1; return { ok: true, revision };
    },
    getShare: async id => structuredClone(shares.get(id) || null),
    putShare: async (id, value) => {
      if (shares.has(id)) return { ok: false, reason: 'exists' };
      shares.set(id, structuredClone(value)); return { ok: true };
    },
    deleteShare: async id => { shares.delete(id); return { revoked: true }; }
  };
}
