export const MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024;
export const MAX_JSON_BYTES = 3 * 1024 * 1024;
export const MAX_REVISION = Number.MAX_SAFE_INTEGER - 1;

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export function objectWithKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

export function base64(value, minimum, maximum) {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(maximum / 3) ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length >= minimum && bytes.length <= maximum && bytes.toString('base64') === value;
}

export function validRevision(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_REVISION;
}

export function validateEnvelope(value) {
  if (value && typeof value.ciphertext === 'string' && (value.ciphertext.length > 4 * Math.ceil(MAX_CIPHERTEXT_BYTES / 3) ||
      Buffer.from(value.ciphertext, 'base64').length > MAX_CIPHERTEXT_BYTES))
    throw new HttpError(413, 'Hosted relay supports at most 2 MiB of encrypted vault data');
  if (!objectWithKeys(value, ['format', 'version', 'id', 'kdf', 'iv', 'ciphertext']) ||
      value.format !== 'jjvault' || value.version !== 1 ||
      typeof value.id !== 'string' || !/^[A-Za-z0-9-]{8,80}$/.test(value.id) ||
      !objectWithKeys(value.kdf, ['algorithm', 'salt', 'memoryKiB', 'iterations', 'parallelism']) ||
      value.kdf.algorithm !== 'argon2id' || !Number.isInteger(value.kdf.memoryKiB) ||
      value.kdf.memoryKiB < 65536 || value.kdf.memoryKiB > 262144 ||
      !Number.isInteger(value.kdf.iterations) || value.kdf.iterations < 3 || value.kdf.iterations > 10 ||
      value.kdf.parallelism !== 1 || !base64(value.kdf.salt, 16, 16) ||
      !base64(value.iv, 12, 12) || !base64(value.ciphertext, 16, MAX_CIPHERTEXT_BYTES))
    throw new HttpError(400, 'Invalid encrypted vault');
  // The database size limit is intentionally larger than the valid maximum envelope.
  return value;
}

export function validateShare(value, { future = false, now = Date.now() } = {}) {
  if (!objectWithKeys(value, ['version', 'iv', 'ciphertext', 'expiresAt']) || value.version !== 1 ||
      !base64(value.iv, 12, 12) || !base64(value.ciphertext, 16, MAX_CIPHERTEXT_BYTES) ||
      typeof value.expiresAt !== 'string' || value.expiresAt.length > 40 ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value.expiresAt) ||
      !Number.isFinite(Date.parse(value.expiresAt)) ||
      (future && (Date.parse(value.expiresAt) <= now || Date.parse(value.expiresAt) > now + 30 * 86400000)))
    throw new HttpError(400, 'Invalid encrypted share, expiry must be within thirty days and ciphertext at most 2 MiB');
  return value;
}

export async function readBoundedJson(message, maximum = MAX_JSON_BYTES) {
  const size = message.headers.get('content-length');
  if (size !== null && (!/^\d+$/.test(size) || Number(size) > maximum))
    throw new HttpError(413, 'Hosted relay JSON body exceeds 3 MiB');
  const reader = message.body?.getReader();
  if (!reader) throw new HttpError(400, 'Invalid JSON');
  let total = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) throw new HttpError(413, 'Hosted relay JSON body exceeds 3 MiB');
      chunks.push(value);
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total)));
  } catch (error) {
    await reader.cancel().catch(() => {});
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, 'Invalid JSON');
  } finally { reader.releaseLock(); }
}
