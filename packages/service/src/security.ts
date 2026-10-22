import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { IncomingMessage, ServerResponse } from 'node:http';

export function randomToken(): string { return randomBytes(48).toString('base64url'); }
export function requireStrongToken(token: string, label = 'API token'): void {
  if (typeof token !== 'string' || token.length < 43 || token.length > 1024 || /\s/.test(token)) throw new Error(`${label} must contain at least 43 non whitespace characters`);
}
export function tokenEqual(a: string, b: string): boolean {
  return timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());
}
export function bearer(req: IncomingMessage): string {
  const h = req.headers.authorization;
  return typeof h === 'string' && /^Bearer [^\s]+$/.test(h) ? h.slice(7) : '';
}
export function json(res: ServerResponse, code: number, body: unknown): void {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  res.end(JSON.stringify(body));
}
export async function readJson(req: IncomingMessage, maxBytes = 1_048_576): Promise<any> {
  const chunks: Buffer[] = []; let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > maxBytes) throw new Error('Request too large');
    chunks.push(Buffer.from(chunk));
  }
  const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (body === null || typeof body !== 'object' || Array.isArray(body)) throw new Error('Expected a JSON object');
  return body;
}
/** No symlinks, group/world access, or files owned by another account. */
export async function readOwnerFile(path: string): Promise<string> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || (process.getuid && stat.uid !== process.getuid())) throw new Error('Owner file must belong to this user and have mode 0600');
    return await handle.readFile('utf8');
  } finally { await handle.close(); }
}
export async function atomicOwnerWrite(path: string, data: string | Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try { const stat = await lstat(path); if (stat.isSymbolicLink()) throw new Error('Refusing symbolic link'); } catch (e: any) { if (e.code !== 'ENOENT') throw e; }
  const temporary = `${path}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`;
  const handle = await open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(data); await handle.sync(); await handle.close();
    await rename(temporary, path); await chmod(path, 0o600);
    const dir = await open(dirname(path), 'r'); try { await dir.sync(); } finally { await dir.close(); }
  } catch (error) { await handle.close().catch(() => {}); await unlink(temporary).catch(() => {}); throw error; }
}
export function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : 'Request failed';
  if (/^(Vault is locked|Unauthorized|Forbidden|Rate limit|Login not found|Item not found|Ambiguous|No allowed|Invalid|Browser|Assistant|Travel|Request too large|Expected|Unsupported|Not allowed|Cannot)/i.test(message)) return message;
  return 'Request failed';
}

/** Prevent two relay processes from accepting compare and swap writes to one state file. */
export async function acquireOwnerLock(path: string): Promise<() => Promise<void>> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  let handle;
  try { handle = await open(path, 'wx', 0o600); } catch (error: any) {
    if (error.code === 'EEXIST') throw new Error('Relay state is already locked. Stop its other process, or remove its stale lock file after confirming it is stopped.');
    throw error;
  }
  try { await handle.writeFile(JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })); await handle.sync(); } catch (error) { await handle.close(); await unlink(path).catch(() => {}); throw error; }
  let released = false;
  return async () => { if (released) return; released = true; await handle.close(); await unlink(path); };
}
