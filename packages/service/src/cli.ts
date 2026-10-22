#!/usr/bin/env node
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { isDirectExecution } from './entrypoint.ts';
import { atomicOwnerWrite, readOwnerFile, requireStrongToken } from './security.ts';
import { validateEnvelope } from '../../core/src/index.ts';
import { createDeviceSessionStore } from './device-session.ts';

// Offline restore needs no OS encryption access, only safe cache removal.
const unavailableSessionEncryption = {
  isEncryptionAvailable: () => false,
  encryptString: (_value: string): Buffer => { throw new Error('Session encryption is unavailable in the owner CLI'); },
  decryptString: (_value: Buffer): string => { throw new Error('Session encryption is unavailable in the owner CLI'); },
};

export async function runCli(args: string[], config: { directory?: string; port?: number; output?: (text: string) => void } = {}): Promise<void> {
  const directory = config.directory || process.env.JJ_VAULT_DIR || join(homedir(), 'Library', 'Application Support', 'JJ Vault');
  const port = config.port || Number(process.env.JJ_VAULT_PORT || 17373);
  const output = config.output || (value => process.stdout.write(value + '\n'));
  const [command, argument, field] = args;
  if (!command || ['help', '--help', '-h'].includes(command)) {
    output('jjvault status\njjvault search QUERY\njjvault get ITEM_ID [FIELD]\njjvault lock\njjvault backup FILE\njjvault restore FILE\nUnlock in the Mac app. CLI accepts no master password. Restore requires the Mac app closed.'); return;
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('Invalid local port');
  if (command === 'backup') {
    if (!argument) throw new Error('Backup needs a destination file');
    const source = await readOwnerFile(join(directory, 'vault.json')); validateEnvelope(JSON.parse(source));
    await atomicOwnerWrite(resolve(argument), source); output('Encrypted backup saved'); return;
  }
  if (command === 'restore') {
    if (!argument) throw new Error('Restore needs an encrypted backup file');
    let running = false;
    try { await fetch(`http://127.0.0.1:${port}/admin`, { method: 'POST', signal: AbortSignal.timeout(1000) }); running = true; } catch {}
    if (running) throw new Error('Close the Mac app before restoring an encrypted backup');
    const backup = await readOwnerFile(resolve(argument)); validateEnvelope(JSON.parse(backup));
    // Keep the existing encrypted vault before a reversible replacement.
    try { const current = await readOwnerFile(join(directory, 'vault.json')); await atomicOwnerWrite(join(directory, `vault.before-restore.${Date.now()}.json`), current); } catch (error: any) { if (error.code !== 'ENOENT') throw error; }
    // Even a backup with the same key identity can roll back vault access rules.
    // Do not let a saved session reopen the replacement without an owner unlock.
    if (!createDeviceSessionStore(directory, unavailableSessionEncryption).forget()) throw new Error('Unable to clear the saved device session. Encrypted backup was not restored.');
    await atomicOwnerWrite(join(directory, 'vault.json'), backup); output('Encrypted backup restored. Unlock in the Mac app with its master password and Secret Key.'); return;
  }
  if (!['status', 'search', 'get', 'lock'].includes(command)) throw new Error('Unknown command');
  if (['get', 'search'].includes(command) && !argument) throw new Error('An item ID or search query is required');
  const token = (await readOwnerFile(join(directory, 'admin-token'))).trim(); requireStrongToken(token, 'Admin token');
  const response = await fetch(`http://127.0.0.1:${port}/admin`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ action: command, ...(command === 'search' ? { query: argument } : {}), ...(command === 'get' ? { id: argument } : {}) }), redirect: 'error', signal: AbortSignal.timeout(10000) });
  const result = await response.json();
  if (!response.ok || !result.ok) throw new Error(result.error || 'Local request failed');
  if (field && command === 'get') {
    const value = result.result[field] ?? result.result.fields?.find((entry: any) => entry.label === field)?.value;
    if (value === undefined || typeof value === 'object') throw new Error('Field is missing or is not a scalar value');
    output(String(value));
  } else output(JSON.stringify(result.result, null, 2));
}
if (isDirectExecution(import.meta.url) && /(?:^|[\\/])cli\.(?:ts|mjs|cjs)$/.test(process.argv[1])) void runCli(process.argv.slice(2)).catch(error => { process.stderr.write((error instanceof Error ? error.message : 'JJ Vault command failed') + '\n'); process.exitCode = 1; });
