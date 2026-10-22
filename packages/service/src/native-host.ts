import { homedir } from 'node:os';
import { join } from 'node:path';
import { isDirectExecution } from './entrypoint.ts';
import { readOwnerFile, requireStrongToken } from './security.ts';

export interface BrowserHostConfig {
  chromeExtensionIds?: string[];
  firefoxExtensionIds?: string[];
  safariExtensionIds?: string[];
  browserTokenFile?: string;
  port?: number;
}
export function verifyBrowserCaller(caller: string | undefined, config: BrowserHostConfig): boolean {
  if (!caller) return false;
  const chrome = /^chrome-extension:\/\/([a-p]{32})\/?$/.exec(caller);
  if (chrome) return (config.chromeExtensionIds || []).includes(chrome[1]);
  const safari = /^safari-web-extension:\/\/([A-Za-z0-9.-]+)\/?$/.exec(caller);
  if (safari) return (config.safariExtensionIds || []).includes(safari[1]);
  return (config.firefoxExtensionIds || []).some(id => id.length >= 3 && id === caller);
}
export async function runNativeHost(options: { configFile?: string; caller?: string; input?: NodeJS.ReadableStream; output?: NodeJS.WritableStream } = {}): Promise<void> {
  const input = options.input || process.stdin; const output = options.output || process.stdout;
  const directory = join(homedir(), 'Library', 'Application Support', 'JJ Vault');
  const config: BrowserHostConfig = JSON.parse(await readOwnerFile(options.configFile || process.env.JJ_VAULT_BROWSER_CONFIG || join(directory, 'browser-host.json')));
  const caller = options.caller ?? (process.argv[2]?.startsWith('chrome-extension://') || process.argv[2]?.startsWith('safari-web-extension://') ? process.argv[2] : process.argv[3]);
  if (!verifyBrowserCaller(caller, config)) throw new Error('Browser caller is not paired');
  const token = (await readOwnerFile(config.browserTokenFile || join(directory, 'browser-token'))).trim(); requireStrongToken(token, 'Browser token');
  const port = config.port ?? 17373;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('Invalid browser host port');
  let buffer = Buffer.alloc(0); let expected: number | null = null; let pending = Promise.resolve();
  function send(value: unknown) {
    const payload = Buffer.from(JSON.stringify(value));
    if (payload.length > 4 * 1024 * 1024) throw new Error('Browser response too large');
    const header = Buffer.alloc(4); header.writeUInt32LE(payload.length); output.write(Buffer.concat([header, payload]));
  }
  for await (const chunk of input as AsyncIterable<Buffer>) {
    buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
    while (true) {
      if (expected === null) { if (buffer.length < 4) break; expected = buffer.readUInt32LE(0); buffer = buffer.subarray(4); if (expected > 1024 * 1024 || expected < 2) throw new Error('Invalid native message size'); }
      if (buffer.length < expected) break;
      const message = buffer.subarray(0, expected); buffer = buffer.subarray(expected); expected = null;
      pending = pending.then(async () => {
        try {
          const body = JSON.parse(message.toString('utf8'));
          if (!body || !['list', 'get', 'save'].includes(body.action)) throw new Error('Invalid native action');
          const response = await fetch(`http://127.0.0.1:${port}/browser`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(10000) });
          const result = await response.json(); send(result);
        } catch { send({ ok: false, error: 'JJ Vault is unavailable, locked, or rejected this request' }); }
      });
    }
    // Bound outstanding requests rather than accumulating unbounded secret replies.
    await pending;
  }
  await pending;
  if (buffer.length || expected !== null) throw new Error('Incomplete native message');
}
if (isDirectExecution(import.meta.url) && /(?:^|[\\/])native-host\.(?:ts|mjs|cjs)$/.test(process.argv[1])) void runNativeHost().catch(() => { process.stderr.write('JJ Vault native host rejected the connection. Check pairing and file permissions.\n'); process.exitCode = 1; });
