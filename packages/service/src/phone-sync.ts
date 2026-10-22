import { createHash, createPrivateKey, createPublicKey, randomBytes, timingSafeEqual, X509Certificate } from 'node:crypto';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { hostname, networkInterfaces } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { VaultEngine } from '../../core/src/index.ts';
import { syncVault } from './clients.ts';
import { atomicOwnerWrite, randomToken, readOwnerFile, requireStrongToken, tokenEqual } from './security.ts';
import { startSyncServer, type PairingLease } from './sync-server.ts';

const executeFile = promisify(execFile);
export interface PhonePairing {
  type: 'jjvault-pairing'; version: 1; url: string; name: string; certificate: string; nonce: string; vaultId: string; expiresAt: string;
}
export interface PhoneSyncStatus {
  enabled: boolean; running: boolean; paired: boolean; url?: string; name?: string; lastSyncAt?: string; lastError?: string; lastErrorCode?: string; revision?: number; vaultId?: string;
}
interface Config { version: 1; enabled: boolean; pairedAt?: string; }
export interface PhoneSyncOptions {
  /** Test injection and explicit owner configuration only. Never accepted through MCP. */
  httpPort?: number; tlsPort?: number; host?: string; hostname?: string; addresses?: () => string[]; now?: () => number; intervalMs?: number; writeRelay?: (file: string, data: string) => Promise<void>;
}
export interface PhoneSyncManager {
  status(): PhoneSyncStatus; startPairing(): Promise<PhonePairing>; cancelPairing(): void;
  syncNow(): Promise<PhoneSyncStatus>; poll(): Promise<PhoneSyncStatus>; disable(): Promise<void>; close(): Promise<void>; stop(): Promise<void>;
}
function privateIPv4(value: string): boolean {
  const parts = value.split('.').map(Number); if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return parts[0] === 10 || parts[0] === 192 && parts[1] === 168 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31 || parts[0] === 169 && parts[1] === 254;
}
function lanAddresses(): string[] {
  return [...new Set(Object.entries(networkInterfaces()).filter(([name]) => /^(en|eth)\d+$/.test(name)).flatMap(([, entries]) => (entries || []).filter(entry => !entry.internal && entry.family === 'IPv4' && privateIPv4(entry.address)).map(entry => entry.address)))];
}
async function localHostname(): Promise<string> {
  try { const { stdout } = await executeFile('/usr/sbin/scutil', ['--get', 'LocalHostName'], { timeout: 3000, maxBuffer: 4096 }); const name = stdout.trim(); if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(name)) return name + '.local'; } catch {}
  const name = hostname().split('.')[0].replace(/[^a-z0-9-]/gi, '').slice(0, 63); if (!name) throw new Error('A local Mac hostname is required'); return name + '.local';
}
async function privateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o7777) !== 0o700 || process.getuid && info.uid !== process.getuid()) throw new Error('Phone sync requires an owner directory with mode 0700');
}
async function ensurePrivateDirectory(directory: string): Promise<void> {
  try { await privateDirectory(directory); } catch (error: any) {
    if (error.code !== 'EEXIST') throw error;
    const info = await lstat(directory); if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o7777) !== 0o700 || process.getuid && info.uid !== process.getuid()) throw new Error('Phone sync requires an owner directory with mode 0700');
  }
}
async function privateFile(path: string): Promise<string> {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o7777) !== 0o600 || process.getuid && info.uid !== process.getuid()) throw new Error('Phone sync files must be private owner files');
  return readOwnerFile(path);
}
/** Validate the generated identity without trusting arbitrary certificates or ignoring hostname and validity. */
export function validatePhoneCertificate(certPEM: string, keyPEM: string, name: string, addresses: string[], now = Date.now()): X509Certificate {
  const failed = (stage: string) => Object.assign(new Error('Invalid phone sync certificate'), { code: 'PHONE_CERTIFICATE_' + stage });
  let cert: X509Certificate;
  try { cert = new X509Certificate(certPEM); } catch { throw failed('PARSE'); }
  if (Date.parse(cert.validFrom) > now || Date.parse(cert.validTo) <= now) throw failed('DATE');
  try { if (!cert.checkHost(name)) throw failed('HOST'); } catch { throw failed('HOST'); }
  try { if (addresses.some(address => !cert.checkIP(address))) throw failed('IP'); } catch { throw failed('IP'); }
  try { if (!cert.verify(cert.publicKey)) throw failed('SIGNATURE'); } catch { throw failed('SIGNATURE'); }
  let expected: Buffer; let actual: Buffer;
  try { expected = cert.publicKey.export({ type: 'spki', format: 'der' }) as Buffer; actual = createPublicKey(createPrivateKey(keyPEM)).export({ type: 'spki', format: 'der' }) as Buffer; } catch { throw failed('KEY_PARSE'); }
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw failed('KEY_MATCH');
  return cert;
}
async function certificateFiles(directory: string, name: string, addresses: string[], regenerate: boolean): Promise<{ key: string; cert: string; certificate: string; regenerated: boolean }> {
  const certFile = join(directory, 'certificate.pem'); const keyFile = join(directory, 'private-key.pem');
  try {
    const [cert, key] = await Promise.all([privateFile(certFile), privateFile(keyFile)]); const leaf = validatePhoneCertificate(cert, key, name, addresses);
    if (Date.parse(leaf.validTo) - Date.now() < 7 * 86400000) throw new Error('Certificate needs renewal');
    return { key, cert, certificate: leaf.raw.toString('base64'), regenerated: false };
  } catch (error: any) { if (!regenerate) throw error; }
  const temp = await mkdtemp(join(directory, 'certificate-')); await chmod(temp, 0o700);
  let certificateStage = 'configuration';
  try {
    const configuration = ['[req]', 'distinguished_name=dn', 'prompt=no', 'x509_extensions=server', '[dn]', `CN=${name.slice(0,64)}`, '[server]', 'basicConstraints=critical,CA:FALSE', 'keyUsage=critical,digitalSignature,keyEncipherment', 'extendedKeyUsage=serverAuth', `subjectAltName=DNS:${name},${addresses.map(address => 'IP:' + address).join(',')}`, ''].join('\n');
    const conf = join(temp, 'openssl.cnf'); const keyPath = join(temp, 'key.pem'); const certPath = join(temp, 'cert.pem'); await atomicOwnerWrite(conf, configuration);
    certificateStage = 'openssl';
    await executeFile('/usr/bin/openssl', ['req', '-new', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365', '-config', conf, '-keyout', keyPath, '-out', certPath], { timeout: 15000, maxBuffer: 16384 });
    certificateStage = 'read';
    await chmod(keyPath, 0o600); await chmod(certPath, 0o600);
    const [key, cert] = await Promise.all([privateFile(keyPath), privateFile(certPath)]); const leaf = (() => { certificateStage = 'validation'; return validatePhoneCertificate(cert, key, name, addresses); })();
    certificateStage = 'save';
    await atomicOwnerWrite(keyFile, key); await atomicOwnerWrite(certFile, cert); return { key, cert, certificate: leaf.raw.toString('base64'), regenerated: true };
  } catch (error: any) { throw Object.assign(new Error('Unable to create the local phone sync certificate'), { code: typeof error?.code === 'string' && /^PHONE_CERTIFICATE_[A-Z_]+$/.test(error.code) ? error.code : 'PHONE_CERTIFICATE_' + certificateStage.toUpperCase() }); }
  finally { await rm(temp, { recursive: true, force: true }); }
}
/** Hash content locally. Activity, token records, quota counters, and revision never trigger uploads. */
export function phoneSyncContentFingerprint(engine: VaultEngine): string {
  const data = engine.data(); return createHash('sha256').update(JSON.stringify({ vaults: data.vaults, items: data.items, travelMode: data.settings.travelMode })).digest('hex');
}
/** Disabled by default. Construction never enables a listener or generates a certificate. */
export async function createPhoneSyncManager(directory: string, engine: VaultEngine, options: PhoneSyncOptions = {}): Promise<PhoneSyncManager> {
  const folder = join(directory, 'phone-sync'); const configPath = join(folder, 'config.json'); const tokenPath = join(folder, 'relay-token');
  let config: Config = { version: 1, enabled: false }; let state: PhoneSyncStatus = { enabled: false, running: false, paired: false };
  let relay: Awaited<ReturnType<typeof startSyncServer>> | undefined; let token: string | undefined; let identity: Awaited<ReturnType<typeof certificateFiles>> | undefined;
  let pairingGeneration = 0;
  let pending: { nonce: string; expires: number; session: number; vaultId: string } | undefined; let timer: NodeJS.Timeout | undefined; let syncTask: Promise<PhoneSyncStatus> | undefined; let startup: Promise<void> | undefined;
  let networkSignature: string | undefined;
  let configWrites: Promise<void> = Promise.resolve();
  let lastFingerprint: string | undefined; let lastRevision: number | undefined; const now = options.now || Date.now;
  const snapshot = () => ({ ...state });
  const cancelPairing = () => { pending = undefined; pairingGeneration++; };
  async function saveConfig() { const value = JSON.stringify(config); const task = configWrites.then(() => atomicOwnerWrite(configPath, value)); configWrites = task.catch(() => {}); return task; }
  function consumeNonce(value: string): PairingLease | false {
    if (!pending || now() >= pending.expires || engine.status().locked || engine.sessionVersion() !== pending.session || !/^[A-Za-z0-9_-]{43}$/.test(value) || !tokenEqual(value, pending.nonce)) return false;
    const consumed = pending; const attempt = pairingGeneration; pending = undefined;
    return {
      vaultId: consumed.vaultId,
      valid: () => config.enabled && now() < consumed.expires && !engine.status().locked && engine.sessionVersion() === consumed.session && pairingGeneration === attempt,
      issued() {
        state.paired = true; config.pairedAt = new Date(now()).toISOString();
        void saveConfig().catch(() => { state.lastError = 'Unable to save phone pairing status'; });
        void engine.record('phone.paired').catch(() => {});
      }
    };
  }
  async function start(regenerate: boolean) {
    if (startup) return startup;
    if (relay && !regenerate) return;
    let stage = 'directory';
    startup = (async () => {
      await ensurePrivateDirectory(folder);
      stage = 'network';
      const addresses = [...new Set((options.addresses || lanAddresses)())].sort((a,b) => Number(a.startsWith('169.254.')) - Number(b.startsWith('169.254.')));
      if (!addresses.length || addresses.some(address => !/^\d{1,3}(\.\d{1,3}){3}$/.test(address))) throw new Error('Connect this Mac to your local network before pairing');
      const name = (options.hostname || await localHostname()).toLowerCase(); if (!/^[a-z0-9](?:[a-z0-9.-]{0,250}[a-z0-9])?$/i.test(name)) throw new Error('A valid local hostname is required');
      const host = options.host || addresses[0]; if (!addresses.includes(host)) throw new Error('Phone sync must bind to this Mac network address');
      const desiredNetwork = JSON.stringify({ name, host, addresses: [...addresses].sort() });
      if (relay && networkSignature === desiredNetwork && identity && Date.parse(new X509Certificate(identity.cert).validTo) - Date.now() > 7 * 86400000) return;
      if (relay) await shutdownRelay();
      stage = 'certificate';
      identity = await certificateFiles(folder, name, addresses, regenerate);
      stage = 'token';
      try { token = (await privateFile(tokenPath)).trim(); requireStrongToken(token, 'Phone relay token'); }
      catch (error: any) { if (error.code !== 'ENOENT') throw error; token = randomToken(); await atomicOwnerWrite(tokenPath, token + '\n'); }
      if (identity.regenerated && config.pairedAt) { token = randomToken(); await atomicOwnerWrite(tokenPath, token + '\n'); delete config.pairedAt; state.paired = false; await saveConfig(); }
      stage = 'listener';
      relay = await startSyncServer({ token: token!, file: join(folder, 'relay.json'), port: options.httpPort ?? Number(process.env.JJ_VAULT_PHONE_LOOPBACK_PORT ?? 17374), host: '127.0.0.1', tls: { cert: identity.cert, key: identity.key, port: options.tlsPort ?? Number(process.env.JJ_VAULT_PHONE_HTTPS_PORT ?? 17375), host, names: [name, ...addresses] }, consumePairingNonce: consumeNonce, ...(options.writeRelay ? { writeState: options.writeRelay } : {}) });
      networkSignature = desiredNetwork;
      state.running = true; state.enabled = config.enabled; state.paired = !!config.pairedAt; state.name = name.replace(/\.local$/i, ''); state.url = `https://${name}:${relay.tlsPort}`; delete state.lastError; delete state.lastErrorCode;
      const interval = options.intervalMs ?? 10000; if (interval > 0) { timer = setInterval(() => { if (!engine.status().locked) void performSync(false).catch(() => {}); }, interval); timer.unref(); }
    })().catch(error => { state.lastErrorCode = typeof error?.code === 'string' && /^PHONE_[A-Z_]+$/.test(error.code) ? error.code : 'PHONE_START_' + stage.toUpperCase(); throw error; }).finally(() => { startup = undefined; });
    return startup;
  }
  async function performSync(force: boolean): Promise<PhoneSyncStatus> {
    if (syncTask) return syncTask;
    syncTask = (async () => {
      if (engine.status().locked) throw new Error('Vault is locked');
      if (!relay || !token) throw new Error('Enable phone sync before syncing');
      const base = `http://127.0.0.1:${relay.port}`; const fingerprint = phoneSyncContentFingerprint(engine);
      const response = await fetch(base + '/status', { headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (!response.ok) throw new Error('Phone sync status is unavailable'); const remote = await response.json() as { revision: number; vaultId: string | null };
      if (!Number.isSafeInteger(remote.revision) || remote.revision < 0) throw new Error('Invalid phone sync status');
      if (!state.vaultId) state.vaultId = (await engine.exportForSync()).id;
      if (remote.vaultId && remote.vaultId !== state.vaultId) throw new Error('This phone relay belongs to another vault');
      if (!force && fingerprint === lastFingerprint && remote.revision === lastRevision) return snapshot();
      const result = await syncVault(engine, { url: base, token });
      // Preserve the preflight fingerprint: edits arriving during network awaits must trigger another poll.
      lastFingerprint = fingerprint; lastRevision = result.revision; state.revision = result.revision; state.lastSyncAt = new Date(now()).toISOString(); delete state.lastError; return snapshot();
    })().catch(error => { state.lastError = error instanceof Error && error.message === 'Vault is locked' ? 'Vault is locked' : 'Phone sync is unavailable. Check the Mac network and phone connection.'; throw new Error(state.lastError); }).finally(() => { syncTask = undefined; });
    return syncTask;
  }
  async function shutdownRelay() {
    if (timer) clearInterval(timer); timer = undefined;
    if (syncTask) await syncTask.catch(() => {});
    const active = relay; relay = undefined; state.running = false;
    if (active) await active.close(); identity = undefined; token = undefined; networkSignature = undefined;
  }
  async function close() {
    cancelPairing(); if (timer) clearInterval(timer); timer = undefined;
    if (startup) await startup.catch(() => {});
    await shutdownRelay(); await configWrites;
  }
  const manager: PhoneSyncManager = {
    status: snapshot, cancelPairing,
    async startPairing() {
      if (engine.status().locked) throw new Error('Vault is locked');
      const session = engine.sessionVersion(); const attempt = ++pairingGeneration; pending = undefined;
      config.enabled = true; state.enabled = true;
      try { await start(true); await saveConfig(); await performSync(true); }
      catch (error) { state.lastError = error instanceof Error && error.message === 'Vault is locked' ? 'Vault is locked' : 'Unable to start local phone sync. Check this Mac network and private files.'; throw new Error(state.lastError); }
      if (engine.status().locked || session !== engine.sessionVersion()) throw new Error('Vault is locked');
      if (attempt !== pairingGeneration) throw new Error('Phone pairing was cancelled');
      const envelope = await engine.exportForSync();
      if (engine.status().locked || session !== engine.sessionVersion()) throw new Error('Vault is locked');
      if (attempt !== pairingGeneration) throw new Error('Phone pairing was cancelled'); const nonce = randomBytes(32).toString('base64url'); const expires = now() + 120000; pending = { nonce, expires, session: engine.sessionVersion(), vaultId: envelope.id };
      return { type: 'jjvault-pairing', version: 1, url: state.url!, name: state.name!, certificate: identity!.certificate, nonce, vaultId: envelope.id, expiresAt: new Date(expires).toISOString() };
    },
    syncNow: () => performSync(true), poll: () => performSync(false), close, stop: close,
    async disable() { config.enabled = false; delete config.pairedAt; state.enabled = false; state.paired = false; await close(); await ensurePrivateDirectory(folder); await atomicOwnerWrite(tokenPath, randomToken() + '\n'); await saveConfig(); lastFingerprint = undefined; lastRevision = undefined; }
  };
  try {
    const info = await lstat(folder); if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o7777) !== 0o700 || process.getuid && info.uid !== process.getuid()) throw new Error();
    const stored = JSON.parse(await privateFile(configPath)); if (stored.version !== 1 || typeof stored.enabled !== 'boolean' || stored.pairedAt !== undefined && (typeof stored.pairedAt !== 'string' || !Number.isFinite(Date.parse(stored.pairedAt)))) throw new Error();
    config = { version: 1, enabled: stored.enabled, ...(stored.pairedAt ? { pairedAt: stored.pairedAt } : {}) }; state.enabled = config.enabled; state.paired = !!config.pairedAt;
    if (config.enabled) await start(false);
  } catch (error: any) { if (error.code !== 'ENOENT') state.lastError = 'Unable to restore phone sync. Pair your phone again from this Mac.'; }
  return manager;
}
