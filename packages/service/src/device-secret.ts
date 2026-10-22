import {
  closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync, type Stats,
} from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join, resolve } from 'node:path';

/** Electron safeStorage is provided by the main process, after app readiness. */
export interface DeviceSecretEncryption {
  isEncryptionAvailable(): boolean;
  encryptString(plainText: string): Buffer;
  decryptString(cipherText: Buffer): string;
}

export interface DeviceSecretStore {
  /** Returns false when the OS cannot protect the key or the cache is unsafe. */
  remember(vaultId: string, secretKey: string): boolean;
  /** Never returns a key for another vault, damaged data, or unsafe paths. */
  read(vaultId: string): string | null;
  /** Removes this device's remembered key, without touching vault contents. */
  forget(): boolean;
}

const MAX_FILE_BYTES = 64 * 1024;
const MAX_PLAIN_BYTES = 1024;
const CACHE_FILE = 'device-secret.json';

function validVaultId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256
    && value.trim() === value && !/[\u0000-\u001f\u007f]/u.test(value);
}

function validSecretKey(value: unknown): value is string {
  if (typeof value !== 'string' || !/^JJ1\.[A-Za-z0-9_-]{43}$/u.test(value)) return false;
  const bytes = Buffer.from(value.slice(4), 'base64url');
  return bytes.length === 32 && bytes.toString('base64url') === value.slice(4);
}

function missing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

function ownedAndPrivate(info: Stats): boolean {
  const uid = process.getuid?.();
  return uid !== undefined && info.uid === uid && (info.mode & 0o077) === 0;
}

function exactKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

/**
 * Remembers only the Secret Key using OS backed encryption. The master password
 * and vault encryption key are never accepted by this API or written to disk.
 * All failures are cache misses, so optional remembering cannot block an unlock.
 */
export function createDeviceSecretStore(root: string, adapter: DeviceSecretEncryption): DeviceSecretStore {
  const directory = resolve(root);
  const file = join(directory, CACHE_FILE);

  function safeDirectory(create: boolean): boolean {
    try {
      if (create) {
        try { mkdirSync(directory, { mode: 0o700 }); }
        catch (error) {
          if (!(typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST')) throw error;
        }
      }
      const info = lstatSync(directory);
      return info.isDirectory() && !info.isSymbolicLink() && ownedAndPrivate(info);
    } catch { return false; }
  }

  function safeExistingFile(): boolean {
    try {
      const info = lstatSync(file);
      return info.isFile() && !info.isSymbolicLink() && info.nlink === 1
        && ownedAndPrivate(info) && info.size > 0 && info.size <= MAX_FILE_BYTES;
    } catch (error) { return missing(error); }
  }

  return {
    remember(vaultId, secretKey) {
      let temporary: string | undefined;
      let descriptor: number | undefined;
      try {
        if (!validVaultId(vaultId) || !validSecretKey(secretKey) || !adapter.isEncryptionAvailable()) return false;
        if (!safeDirectory(true) || !safeExistingFile()) return false;
        const plainText = JSON.stringify({ version: 1, vaultId, secretKey });
        if (Buffer.byteLength(plainText) > MAX_PLAIN_BYTES) return false;
        const protectedBytes = adapter.encryptString(plainText);
        if (!Buffer.isBuffer(protectedBytes) || protectedBytes.length === 0 || protectedBytes.length > MAX_FILE_BYTES / 2) return false;
        const serialized = JSON.stringify({ version: 1, vaultId, ciphertext: protectedBytes.toString('base64') });
        if (Buffer.byteLength(serialized) > MAX_FILE_BYTES) return false;
        temporary = join(directory, `.device-secret-${randomBytes(16).toString('hex')}.tmp`);
        descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        writeFileSync(descriptor, serialized, { encoding: 'utf8' });
        fchmodSync(descriptor, 0o600);
        fsyncSync(descriptor);
        closeSync(descriptor);
        descriptor = undefined;
        // Recheck the destination just before replacement. Never follow links.
        if (!safeDirectory(false) || !safeExistingFile()) return false;
        renameSync(temporary, file);
        temporary = undefined;
        return true;
      } catch { return false; }
      finally {
        if (descriptor !== undefined) { try { closeSync(descriptor); } catch {} }
        if (temporary !== undefined) { try { unlinkSync(temporary); } catch {} }
      }
    },

    read(vaultId) {
      let descriptor: number | undefined;
      try {
        if (!validVaultId(vaultId) || !adapter.isEncryptionAvailable() || !safeDirectory(false)) return null;
        descriptor = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
        const info = fstatSync(descriptor);
        if (!info.isFile() || info.nlink !== 1 || !ownedAndPrivate(info) || info.size === 0 || info.size > MAX_FILE_BYTES) return null;
        const bytes = readFileSync(descriptor);
        if (bytes.length > MAX_FILE_BYTES) return null;
        const envelope: unknown = JSON.parse(bytes.toString('utf8'));
        if (!exactKeys(envelope, ['version', 'vaultId', 'ciphertext']) || envelope.version !== 1
          || envelope.vaultId !== vaultId || typeof envelope.ciphertext !== 'string') return null;
        const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
        if (ciphertext.length === 0 || ciphertext.toString('base64') !== envelope.ciphertext) return null;
        const plainText = adapter.decryptString(ciphertext);
        if (typeof plainText !== 'string' || Buffer.byteLength(plainText) > MAX_PLAIN_BYTES) return null;
        const payload: unknown = JSON.parse(plainText);
        if (!exactKeys(payload, ['version', 'vaultId', 'secretKey']) || payload.version !== 1
          || payload.vaultId !== vaultId || !validSecretKey(payload.secretKey)) return null;
        return payload.secretKey;
      } catch { return null; }
      finally { if (descriptor !== undefined) { try { closeSync(descriptor); } catch {} } }
    },

    forget() {
      try {
        if (!safeDirectory(false)) {
          try { lstatSync(directory); return false; }
          catch (error) { return missing(error); }
        }
        // Damaged ciphertext can still be forgotten, but unsafe files cannot.
        let info: Stats;
        try { info = lstatSync(file); }
        catch (error) { return missing(error); }
        if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || !ownedAndPrivate(info)) return false;
        unlinkSync(file);
        return true;
      } catch { return false; }
    },
  };
}
