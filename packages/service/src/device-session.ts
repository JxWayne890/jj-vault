import {
  closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readSync, renameSync, unlinkSync, writeFileSync, type Stats,
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { join, resolve } from 'node:path';
import type { Envelope } from '../../core/src/types.ts';
import type { DeviceSecretEncryption } from './device-secret.ts';

export interface DeviceSessionStore {
  /** Persist a session key only when the operating system can protect it. */
  remember(identity: string, key: Uint8Array): boolean;
  /** The caller owns the returned buffer and must clear it after use. */
  recall(identity: string): Buffer | undefined;
  /** Forget this device's session without changing the encrypted vault. */
  forget(): boolean;
}

const CACHE_FILE = 'device-session.json';
const MAX_FILE_BYTES = 64 * 1024;
const MAX_PLAIN_BYTES = 1024;
const ID_PATTERN = /^[a-zA-Z0-9-]{8,80}$/u;
const IDENTITY_PATTERN = /^[a-zA-Z0-9-]{8,80}:[a-f0-9]{64}$/u;

/**
 * Vault edits change IV and ciphertext, but the root key identity stays stable.
 * Binding all KDF inputs also rejects a different key under a reused vault ID.
 */
export function deviceSessionIdentity(envelope: Envelope): string {
  const kdf = envelope?.kdf;
  if (envelope?.format !== 'jjvault' || envelope.version !== 1
    || typeof envelope.id !== 'string' || !ID_PATTERN.test(envelope.id)
    || kdf?.algorithm !== 'argon2id' || typeof kdf.salt !== 'string'
    || Buffer.from(kdf.salt, 'base64').length !== 16
    || Buffer.from(kdf.salt, 'base64').toString('base64') !== kdf.salt
    || !Number.isInteger(kdf.memoryKiB) || kdf.memoryKiB < 65536 || kdf.memoryKiB > 262144
    || !Number.isInteger(kdf.iterations) || kdf.iterations < 3 || kdf.iterations > 10
    || kdf.parallelism !== 1) throw new Error('Invalid vault session identity');
  const canonical = JSON.stringify([
    envelope.format, envelope.version, envelope.id, kdf.algorithm,
    kdf.salt, kdf.memoryKiB, kdf.iterations, kdf.parallelism,
  ]);
  return `${envelope.id}:${createHash('sha256').update(canonical).digest('hex')}`;
}

function validIdentity(value: unknown): value is string {
  return typeof value === 'string' && IDENTITY_PATTERN.test(value);
}

function missing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

function ownedWithMode(info: Stats, mode: number): boolean {
  const uid = process.getuid?.();
  return uid !== undefined && info.uid === uid && (info.mode & 0o7777) === mode;
}

function exactKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

/**
 * Optional device resume uses OS protected ciphertext only. Every failure is a
 * cache miss. Neither a master password nor a Secret Key belongs in this file.
 */
export function createDeviceSessionStore(root: string, adapter: DeviceSecretEncryption): DeviceSessionStore {
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
      return info.isDirectory() && !info.isSymbolicLink() && ownedWithMode(info, 0o700);
    } catch { return false; }
  }

  function safeExistingFile(): boolean {
    try {
      const info = lstatSync(file);
      return info.isFile() && !info.isSymbolicLink() && info.nlink === 1
        && ownedWithMode(info, 0o600) && info.size > 0 && info.size <= MAX_FILE_BYTES;
    } catch (error) { return missing(error); }
  }

  return {
    remember(identity, key) {
      let temporary: string | undefined;
      let descriptor: number | undefined;
      try {
        if (!validIdentity(identity) || !(key instanceof Uint8Array) || key.byteLength !== 32
          || !adapter.isEncryptionAvailable() || !safeDirectory(true) || !safeExistingFile()) return false;
        const payload = JSON.stringify({ version: 1, identity, key: Buffer.from(key).toString('base64') });
        if (Buffer.byteLength(payload) > MAX_PLAIN_BYTES) return false;
        const ciphertext = adapter.encryptString(payload);
        if (!Buffer.isBuffer(ciphertext) || ciphertext.length === 0 || ciphertext.length > MAX_FILE_BYTES / 2) return false;
        const serialized = JSON.stringify({ version: 1, identity, ciphertext: ciphertext.toString('base64') });
        if (Buffer.byteLength(serialized) > MAX_FILE_BYTES) return false;
        temporary = join(directory, `.device-session-${randomBytes(16).toString('hex')}.tmp`);
        descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        writeFileSync(descriptor, serialized, { encoding: 'utf8' });
        fchmodSync(descriptor, 0o600);
        fsyncSync(descriptor);
        closeSync(descriptor);
        descriptor = undefined;
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

    recall(identity) {
      let descriptor: number | undefined;
      let key: Buffer | undefined;
      try {
        if (!validIdentity(identity) || !adapter.isEncryptionAvailable() || !safeDirectory(false)) return undefined;
        descriptor = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        const info = fstatSync(descriptor);
        if (!info.isFile() || info.nlink !== 1 || !ownedWithMode(info, 0o600)
          || info.size === 0 || info.size > MAX_FILE_BYTES) return undefined;
        // Bound the read itself, including a file grown after fstat by another process.
        const bytes = Buffer.alloc(MAX_FILE_BYTES + 1);
        let length = 0;
        while (length < bytes.length) {
          const count = readSync(descriptor, bytes, length, bytes.length - length, length);
          if (count === 0) break;
          length += count;
        }
        if (length > MAX_FILE_BYTES) return undefined;
        const envelope: unknown = JSON.parse(bytes.subarray(0, length).toString('utf8'));
        if (!exactKeys(envelope, ['version', 'identity', 'ciphertext']) || envelope.version !== 1
          || envelope.identity !== identity || typeof envelope.ciphertext !== 'string') return undefined;
        const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
        if (ciphertext.length === 0 || ciphertext.toString('base64') !== envelope.ciphertext) return undefined;
        const plaintext = adapter.decryptString(ciphertext);
        if (typeof plaintext !== 'string' || Buffer.byteLength(plaintext) > MAX_PLAIN_BYTES) return undefined;
        const payload: unknown = JSON.parse(plaintext);
        if (!exactKeys(payload, ['version', 'identity', 'key']) || payload.version !== 1
          || payload.identity !== identity || typeof payload.key !== 'string') return undefined;
        key = Buffer.from(payload.key, 'base64');
        if (key.length !== 32 || key.toString('base64') !== payload.key) { key.fill(0); return undefined; }
        const recalled = key;
        key = undefined;
        return recalled;
      } catch { return undefined; }
      finally {
        key?.fill(0);
        if (descriptor !== undefined) { try { closeSync(descriptor); } catch {} }
      }
    },

    forget() {
      try {
        if (!safeDirectory(false)) {
          try { lstatSync(directory); return false; }
          catch (error) { return missing(error); }
        }
        let info: Stats;
        try { info = lstatSync(file); }
        catch (error) { return missing(error); }
        if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || !ownedWithMode(info, 0o600)) return false;
        unlinkSync(file);
        return true;
      } catch { return false; }
    },
  };
}
