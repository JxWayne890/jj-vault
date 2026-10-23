import {
  closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readSync, renameSync, unlinkSync, writeFileSync, type Stats,
} from 'node:fs';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { join, resolve } from 'node:path';
import type { DeviceSecretEncryption } from './device-secret.ts';

export interface DevicePinStatus {
  enabled: boolean;
  available: boolean;
  retryAt?: number;
}

export interface DevicePinStore {
  status(identity: string): DevicePinStatus;
  /** Call only after the owner has authorized changing device unlock settings. */
  set(identity: string, pin: string, key: Uint8Array): void;
  /** The caller owns the returned key and must clear it after use. */
  unlock(identity: string, pin: string): Buffer;
  /** Call only after the owner has authorized removing device unlock settings. */
  remove(): void;
}

interface PinPayload {
  version: 1;
  identity: string;
  salt: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  failures: number;
  retryAt: number;
}

const FILE_NAME = 'device-pin.json';
const MAX_FILE_BYTES = 64 * 1024;
const MAX_PLAIN_BYTES = 2048;
const MAX_FAILURES = 1_000_000;
const IDENTITY_PATTERN = /^[a-zA-Z0-9-]{8,80}:[a-f0-9]{64}$/u;
const PIN_PATTERN = /^[0-9]{4,6}$/u;
const UNAVAILABLE = 'PIN unlock is unavailable. Unlock with your master password.';
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function validIdentity(value: unknown): value is string {
  return typeof value === 'string' && IDENTITY_PATTERN.test(value);
}

function validPin(value: unknown): value is string {
  return typeof value === 'string' && PIN_PATTERN.test(value);
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

function encodedBytes(value: unknown, length: number): value is string {
  if (typeof value !== 'string' || value.length !== Math.ceil(length / 3) * 4) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === length && bytes.toString('base64') === value;
}

function validPayload(value: unknown): value is PinPayload {
  return exactKeys(value, ['version', 'identity', 'salt', 'nonce', 'ciphertext', 'tag', 'failures', 'retryAt'])
    && value.version === 1 && validIdentity(value.identity)
    && encodedBytes(value.salt, 16) && encodedBytes(value.nonce, 12)
    && encodedBytes(value.ciphertext, 32) && encodedBytes(value.tag, 16)
    && Number.isSafeInteger(value.failures) && (value.failures as number) >= 0 && (value.failures as number) <= MAX_FAILURES
    && Number.isSafeInteger(value.retryAt) && (value.retryAt as number) >= 0
    && ((value.failures as number) < 5 ? value.retryAt === 0 : (value.retryAt as number) > 0);
}

function aad(identity: string): Buffer {
  return Buffer.from(JSON.stringify(['jjvault-device-pin', 1, identity]), 'utf8');
}

function derive(pin: string, salt: string): Buffer {
  const bytes = Buffer.from(pin, 'ascii');
  try { return scryptSync(bytes, Buffer.from(salt, 'base64'), 32, SCRYPT); }
  finally { bytes.fill(0); }
}

/** Five failures start a 30 second delay, doubling per failure to one hour. */
function cooldown(failures: number): number {
  return failures < 5 ? 0 : Math.min(3_600_000, 30_000 * 2 ** Math.min(failures - 5, 7));
}

/**
 * A device PIN wraps a root key inside OS protected storage. The short PIN is
 * never a vault encryption secret or recovery credential. Corrupt or unsafe
 * existing storage remains enabled but unavailable, so it cannot bypass PIN
 * requirements through an automatic session resume.
 */
export function createDevicePinStore(root: string, adapter: DeviceSecretEncryption, now: () => number = Date.now): DevicePinStore {
  const directory = resolve(root);
  const file = join(directory, FILE_NAME);

  function available(): boolean {
    try { return adapter.isEncryptionAvailable() === true; }
    catch { return false; }
  }

  function timestamp(): number {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - 3_600_000) throw new Error(UNAVAILABLE);
    return value;
  }

  function directoryState(create: boolean): 'missing' | 'safe' {
    if (create) {
      try { mkdirSync(directory, { mode: 0o700 }); }
      catch (error) {
        if (!(typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST')) throw error;
      }
    }
    let info: Stats;
    try { info = lstatSync(directory); }
    catch (error) { if (missing(error)) return 'missing'; throw error; }
    if (!info.isDirectory() || info.isSymbolicLink() || !ownedWithMode(info, 0o700)) throw new Error(UNAVAILABLE);
    return 'safe';
  }

  function fileState(): 'missing' | 'safe' {
    let info: Stats;
    try { info = lstatSync(file); }
    catch (error) { if (missing(error)) return 'missing'; throw error; }
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || !ownedWithMode(info, 0o600)) throw new Error(UNAVAILABLE);
    return 'safe';
  }

  function read(): PinPayload | undefined {
    let descriptor: number | undefined;
    try {
      if (directoryState(false) === 'missing' || fileState() === 'missing') return undefined;
      if (!available()) throw new Error(UNAVAILABLE);
      descriptor = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const info = fstatSync(descriptor);
      if (!info.isFile() || info.nlink !== 1 || !ownedWithMode(info, 0o600)
        || info.size === 0 || info.size > MAX_FILE_BYTES) throw new Error(UNAVAILABLE);
      const bytes = Buffer.alloc(MAX_FILE_BYTES + 1);
      let length = 0;
      while (length < bytes.length) {
        const count = readSync(descriptor, bytes, length, bytes.length - length, length);
        if (count === 0) break;
        length += count;
      }
      if (length > MAX_FILE_BYTES) throw new Error(UNAVAILABLE);
      const envelope: unknown = JSON.parse(bytes.subarray(0, length).toString('utf8'));
      if (!exactKeys(envelope, ['version', 'identity', 'ciphertext']) || envelope.version !== 1
        || !validIdentity(envelope.identity) || typeof envelope.ciphertext !== 'string'
        || envelope.ciphertext.length === 0 || envelope.ciphertext.length > MAX_FILE_BYTES / 2 * 4 / 3 + 4) throw new Error(UNAVAILABLE);
      const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
      if (ciphertext.length === 0 || ciphertext.length > MAX_FILE_BYTES / 2
        || ciphertext.toString('base64') !== envelope.ciphertext) throw new Error(UNAVAILABLE);
      const plaintext = adapter.decryptString(ciphertext);
      if (typeof plaintext !== 'string' || Buffer.byteLength(plaintext) > MAX_PLAIN_BYTES) throw new Error(UNAVAILABLE);
      const payload: unknown = JSON.parse(plaintext);
      if (!validPayload(payload) || payload.identity !== envelope.identity) throw new Error(UNAVAILABLE);
      return payload;
    } finally {
      if (descriptor !== undefined) { try { closeSync(descriptor); } catch {} }
    }
  }

  function write(payload: PinPayload): void {
    let temporary: string | undefined;
    let descriptor: number | undefined;
    try {
      if (!available() || directoryState(true) !== 'safe') throw new Error(UNAVAILABLE);
      fileState();
      const ciphertext = adapter.encryptString(JSON.stringify(payload));
      if (!Buffer.isBuffer(ciphertext) || ciphertext.length === 0 || ciphertext.length > MAX_FILE_BYTES / 2) throw new Error(UNAVAILABLE);
      const serialized = JSON.stringify({ version: 1, identity: payload.identity, ciphertext: ciphertext.toString('base64') });
      if (Buffer.byteLength(serialized) > MAX_FILE_BYTES) throw new Error(UNAVAILABLE);
      temporary = join(directory, `.device-pin-${randomBytes(16).toString('hex')}.tmp`);
      descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      writeFileSync(descriptor, serialized, { encoding: 'utf8' });
      fchmodSync(descriptor, 0o600);
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = undefined;
      if (directoryState(false) !== 'safe') throw new Error(UNAVAILABLE);
      fileState();
      renameSync(temporary, file);
      temporary = undefined;
      // Flush the rename before PIN validation so a crash cannot erase a try.
      descriptor = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
      fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) { try { closeSync(descriptor); } catch {} }
      if (temporary !== undefined) { try { unlinkSync(temporary); } catch {} }
    }
  }

  return {
    status(identity) {
      try {
        const payload = read();
        if (!payload) return { enabled: false, available: available() };
        if (!validIdentity(identity)) return { enabled: true, available: false };
        if (payload.identity !== identity) return { enabled: false, available: available() };
        const current = timestamp();
        return { enabled: true, available: true, ...(payload.retryAt > current ? { retryAt: payload.retryAt } : {}) };
      } catch { return { enabled: true, available: false }; }
    },

    set(identity, pin, key) {
      if (!validIdentity(identity)) throw new Error('Invalid vault session identity');
      if (!validPin(pin)) throw new Error('PIN must contain 4 to 6 digits');
      if (!(key instanceof Uint8Array) || key.byteLength !== 32) throw new Error('Invalid vault session key');
      let derived: Buffer | undefined;
      const copiedKey = Buffer.from(key);
      try {
        if (!available()) throw new Error(UNAVAILABLE);
        const salt = randomBytes(16).toString('base64');
        const nonce = randomBytes(12);
        derived = derive(pin, salt);
        const cipher = createCipheriv('aes-256-gcm', derived, nonce);
        cipher.setAAD(aad(identity));
        const ciphertext = Buffer.concat([cipher.update(copiedKey), cipher.final()]);
        write({ version: 1, identity, salt, nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64'), tag: cipher.getAuthTag().toString('base64'), failures: 0, retryAt: 0 });
      } catch { throw new Error(UNAVAILABLE); }
      finally { copiedKey.fill(0); derived?.fill(0); }
    },

    unlock(identity, pin) {
      if (!validIdentity(identity)) throw new Error('Invalid vault session identity');
      if (!validPin(pin)) throw new Error('PIN must contain 4 to 6 digits');
      let payload: PinPayload | undefined;
      try { payload = read(); }
      catch { throw new Error(UNAVAILABLE); }
      if (!payload || payload.identity !== identity) throw new Error('PIN unlock is not enabled for this vault');
      const current = timestamp();
      if (payload.retryAt > current) throw new Error('PIN is temporarily locked. Try again later.');
      const failures = Math.min(MAX_FAILURES, payload.failures + 1);
      const attempted = { ...payload, failures, retryAt: failures >= 5 ? current + cooldown(failures) : 0 };
      try { write(attempted); }
      catch { throw new Error(UNAVAILABLE); }
      let derived: Buffer | undefined;
      let key: Buffer | undefined;
      const parts: Buffer[] = [];
      try {
        derived = derive(pin, payload.salt);
        const decipher = createDecipheriv('aes-256-gcm', derived, Buffer.from(payload.nonce, 'base64'));
        decipher.setAAD(aad(identity));
        decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
        try {
          parts.push(decipher.update(Buffer.from(payload.ciphertext, 'base64')));
          parts.push(decipher.final());
          key = Buffer.concat(parts);
        } catch { throw new Error('Incorrect PIN'); }
        if (key.length !== 32) throw new Error(UNAVAILABLE);
        try { write({ ...payload, failures: 0, retryAt: 0 }); }
        catch { throw new Error(UNAVAILABLE); }
        const result = key;
        key = undefined;
        return result;
      } finally {
        derived?.fill(0);
        key?.fill(0);
        for (const part of parts) part.fill(0);
      }
    },

    remove() {
      try {
        if (directoryState(false) === 'missing' || fileState() === 'missing') return;
        unlinkSync(file);
        const descriptor = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
        try { fsyncSync(descriptor); }
        finally { closeSync(descriptor); }
      } catch { throw new Error('PIN settings could not be removed'); }
    },
  };
}
