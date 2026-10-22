import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createDeviceSessionStore, deviceSessionIdentity } from '../src/device-session.ts';
import type { DeviceSecretEncryption } from '../src/device-secret.ts';
import { VaultEngine } from '../../core/src/engine.ts';
import { newEnvelope } from '../../core/src/crypto.ts';
import type { Envelope } from '../../core/src/types.ts';

const sessionKey = Buffer.alloc(32, 23);
const envelope = newEnvelope();
const identity = deviceSessionIdentity(envelope);

function encryptor(key = randomBytes(32)): DeviceSecretEncryption {
  return {
    isEncryptionAvailable: () => true,
    encryptString(plaintext) {
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, nonce);
      const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      return Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]);
    },
    decryptString(bytes) {
      const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
      decipher.setAuthTag(bytes.subarray(12, 28));
      return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8');
    },
  };
}

function fixture(t: TestContext) {
  const base = mkdtempSync(join(tmpdir(), 'jj-device-session-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const root = join(base, 'vault');
  return { base, root, file: join(root, 'device-session.json') };
}

test('session identity survives edits and binds the vault ID and every key derivation input', () => {
  const edited = structuredClone(envelope);
  edited.iv = randomBytes(12).toString('base64');
  edited.ciphertext = randomBytes(80).toString('base64');
  assert.equal(deviceSessionIdentity(edited), identity);
  for (const changes of [
    { id: crypto.randomUUID() },
    { kdf: { ...envelope.kdf, salt: randomBytes(16).toString('base64') } },
    { kdf: { ...envelope.kdf, memoryKiB: 131072 } },
    { kdf: { ...envelope.kdf, iterations: 4 } },
  ]) assert.notEqual(deviceSessionIdentity({ ...envelope, ...changes }), identity);
  for (const changes of [
    { format: 'other' }, { version: 2 }, { id: '../vault' },
    { kdf: { ...envelope.kdf, algorithm: 'scrypt' } },
    { kdf: { ...envelope.kdf, salt: envelope.kdf.salt + '\n' } },
    { kdf: { ...envelope.kdf, salt: randomBytes(17).toString('base64') } },
    { kdf: { ...envelope.kdf, memoryKiB: 1 } },
    { kdf: { ...envelope.kdf, iterations: 0 } },
    { kdf: { ...envelope.kdf, parallelism: 2 } },
  ]) assert.throws(() => deviceSessionIdentity({ ...envelope, ...changes } as Envelope), /identity/);
});

test('session cache is OS ciphertext, private, persistent, and returns independent key buffers', (t) => {
  const { root, file } = fixture(t);
  const osKey = randomBytes(32);
  const store = createDeviceSessionStore(root, encryptor(osKey));
  const input = Buffer.from(sessionKey);
  assert.equal(store.remember(identity, input), true);
  assert.deepEqual(input, sessionKey);
  const disk = readFileSync(file, 'utf8');
  assert.equal(disk.includes(sessionKey.toString('base64')), false);
  assert.equal(disk.includes('"key"'), false);
  assert.equal(lstatSync(root).mode & 0o777, 0o700);
  assert.equal(lstatSync(file).mode & 0o777, 0o600);
  const recalled = store.recall(identity)!;
  assert.deepEqual(recalled, sessionKey);
  recalled.fill(0);
  assert.deepEqual(store.recall(identity), sessionKey);
  assert.deepEqual(createDeviceSessionStore(root, encryptor(osKey)).recall(identity), sessionKey);
  assert.equal(createDeviceSessionStore(root, encryptor()).recall(identity), undefined);
  assert.deepEqual(readdirSync(root), ['device-session.json']);
});

test('outer and OS encrypted identity must both match, including a replaced salt under the same vault ID', (t) => {
  const { root, file } = fixture(t);
  const store = createDeviceSessionStore(root, encryptor());
  const another = deviceSessionIdentity({ ...envelope, kdf: { ...envelope.kdf, salt: randomBytes(16).toString('base64') } });
  assert.equal(store.remember(identity, sessionKey), true);
  assert.equal(store.recall(another), undefined);
  const saved = JSON.parse(readFileSync(file, 'utf8'));
  saved.identity = another;
  writeFileSync(file, JSON.stringify(saved));
  assert.equal(store.recall(another), undefined);
  assert.equal(store.recall(identity), undefined);
});

test('tampered ciphertext and invalid or oversized envelopes cannot resume', (t) => {
  const { root, file } = fixture(t);
  const store = createDeviceSessionStore(root, encryptor());
  assert.equal(store.remember(identity, sessionKey), true);
  const saved = readFileSync(file);
  const changed = JSON.parse(saved.toString('utf8'));
  const damaged = Buffer.from(changed.ciphertext, 'base64');
  damaged[damaged.length - 1] ^= 1;
  changed.ciphertext = damaged.toString('base64');
  writeFileSync(file, JSON.stringify(changed));
  assert.equal(store.recall(identity), undefined);
  for (const bytes of [Buffer.from('{broken'), Buffer.from('null'), Buffer.alloc(65537, 65), Buffer.alloc(0)]) {
    writeFileSync(file, bytes);
    assert.equal(store.recall(identity), undefined);
  }
  for (const changes of [{ version: 2 }, { extra: true }, { ciphertext: '' }, { ciphertext: JSON.parse(saved.toString()).ciphertext + '\n' }]) {
    writeFileSync(file, JSON.stringify({ ...JSON.parse(saved.toString()), ...changes }));
    assert.equal(store.recall(identity), undefined);
  }
});

test('decrypted content requires exact fields, identity, version, and canonical 32 byte key encoding', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  const store = createDeviceSessionStore(root, adapter);
  mkdirSync(root, { mode: 0o700 });
  for (const payload of [
    { version: 2, identity, key: sessionKey.toString('base64') },
    { version: 1, identity: 'other', key: sessionKey.toString('base64') },
    { version: 1, identity, key: Buffer.alloc(31).toString('base64') },
    { version: 1, identity, key: Buffer.alloc(33).toString('base64') },
    { version: 1, identity, key: sessionKey.toString('base64') + '\n' },
    { version: 1, identity, key: sessionKey.toString('base64'), password: 'forbidden' },
    { version: 1, identity, key: sessionKey.toString('base64'), extra: 'x'.repeat(2048) },
  ]) {
    writeFileSync(file, JSON.stringify({ version: 1, identity, ciphertext: adapter.encryptString(JSON.stringify(payload)).toString('base64') }), { mode: 0o600 });
    assert.equal(store.recall(identity), undefined);
  }
});

test('invalid input or unavailable OS encryption cannot create a plaintext fallback or alter an existing cache', (t) => {
  const { root, file } = fixture(t);
  let available = false;
  let encrypted = 0;
  let decrypted = 0;
  const real = encryptor();
  const store = createDeviceSessionStore(root, {
    isEncryptionAvailable: () => available,
    encryptString: (plaintext) => { encrypted++; return real.encryptString(plaintext); },
    decryptString: (bytes) => { decrypted++; return real.decryptString(bytes); },
  });
  assert.equal(store.remember(identity, sessionKey), false);
  assert.equal(store.recall(identity), undefined);
  assert.equal(existsSync(root), false);
  available = true;
  for (const candidate of ['', 'vault', 'a'.repeat(200), ` ${identity}`, identity + '\n']) {
    assert.equal(store.remember(candidate, sessionKey), false);
    assert.equal(store.recall(candidate), undefined);
  }
  for (const key of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), 'secret' as unknown as Uint8Array]) {
    assert.equal(store.remember(identity, key), false);
  }
  assert.equal(existsSync(root), false);
  assert.equal(encrypted, 0);
  assert.equal(store.remember(identity, sessionKey), true);
  const saved = readFileSync(file);
  available = false;
  assert.equal(store.remember(identity, sessionKey), false);
  assert.equal(store.recall(identity), undefined);
  assert.deepEqual(readFileSync(file), saved);
  assert.equal(encrypted, 1);
  assert.equal(decrypted, 0);
});

test('OS adapter failure preserves existing ciphertext and leaves no temporary file', (t) => {
  const { root, file } = fixture(t);
  const real = encryptor();
  let fail = false;
  const store = createDeviceSessionStore(root, {
    ...real,
    encryptString: (plaintext) => { if (fail) throw new Error('Keychain unavailable'); return real.encryptString(plaintext); },
    decryptString: (bytes) => { if (fail) throw new Error('Keychain unavailable'); return real.decryptString(bytes); },
  });
  assert.equal(store.remember(identity, sessionKey), true);
  const saved = readFileSync(file);
  fail = true;
  assert.equal(store.remember(identity, randomBytes(32)), false);
  assert.equal(store.recall(identity), undefined);
  assert.deepEqual(readFileSync(file), saved);
  assert.deepEqual(readdirSync(root), ['device-session.json']);
});

test('session cache rejects unsafe directory and file modes', (t) => {
  const { root, file } = fixture(t);
  const store = createDeviceSessionStore(root, encryptor());
  assert.equal(store.remember(identity, sessionKey), true);
  for (const mode of [0o755, 0o770, 0o500]) {
    chmodSync(root, mode);
    assert.equal(store.recall(identity), undefined);
    assert.equal(store.remember(identity, sessionKey), false);
    assert.equal(store.forget(), false);
  }
  chmodSync(root, 0o700);
  for (const mode of [0o644, 0o660, 0o400]) {
    chmodSync(file, mode);
    assert.equal(store.recall(identity), undefined);
    assert.equal(store.remember(identity, sessionKey), false);
    assert.equal(store.forget(), false);
  }
  chmodSync(file, 0o600);
});

test('session cache refuses symlink directories, symlink files, and hard links without touching targets', (t) => {
  const { base, root, file } = fixture(t);
  const outside = join(base, 'outside');
  mkdirSync(outside, { mode: 0o700 });
  symlinkSync(outside, root, 'dir');
  const store = createDeviceSessionStore(root, encryptor());
  assert.equal(store.remember(identity, sessionKey), false);
  assert.equal(store.recall(identity), undefined);
  assert.equal(store.forget(), false);
  rmSync(root);
  mkdirSync(root, { mode: 0o700 });
  const target = join(outside, 'keep');
  writeFileSync(target, 'keep me', { mode: 0o600 });
  symlinkSync(target, file);
  assert.equal(store.remember(identity, sessionKey), false);
  assert.equal(store.recall(identity), undefined);
  assert.equal(store.forget(), false);
  assert.equal(readFileSync(target, 'utf8'), 'keep me');
  rmSync(file);
  linkSync(target, file);
  assert.equal(store.remember(identity, sessionKey), false);
  assert.equal(store.recall(identity), undefined);
  assert.equal(store.forget(), false);
  assert.equal(readFileSync(target, 'utf8'), 'keep me');
});

test('session cache refuses a FIFO without waiting for another process', { skip: process.platform === 'win32' }, (t) => {
  const { root, file } = fixture(t);
  mkdirSync(root, { mode: 0o700 });
  execFileSync('mkfifo', ['-m', '600', file]);
  const store = createDeviceSessionStore(root, encryptor());
  assert.equal(store.recall(identity), undefined);
  assert.equal(store.remember(identity, sessionKey), false);
  assert.equal(store.forget(), false);
});

test('destination is rechecked after OS encryption and unsafe replacements leave no temporary file', (t) => {
  const { base, root, file } = fixture(t);
  const target = join(base, 'keep');
  writeFileSync(target, 'keep me', { mode: 0o600 });
  const real = encryptor();
  const store = createDeviceSessionStore(root, {
    ...real,
    encryptString: (plaintext) => {
      symlinkSync(target, file);
      return real.encryptString(plaintext);
    },
  });
  assert.equal(store.remember(identity, sessionKey), false);
  assert.equal(readFileSync(target, 'utf8'), 'keep me');
  assert.deepEqual(readdirSync(root), ['device-session.json']);
});

test('forget removes only the protected session, including damaged ciphertext', (t) => {
  const { root, file } = fixture(t);
  const store = createDeviceSessionStore(root, encryptor());
  assert.equal(store.forget(), true);
  assert.equal(store.remember(identity, sessionKey), true);
  const vault = join(root, 'vault.jjvault');
  writeFileSync(vault, 'encrypted vault', { mode: 0o600 });
  writeFileSync(file, '{damaged');
  assert.equal(store.forget(), true);
  assert.equal(existsSync(file), false);
  assert.equal(store.recall(identity), undefined);
  assert.equal(readFileSync(vault, 'utf8'), 'encrypted vault');
  assert.equal(store.forget(), true);
});

test('lock clears protected resume synchronously even when triggered by engine idle policy', async (t) => {
  const { root } = fixture(t);
  const store = createDeviceSessionStore(root, encryptor());
  let disk: Envelope | null = null;
  let callbacks = 0;
  const engine = new VaultEngine({ read: async () => disk && structuredClone(disk), write: async (value) => { disk = structuredClone(value); } }, () => {
    callbacks++;
    assert.equal(store.forget(), true);
  });
  await engine.initialize('A test master password with enough words');
  const cachedIdentity = deviceSessionIdentity(disk!);
  const key = engine.exportSessionKey();
  assert.equal(store.remember(cachedIdentity, key), true);
  engine.lock();
  assert.equal(callbacks, 1);
  assert.equal(store.recall(cachedIdentity), undefined);
  await engine.unlockWithKey(key, 'deviceResume');
  assert.equal(engine.data().activity.at(-1)?.action, 'vault.deviceResumed');
  engine.data().settings.idleMinutes = 1;
  assert.equal(store.remember(cachedIdentity, key), true);
  (engine as unknown as { lastTouch: number }).lastTouch = Date.now() - 61000;
  engine.checkIdle();
  assert.equal(callbacks, 2);
  assert.equal(engine.status().locked, true);
  assert.equal(store.recall(cachedIdentity), undefined);
  await engine.unlockWithKey(key);
  assert.equal(engine.data().activity.at(-1)?.action, 'vault.biometricUnlock');
  key.fill(0);
});

test('a failing device lock callback cannot retain an unlocked engine', async () => {
  let disk: Envelope | null = null;
  const engine = new VaultEngine({ read: async () => disk && structuredClone(disk), write: async (value) => { disk = structuredClone(value); } }, () => { throw new Error('Device cache unavailable'); });
  await engine.initialize('Another test master password with enough words');
  assert.doesNotThrow(() => engine.lock());
  assert.equal(engine.status().locked, true);
  assert.throws(() => engine.exportSessionKey(), /Vault is locked/);
});
