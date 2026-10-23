import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {
  chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync,
  readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createDevicePinStore } from '../src/device-pin.ts';
import type { DeviceSecretEncryption } from '../src/device-secret.ts';

const identity = `a55a7429-94a9-40d7-9b3b-6351f9b2516d:${'a'.repeat(64)}`;
const otherIdentity = `a55a7429-94a9-40d7-9b3b-6351f9b2516d:${'b'.repeat(64)}`;
const sessionKey = Buffer.alloc(32, 23);
const unavailable = /PIN unlock is unavailable/;

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
  const base = mkdtempSync(join(tmpdir(), 'jj-device-pin-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const root = join(base, 'vault');
  return { base, root, file: join(root, 'device-pin.json') };
}

function payload(file: string, adapter: DeviceSecretEncryption): Record<string, unknown> {
  const envelope = JSON.parse(readFileSync(file, 'utf8'));
  return JSON.parse(adapter.decryptString(Buffer.from(envelope.ciphertext, 'base64')));
}

function replacePayload(file: string, adapter: DeviceSecretEncryption, value: unknown, envelopeIdentity = identity) {
  writeFileSync(file, JSON.stringify({ version: 1, identity: envelopeIdentity, ciphertext: adapter.encryptString(JSON.stringify(value)).toString('base64') }), { mode: 0o600 });
}

test('4, 5, and 6 digit PINs preserve leading zeros and return independent root key buffers', (t) => {
  const { root } = fixture(t);
  const adapter = encryptor();
  const store = createDevicePinStore(root, adapter);
  assert.deepEqual(store.status(identity), { enabled: false, available: true });
  assert.deepEqual(store.status(''), { enabled: false, available: true });
  for (const pin of ['0000', '01234', '001234']) {
    const original = Buffer.from(sessionKey);
    store.set(identity, pin, original);
    assert.deepEqual(original, sessionKey);
    assert.deepEqual(store.status(identity), { enabled: true, available: true });
    const key = store.unlock(identity, pin);
    assert.deepEqual(key, sessionKey);
    key.fill(0);
    const fresh = createDevicePinStore(root, adapter).unlock(identity, pin);
    assert.deepEqual(fresh, sessionKey);
    fresh.fill(0);
  }
});

test('only ASCII 4 to 6 digit strings and valid key identities are accepted', (t) => {
  const { root, file } = fixture(t);
  const store = createDevicePinStore(root, encryptor());
  for (const pin of ['', '123', '1234567', ' 1234', '1234 ', '1234\n', '12.4', '+1234', '１２３４', '١٢٣٤', 1234 as unknown as string]) {
    assert.throws(() => store.set(identity, pin, sessionKey), /PIN must contain 4 to 6 digits/);
    assert.throws(() => store.unlock(identity, pin), /PIN must contain 4 to 6 digits/);
  }
  for (const invalid of ['', 'vault', identity + '\n', 'a'.repeat(200), ` ${identity}`]) {
    assert.throws(() => store.set(invalid, '1234', sessionKey), /Invalid vault session identity/);
    assert.throws(() => store.unlock(invalid, '1234'), /Invalid vault session identity/);
    assert.deepEqual(store.status(invalid), { enabled: false, available: true });
  }
  for (const key of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), 'secret' as unknown as Uint8Array]) {
    assert.throws(() => store.set(identity, '1234', key), /Invalid vault session key/);
  }
  assert.equal(existsSync(root), false);
  assert.equal(existsSync(file), false);
  store.set(identity, '1234', sessionKey);
  assert.deepEqual(store.status(''), { enabled: true, available: false });
});

test('disk and OS protected payload contain no plaintext PIN or root key', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  const store = createDevicePinStore(root, adapter);
  const pin = '091827';
  store.set(identity, pin, sessionKey);
  const disk = readFileSync(file, 'utf8');
  const plain = adapter.decryptString(Buffer.from(JSON.parse(disk).ciphertext, 'base64'));
  for (const value of [disk, plain]) {
    assert.equal(value.includes(pin), false);
    assert.equal(value.includes(sessionKey.toString('base64')), false);
    assert.equal(value.includes('masterPassword'), false);
    assert.equal(value.includes('secretKey'), false);
  }
  const protectedPayload = JSON.parse(plain);
  assert.equal(Buffer.from(protectedPayload.salt, 'base64').length, 16);
  assert.equal(Buffer.from(protectedPayload.nonce, 'base64').length, 12);
  assert.equal(Buffer.from(protectedPayload.ciphertext, 'base64').length, 32);
  assert.equal(Buffer.from(protectedPayload.tag, 'base64').length, 16);
  assert.equal(protectedPayload.failures, 0);
  assert.equal(protectedPayload.retryAt, 0);
  assert.equal(lstatSync(root).mode & 0o777, 0o700);
  assert.equal(lstatSync(file).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(root), ['device-pin.json']);
});

test('failed attempts persist across stores, delay after five failures, and reset after success', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  let current = 1_000_000;
  const fresh = () => createDevicePinStore(root, adapter, () => current);
  fresh().set(identity, '0123', sessionKey);
  for (let failure = 1; failure <= 4; failure++) {
    assert.throws(() => fresh().unlock(identity, '3210'), /Incorrect PIN/);
    assert.equal(payload(file, adapter).failures, failure);
    assert.deepEqual(fresh().status(identity), { enabled: true, available: true });
  }
  assert.throws(() => fresh().unlock(identity, '3210'), /Incorrect PIN/);
  assert.deepEqual(fresh().status(identity), { enabled: true, available: true, retryAt: current + 30_000 });
  const before = readFileSync(file);
  assert.throws(() => fresh().unlock(identity, '0123'), /temporarily locked/);
  assert.deepEqual(readFileSync(file), before);
  current += 30_000;
  assert.throws(() => fresh().unlock(identity, '3210'), /Incorrect PIN/);
  assert.deepEqual(fresh().status(identity), { enabled: true, available: true, retryAt: current + 60_000 });
  current += 60_000;
  const key = fresh().unlock(identity, '0123');
  assert.deepEqual(key, sessionKey);
  key.fill(0);
  assert.equal(payload(file, adapter).failures, 0);
  assert.equal(payload(file, adapter).retryAt, 0);
  assert.deepEqual(fresh().status(identity), { enabled: true, available: true });
});

test('cooldown doubles to a maximum one hour and persists before PIN checking', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  let current = 1_000_000;
  const store = createDevicePinStore(root, adapter, () => current);
  store.set(identity, '1234', sessionKey);
  for (let failure = 1; failure <= 14; failure++) {
    assert.throws(() => store.unlock(identity, '4321'), /Incorrect PIN/);
    const saved = payload(file, adapter);
    assert.equal(saved.failures, failure);
    const delay = failure < 5 ? 0 : Math.min(3_600_000, 30_000 * 2 ** (failure - 5));
    assert.equal(saved.retryAt, delay ? current + delay : 0);
    current += delay;
  }
  // A successful fifth attempt is checked after its counter is durably saved.
  store.set(identity, '1234', sessionKey);
  for (let attempt = 0; attempt < 4; attempt++) assert.throws(() => store.unlock(identity, '4321'), /Incorrect PIN/);
  let sawFifth = false;
  const observed = createDevicePinStore(root, {
    ...adapter,
    encryptString(plaintext) {
      const value = JSON.parse(plaintext);
      if (value.failures === 5) sawFifth = true;
      if (value.failures === 0) assert.equal(sawFifth, true);
      return adapter.encryptString(plaintext);
    },
  }, () => current);
  observed.unlock(identity, '1234').fill(0);
  assert.equal(sawFifth, true);
});

test('PIN data binds both identities and refuses a key copied to a different vault identity', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  const store = createDevicePinStore(root, adapter);
  store.set(identity, '1234', sessionKey);
  assert.deepEqual(store.status(otherIdentity), { enabled: false, available: true });
  assert.throws(() => store.unlock(otherIdentity, '1234'), /not enabled for this vault/);
  const original = readFileSync(file);
  const envelope = JSON.parse(original.toString());
  envelope.identity = otherIdentity;
  writeFileSync(file, JSON.stringify(envelope));
  assert.deepEqual(store.status(identity), { enabled: true, available: false });
  assert.deepEqual(store.status(otherIdentity), { enabled: true, available: false });
  writeFileSync(file, original);
  const changed = { ...payload(file, adapter), identity: otherIdentity };
  replacePayload(file, adapter, changed, otherIdentity);
  assert.throws(() => store.unlock(otherIdentity, '1234'), /Incorrect PIN/);
});

test('corrupt and oversized files stay enabled but unavailable', (t) => {
  const { root, file } = fixture(t);
  const store = createDevicePinStore(root, encryptor());
  store.set(identity, '1234', sessionKey);
  const original = readFileSync(file);
  const envelope = JSON.parse(original.toString());
  const damaged = Buffer.from(envelope.ciphertext, 'base64');
  damaged[damaged.length - 1] ^= 1;
  const values = [
    Buffer.from('{broken'), Buffer.from('null'), Buffer.alloc(65537, 65), Buffer.alloc(0),
    Buffer.from(JSON.stringify({ ...envelope, ciphertext: damaged.toString('base64') })),
    Buffer.from(JSON.stringify({ ...envelope, version: 2 })),
    Buffer.from(JSON.stringify({ ...envelope, extra: true })),
    Buffer.from(JSON.stringify({ ...envelope, ciphertext: envelope.ciphertext + '\n' })),
  ];
  for (const value of values) {
    writeFileSync(file, value);
    assert.deepEqual(store.status(identity), { enabled: true, available: false });
    assert.throws(() => store.unlock(identity, '1234'), unavailable);
  }
});

test('decrypted payload has exact bounded fields and canonical binary encodings', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  const store = createDevicePinStore(root, adapter);
  store.set(identity, '1234', sessionKey);
  const original = payload(file, adapter);
  for (const changes of [
    { version: 2 }, { identity: 'other' }, { extra: true },
    { salt: Buffer.alloc(15).toString('base64') }, { nonce: Buffer.alloc(11).toString('base64') },
    { ciphertext: Buffer.alloc(31).toString('base64') }, { tag: Buffer.alloc(15).toString('base64') },
    { salt: original.salt + '\n' }, { ciphertext: original.ciphertext + '\n' },
    { failures: -1 }, { failures: 1.5 }, { failures: 1_000_001 }, { failures: '0' },
    { retryAt: -1 }, { retryAt: 1.5 }, { retryAt: Number.MAX_SAFE_INTEGER + 1 },
    { failures: 0, retryAt: 123 }, { failures: 5, retryAt: 0 },
    { extra: 'x'.repeat(3000) },
  ]) {
    replacePayload(file, adapter, { ...original, ...changes });
    assert.deepEqual(store.status(identity), { enabled: true, available: false });
    assert.throws(() => store.unlock(identity, '1234'), unavailable);
  }
});

test('OS protection unavailability fails closed without plaintext fallback or decrypt attempts', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  let available = false;
  let decryptions = 0;
  const store = createDevicePinStore(root, {
    ...adapter,
    isEncryptionAvailable: () => available,
    decryptString(bytes) { decryptions++; return adapter.decryptString(bytes); },
  });
  assert.deepEqual(store.status(identity), { enabled: false, available: false });
  assert.throws(() => store.set(identity, '1234', sessionKey), unavailable);
  assert.equal(existsSync(root), false);
  available = true;
  store.set(identity, '1234', sessionKey);
  const saved = readFileSync(file);
  available = false;
  assert.deepEqual(store.status(identity), { enabled: true, available: false });
  assert.deepEqual(store.status(otherIdentity), { enabled: true, available: false });
  assert.throws(() => store.unlock(identity, '1234'), unavailable);
  assert.throws(() => store.set(identity, '4567', sessionKey), unavailable);
  assert.deepEqual(readFileSync(file), saved);
  assert.equal(decryptions, 0);
});

test('adapter errors preserve ciphertext, refuse unlock, and leave no temporary files', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  const good = createDevicePinStore(root, adapter);
  good.set(identity, '1234', sessionKey);
  const original = readFileSync(file);
  for (const changes of [
    { isEncryptionAvailable() { throw new Error('OS unavailable'); } },
    { encryptString() { throw new Error('OS unavailable'); } },
    { decryptString() { throw new Error('OS unavailable'); } },
  ]) {
    const store = createDevicePinStore(root, { ...adapter, ...changes });
    assert.throws(() => store.unlock(identity, '1234'), unavailable);
    if (!('decryptString' in changes)) assert.throws(() => store.set(identity, '2345', sessionKey), unavailable);
    assert.deepEqual(readFileSync(file), original);
    assert.deepEqual(readdirSync(root), ['device-pin.json']);
  }
  assert.deepEqual(createDevicePinStore(root, encryptor()).status(identity), { enabled: true, available: false });
});

test('unsafe root or file permissions remain enabled and cannot be changed or removed', (t) => {
  const { root, file } = fixture(t);
  const store = createDevicePinStore(root, encryptor());
  store.set(identity, '1234', sessionKey);
  const original = readFileSync(file);
  for (const mode of [0o755, 0o770, 0o500]) {
    chmodSync(root, mode);
    assert.deepEqual(store.status(identity), { enabled: true, available: false });
    assert.throws(() => store.unlock(identity, '1234'), unavailable);
    assert.throws(() => store.set(identity, '2345', sessionKey), unavailable);
    assert.throws(() => store.remove(), /could not be removed/);
  }
  chmodSync(root, 0o700);
  for (const mode of [0o644, 0o660, 0o400]) {
    chmodSync(file, mode);
    assert.deepEqual(store.status(identity), { enabled: true, available: false });
    assert.throws(() => store.unlock(identity, '1234'), unavailable);
    assert.throws(() => store.set(identity, '2345', sessionKey), unavailable);
    assert.throws(() => store.remove(), /could not be removed/);
  }
  chmodSync(file, 0o600);
  assert.deepEqual(readFileSync(file), original);
});

test('symlink roots, symlink files, and hard links fail closed without touching targets', (t) => {
  const { base, root, file } = fixture(t);
  const outside = join(base, 'outside');
  mkdirSync(outside, { mode: 0o700 });
  symlinkSync(outside, root, 'dir');
  const store = createDevicePinStore(root, encryptor());
  assert.deepEqual(store.status(identity), { enabled: true, available: false });
  assert.throws(() => store.set(identity, '1234', sessionKey), unavailable);
  assert.throws(() => store.remove(), /could not be removed/);
  rmSync(root);
  mkdirSync(root, { mode: 0o700 });
  const target = join(outside, 'keep');
  writeFileSync(target, 'keep me', { mode: 0o600 });
  for (const link of [() => symlinkSync(target, file), () => linkSync(target, file)]) {
    link();
    assert.deepEqual(store.status(identity), { enabled: true, available: false });
    assert.throws(() => store.unlock(identity, '1234'), unavailable);
    assert.throws(() => store.set(identity, '2345', sessionKey), unavailable);
    assert.throws(() => store.remove(), /could not be removed/);
    assert.equal(readFileSync(target, 'utf8'), 'keep me');
    rmSync(file);
  }
});

test('FIFO storage fails closed without blocking', { skip: process.platform === 'win32' }, (t) => {
  const { root, file } = fixture(t);
  mkdirSync(root, { mode: 0o700 });
  execFileSync('mkfifo', ['-m', '600', file]);
  const store = createDevicePinStore(root, encryptor());
  assert.deepEqual(store.status(identity), { enabled: true, available: false });
  assert.throws(() => store.unlock(identity, '1234'), unavailable);
  assert.throws(() => store.set(identity, '1234', sessionKey), unavailable);
  assert.throws(() => store.remove(), /could not be removed/);
});

test('OS encryption cannot replace the destination with an unsafe link unnoticed', (t) => {
  const { base, root, file } = fixture(t);
  const target = join(base, 'keep');
  writeFileSync(target, 'keep me', { mode: 0o600 });
  const adapter = encryptor();
  const store = createDevicePinStore(root, {
    ...adapter,
    encryptString(plain) {
      symlinkSync(target, file);
      return adapter.encryptString(plain);
    },
  });
  assert.throws(() => store.set(identity, '1234', sessionKey), unavailable);
  assert.equal(readFileSync(target, 'utf8'), 'keep me');
  assert.deepEqual(readdirSync(root), ['device-pin.json']);
  assert.deepEqual(store.status(identity), { enabled: true, available: false });
});

test('owner removal forgets only PIN data, including damaged ciphertext, without OS decryption', (t) => {
  const { root, file } = fixture(t);
  const store = createDevicePinStore(root, encryptor());
  assert.doesNotThrow(() => store.remove());
  store.set(identity, '1234', sessionKey);
  const vault = join(root, 'vault.jjvault');
  writeFileSync(vault, 'encrypted vault', { mode: 0o600 });
  writeFileSync(file, '{damaged');
  const unavailableStore = createDevicePinStore(root, {
    isEncryptionAvailable: () => false,
    encryptString() { throw new Error('must not encrypt'); },
    decryptString() { throw new Error('must not decrypt'); },
  });
  unavailableStore.remove();
  assert.equal(existsSync(file), false);
  assert.equal(readFileSync(vault, 'utf8'), 'encrypted vault');
  assert.deepEqual(store.status(identity), { enabled: false, available: true });
  assert.doesNotThrow(() => store.remove());
});

test('a correct PIN returns no key when the durable success reset fails', t => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  const store = createDevicePinStore(root, adapter);
  store.set(identity, '0123', sessionKey);
  const encrypt = adapter.encryptString.bind(adapter);
  let writes = 0;
  adapter.encryptString = value => {
    writes++;
    if (writes === 2) throw new Error('Synthetic failure during success reset');
    return encrypt(value);
  };
  assert.throws(() => store.unlock(identity, '0123'), unavailable);
  assert.equal(payload(file, adapter).failures, 1);
  adapter.encryptString = encrypt;
  const key = store.unlock(identity, '0123');
  try { assert.deepEqual(key, sessionKey); }
  finally { key.fill(0); }
  assert.equal(payload(file, adapter).failures, 0);
});
