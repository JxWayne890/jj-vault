import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createDeviceSecretStore, type DeviceSecretEncryption } from '../src/device-secret.js';

const secretKey = `JJ1.${Buffer.alloc(32, 23).toString('base64url')}`;
const vaultId = 'a55a7429-94a9-40d7-9b3b-6351f9b2516d';

function encryptor(key = randomBytes(32)): DeviceSecretEncryption {
  return {
    isEncryptionAvailable: () => true,
    encryptString(plainText) {
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, nonce);
      const ciphertext = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
      return Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]);
    },
    decryptString(protectedBytes) {
      const decipher = createDecipheriv('aes-256-gcm', key, protectedBytes.subarray(0, 12));
      decipher.setAuthTag(protectedBytes.subarray(12, 28));
      return Buffer.concat([decipher.update(protectedBytes.subarray(28)), decipher.final()]).toString('utf8');
    },
  };
}

function fixture(t: TestContext) {
  const base = mkdtempSync(join(tmpdir(), 'jj-device-secret-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const root = join(base, 'vault');
  return { base, root, file: join(root, 'device-secret.json') };
}

test('device secret is ciphertext on disk and survives a new store instance', (t) => {
  const { root, file } = fixture(t);
  const osKey = randomBytes(32);
  const store = createDeviceSecretStore(root, encryptor(osKey));
  assert.equal(store.remember(vaultId, secretKey), true);
  const disk = readFileSync(file, 'utf8');
  assert.equal(disk.includes(secretKey), false);
  assert.equal(disk.includes(Buffer.from(secretKey).toString('base64')), false);
  assert.equal(disk.includes('secretKey'), false);
  assert.equal(lstatSync(root).mode & 0o777, 0o700);
  assert.equal(lstatSync(file).mode & 0o777, 0o600);
  assert.equal(store.read(vaultId), secretKey);
  assert.equal(createDeviceSecretStore(root, encryptor(osKey)).read(vaultId), secretKey);
  assert.equal(createDeviceSecretStore(root, encryptor()).read(vaultId), null);
  assert.deepEqual(readdirSync(root), ['device-secret.json']);
});

test('device secret binds both the envelope and encrypted content to its vault', (t) => {
  const { root, file } = fixture(t);
  const store = createDeviceSecretStore(root, encryptor());
  assert.equal(store.remember(vaultId, secretKey), true);
  assert.equal(store.read('other-vault'), null);
  const envelope = JSON.parse(readFileSync(file, 'utf8'));
  envelope.vaultId = 'other-vault';
  writeFileSync(file, JSON.stringify(envelope));
  assert.equal(store.read('other-vault'), null);
  assert.equal(store.read(vaultId), null);
});

test('device secret rejects tampered ciphertext and invalid or oversized cache files', (t) => {
  const { root, file } = fixture(t);
  const store = createDeviceSecretStore(root, encryptor());
  assert.equal(store.remember(vaultId, secretKey), true);
  const saved = readFileSync(file);
  const envelope = JSON.parse(saved.toString('utf8'));
  const damaged = Buffer.from(envelope.ciphertext, 'base64');
  damaged[damaged.length - 1] ^= 1;
  envelope.ciphertext = damaged.toString('base64');
  writeFileSync(file, JSON.stringify(envelope));
  assert.equal(store.read(vaultId), null);
  for (const bytes of [Buffer.from('{broken'), Buffer.from('null'), Buffer.alloc(65537, 65), Buffer.alloc(0)]) {
    writeFileSync(file, bytes);
    assert.equal(store.read(vaultId), null);
  }
  writeFileSync(file, saved);
  const noncanonical = JSON.parse(saved.toString('utf8'));
  noncanonical.ciphertext += '\n';
  writeFileSync(file, JSON.stringify(noncanonical));
  assert.equal(store.read(vaultId), null);
});

test('device secret validates decrypted data and accepts only a canonical generated Secret Key', (t) => {
  const { root, file } = fixture(t);
  const adapter = encryptor();
  const store = createDeviceSecretStore(root, adapter);
  for (const candidate of ['password', 'JJ1.invalid', `${secretKey}=`, `${secretKey.slice(0, -1)}!`, ` ${secretKey}`]) {
    assert.equal(store.remember(vaultId, candidate), false);
  }
  // The last base64url character must have canonical unused bits.
  assert.equal(store.remember(vaultId, `${secretKey.slice(0, -1)}d`), false);
  assert.equal(existsSync(file), false);
  mkdirSync(root, { mode: 0o700 });
  for (const payload of [
    { version: 1, vaultId, secretKey: 'not-a-key' },
    { version: 2, vaultId, secretKey },
    { version: 1, vaultId: 'another-vault', secretKey },
    { version: 1, vaultId, secretKey, masterPassword: 'forbidden' },
  ]) {
    writeFileSync(file, JSON.stringify({ version: 1, vaultId, ciphertext: adapter.encryptString(JSON.stringify(payload)).toString('base64') }), { mode: 0o600 });
    assert.equal(store.read(vaultId), null);
  }
});

test('unavailable OS encryption never writes plaintext or blocks with an exception', (t) => {
  const { root, file } = fixture(t);
  let available = true;
  let encrypted = 0;
  let decrypted = 0;
  const real = encryptor();
  const store = createDeviceSecretStore(root, {
    isEncryptionAvailable: () => available,
    encryptString: (text) => { encrypted++; return real.encryptString(text); },
    decryptString: (bytes) => { decrypted++; return real.decryptString(bytes); },
  });
  available = false;
  assert.equal(store.remember(vaultId, secretKey), false);
  assert.equal(store.read(vaultId), null);
  assert.equal(existsSync(file), false);
  assert.equal(encrypted, 0);
  assert.equal(decrypted, 0);
  available = true;
  assert.equal(store.remember(vaultId, secretKey), true);
  const saved = readFileSync(file);
  available = false;
  assert.equal(store.read(vaultId), null);
  assert.equal(store.remember(vaultId, secretKey), false);
  assert.deepEqual(readFileSync(file), saved);
  assert.equal(decrypted, 0);
});

test('failed replacement preserves the existing ciphertext and invalid vault IDs cannot create caches', (t) => {
  const { root, file } = fixture(t);
  const real = encryptor();
  let fail = false;
  const store = createDeviceSecretStore(root, {
    ...real,
    encryptString: (text) => {
      if (fail) throw new Error('OS protection declined');
      return real.encryptString(text);
    },
  });
  for (const invalid of ['', ' vault', 'vault ', 'a\nb', 'a'.repeat(257)]) {
    assert.equal(store.remember(invalid, secretKey), false);
    assert.equal(store.read(invalid), null);
  }
  assert.equal(existsSync(root), false);
  assert.equal(store.remember(vaultId, secretKey), true);
  const original = readFileSync(file);
  fail = true;
  assert.equal(store.remember('other-vault', secretKey), false);
  assert.deepEqual(readFileSync(file), original);
  assert.equal(store.read(vaultId), secretKey);
  fail = false;
  assert.equal(store.remember('other-vault', secretKey), true);
  assert.equal(store.read(vaultId), null);
  assert.equal(store.read('other-vault'), secretKey);
  assert.deepEqual(readdirSync(root), ['device-secret.json']);
});

test('encryption adapter failures are harmless cache misses with no temporary file', (t) => {
  const { root } = fixture(t);
  const store = createDeviceSecretStore(root, {
    isEncryptionAvailable: () => true,
    encryptString: () => { throw new Error('Keychain unavailable'); },
    decryptString: () => { throw new Error('Keychain unavailable'); },
  });
  assert.equal(store.remember(vaultId, secretKey), false);
  assert.equal(store.read(vaultId), null);
  assert.deepEqual(readdirSync(root), []);
});

test('device secret refuses broad directory or file permissions', (t) => {
  const { root, file } = fixture(t);
  const store = createDeviceSecretStore(root, encryptor());
  assert.equal(store.remember(vaultId, secretKey), true);
  chmodSync(root, 0o755);
  assert.equal(store.read(vaultId), null);
  assert.equal(store.remember(vaultId, secretKey), false);
  assert.equal(store.forget(), false);
  chmodSync(root, 0o700);
  chmodSync(file, 0o644);
  assert.equal(store.read(vaultId), null);
  assert.equal(store.remember(vaultId, secretKey), false);
  assert.equal(store.forget(), false);
});

test('device secret refuses symlink directories and symlink or hard linked files', (t) => {
  const { base, root, file } = fixture(t);
  const outside = join(base, 'outside');
  mkdirSync(outside, { mode: 0o700 });
  symlinkSync(outside, root, 'dir');
  const store = createDeviceSecretStore(root, encryptor());
  assert.equal(store.remember(vaultId, secretKey), false);
  assert.equal(store.read(vaultId), null);
  assert.equal(store.forget(), false);
  rmSync(root);
  mkdirSync(root, { mode: 0o700 });
  const target = join(outside, 'keep');
  writeFileSync(target, 'keep me', { mode: 0o600 });
  symlinkSync(target, file);
  assert.equal(store.remember(vaultId, secretKey), false);
  assert.equal(store.read(vaultId), null);
  assert.equal(store.forget(), false);
  assert.equal(readFileSync(target, 'utf8'), 'keep me');
  rmSync(file);
  linkSync(target, file);
  assert.equal(store.remember(vaultId, secretKey), false);
  assert.equal(store.read(vaultId), null);
  assert.equal(store.forget(), false);
  assert.equal(readFileSync(target, 'utf8'), 'keep me');
});

test('forget removes only the remembered device key, including damaged ciphertext', (t) => {
  const { root, file } = fixture(t);
  const store = createDeviceSecretStore(root, encryptor());
  assert.equal(store.forget(), true);
  assert.equal(store.remember(vaultId, secretKey), true);
  const vault = join(root, 'vault.jjvault');
  writeFileSync(vault, 'encrypted vault', { mode: 0o600 });
  writeFileSync(file, '{damaged');
  assert.equal(store.forget(), true);
  assert.equal(existsSync(file), false);
  assert.equal(store.read(vaultId), null);
  assert.equal(readFileSync(vault, 'utf8'), 'encrypted vault');
  assert.equal(store.forget(), true);
});
