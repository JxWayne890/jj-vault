import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { VaultEngine, type Envelope } from '../../core/src/index.ts';
import { createPasskeyProvider, validateRpId } from '../src/passkeys.ts';
import { startLocalService } from '../src/local-service.ts';
import { randomToken } from '../src/security.ts';

async function fixture() {
  let envelope: Envelope | null = null;
  const engine = new VaultEngine({ read: async () => envelope, write: async value => { envelope = value; } });
  await engine.initialize('passkey fixture master password');
  return engine;
}
function decodeCbor(buffer: Buffer): any {
  let offset = 0;
  function decode(): any {
    const initial = buffer[offset++]; const major = initial >> 5; const info = initial & 31;
    const length = info < 24 ? info : info === 24 ? buffer[offset++] : info === 25 ? (offset += 2, buffer.readUInt16BE(offset - 2)) : (offset += 4, buffer.readUInt32BE(offset - 4));
    if (major === 0) return length; if (major === 1) return -1 - length;
    if (major === 2 || major === 3) { const result = buffer.subarray(offset, offset + length); offset += length; return major === 2 ? result : result.toString(); }
    if (major === 4) return Array.from({ length }, decode);
    if (major === 5) { const map = new Map(); for (let i = 0; i < length; i++) map.set(decode(), decode()); return map; }
    throw new Error('Unexpected CBOR major type');
  }
  return decode();
}
function registration() { return { action: 'register', rpId: 'example.test', clientDataHash: randomBytes(32).toString('base64'), userHandle: randomBytes(24).toString('base64'), userName: 'fixture@example.test', supportedAlgorithms: [-7] }; }

test('WebAuthn registration emits standard none attestation, scoped ES256 COSE key and verified UV flags', async () => {
  const engine = await fixture(); let approvals = 0; const provider = createPasskeyProvider(engine, { verifyUser: async () => { approvals++; } });
  const input = registration(); const result: any = await provider(input); assert.equal(approvals, 1);
  const attestation = decodeCbor(Buffer.from(result.attestationObject, 'base64')); assert.equal(attestation.get('fmt'), 'none'); assert.equal(attestation.get('attStmt').size, 0);
  const auth: Buffer = attestation.get('authData'); assert.deepEqual(auth.subarray(0, 32), createHash('sha256').update(input.rpId).digest());
  assert.equal(auth[32], 0x4d); assert.equal(auth.readUInt32BE(33), 0); assert.equal(auth.readUInt16BE(53), 32); assert.deepEqual(auth.subarray(55, 87), Buffer.from(result.credentialId, 'base64'));
  const cose = decodeCbor(auth.subarray(87)); assert.equal(cose.get(1), 2); assert.equal(cose.get(3), -7); assert.equal(cose.get(-1), 1);
  const publicKey = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: cose.get(-2).toString('base64url'), y: cose.get(-3).toString('base64url') } });
  const assertionInput = { action: 'assert', rpId: input.rpId, clientDataHash: randomBytes(32).toString('base64'), credentialId: result.credentialId, allowedCredentialIds: [result.credentialId] };
  const assertion: any = await provider(assertionInput); assert.equal(approvals, 2);
  const authenticatorData = Buffer.from(assertion.authenticatorData, 'base64'); assert.equal(authenticatorData[32], 0x0d); assert.equal(authenticatorData.readUInt32BE(33), 0);
  assert(verify('sha256', Buffer.concat([authenticatorData, Buffer.from(assertionInput.clientDataHash, 'base64')]), publicKey, Buffer.from(assertion.signature, 'base64')));
  assert.equal(assertion.userHandle, input.userHandle); assert.equal(assertion.relyingParty, input.rpId); assert.equal(assertion.clientDataHash, assertionInput.clientDataHash);
  const discoverable: any = await provider({ ...assertionInput, allowedCredentialIds: [] }); assert.equal(discoverable.credentialId, result.credentialId);
  const list: any = await provider({ action: 'list', rpId: input.rpId }); assert.equal(approvals, 3); assert.equal(list.credentials.length, 1); assert.equal(list.credentials[0].credentialId, result.credentialId);
  const stored = engine.data().items[0]; assert.equal(stored.allowAssistant, false); assert.equal(stored.type, 'passkey'); assert(!JSON.stringify([list, result, assertion]).includes(stored.passkey!.privateKey));
  assert(engine.data().activity.some(event => event.action === 'passkey.asserted'));
});

test('provider rejects invalid RPs, hashes, handles, excludes, algorithms, scopes and revoked vault access', async () => {
  for (const invalid of ['com', 'co.uk', 'github.io', '127.0.0.1', 'example.test:443', 'EXAMPLE.TEST', 'example.test.', 'https://example.test', '-example.test', 'example..test']) assert.throws(() => validateRpId(invalid), /Invalid/);
  assert.equal(validateRpId('localhost'), 'localhost');
  const engine = await fixture(); const provider = createPasskeyProvider(engine, { verifyUser: async () => {} });
  await assert.rejects(provider({ ...registration(), clientDataHash: 'eA==' }), /hash/);
  await assert.rejects(provider({ ...registration(), userHandle: Buffer.alloc(65).toString('base64') }), /handle/);
  await assert.rejects(provider({ ...registration(), supportedAlgorithms: [-257] }), /Unsupported/);
  const valid = registration(); const created: any = await provider(valid);
  await assert.rejects(provider({ ...valid, excludedCredentialIds: [created.credentialId] }), /already exists/);
  await assert.rejects(provider({ action: 'assert', rpId: 'other.test', clientDataHash: valid.clientDataHash, credentialId: created.credentialId }), /not found/);
  await assert.rejects(provider({ action: 'assert', rpId: valid.rpId, clientDataHash: valid.clientDataHash, credentialId: created.credentialId, allowedCredentialIds: [randomBytes(32).toString('base64')] }), /Not allowed/);
  engine.data().vaults[0].allowBrowser = false;
  assert.equal((await provider({ action: 'list', rpId: valid.rpId }) as any).credentials.length, 0);
  await assert.rejects(provider({ action: 'assert', rpId: valid.rpId, clientDataHash: valid.clientDataHash, credentialId: created.credentialId }), /not found/);
});

test('user cancellation, a lock during biometric verification and travel restrictions cannot generate UV responses', async () => {
  const engine = await fixture();
  const denied = createPasskeyProvider(engine, { verifyUser: async () => { throw new Error('User cancelled'); } }); await assert.rejects(denied(registration()), /cancelled/); assert.equal(engine.data().items.length, 0);
  const initial = engine.data(); const locking = createPasskeyProvider(engine, { verifyUser: async () => { engine.lock(); } }); await assert.rejects(locking(registration()), /locked/); assert.equal(initial.items.length, 0);
  const other = await fixture(); other.data().settings.travelMode = true; let approvals = 0;
  const travel = createPasskeyProvider(other, { verifyUser: async () => { approvals++; } }); await assert.rejects(travel(registration()), /No allowed/); assert.equal(approvals, 0);
});

test('backup status is reported only when explicitly recorded, assertion permission is checked after user verification', async () => {
  const engine = await fixture(); const provider = createPasskeyProvider(engine, { verifyUser: async () => {} }); const input = registration(); const created: any = await provider(input);
  (engine.data().items[0].passkey as any).backedUp = true;
  const request = { action: 'assert', rpId: input.rpId, clientDataHash: input.clientDataHash, credentialId: created.credentialId };
  const result: any = await provider(request); assert.equal(Buffer.from(result.authenticatorData, 'base64')[32], 0x1d);
  const revoked = createPasskeyProvider(engine, { verifyUser: async () => { engine.data().vaults[0].allowBrowser = false; } }); await assert.rejects(revoked(request), /not found/);
});

test('/provider uses a separate bearer scope, rejects browser and assistant tokens, and never unlocks', async t => {
  const engine = await fixture(); const assistant = await engine.createToken('Fixture assistant'); const adminToken = randomToken(); const browserToken = randomToken(); const providerToken = randomToken();
  const service = await startLocalService(engine, { port: 0, adminToken, browserToken, providerToken, provider: createPasskeyProvider(engine, { verifyUser: async () => {} }) }); t.after(() => service.close());
  const post = (path: string, token: string, body: unknown, origin?: string) => fetch(`http://127.0.0.1:${service.port}${path}`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(origin ? { Origin: origin } : {}) }, body: JSON.stringify(body) });
  for (const token of [adminToken, browserToken, assistant.token]) assert.equal((await post('/provider', token, { action: 'list', rpId: 'example.test' })).status, 401);
  assert.equal((await post('/mcp', providerToken, {})).status, 401); assert.equal((await post('/browser', providerToken, {})).status, 401);
  assert.equal((await post('/provider', providerToken, { action: 'list', rpId: 'example.test' }, 'https://attacker.test')).status, 403);
  const result = await post('/provider', providerToken, registration()); assert.equal(result.status, 200); const body = await result.json(); assert(body.ok && body.result.attestationObject);
  const metadata = await (await post('/admin', adminToken, { action: 'get', id: engine.data().items[0].id })).json(); assert.equal(metadata.result.passkey.privateKey, undefined);
  assert(!JSON.stringify(metadata).includes(engine.data().items[0].passkey!.privateKey));
  engine.lock(); const locked = await post('/provider', providerToken, { action: 'register', password: 'never accepted' }); assert.equal(locked.status, 423); assert.equal((await locked.json()).error, 'Vault is locked');
});
