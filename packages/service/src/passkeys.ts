import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { isIP } from 'node:net';
import { parse } from 'tldts';
import { newItem, type Item, type Vault, type VaultData, type VaultEngine } from '../../core/src/index.ts';

/** Minimal deterministic CBOR encoder for the WebAuthn structures this provider emits. */
export function encodeCbor(value: unknown): Buffer {
  function head(major: number, length: number): Buffer {
    if (length < 24) return Buffer.from([(major << 5) | length]);
    if (length <= 255) return Buffer.from([(major << 5) | 24, length]);
    if (length <= 65535) { const result = Buffer.alloc(3); result[0] = (major << 5) | 25; result.writeUInt16BE(length, 1); return result; }
    if (length <= 0xffffffff) { const result = Buffer.alloc(5); result[0] = (major << 5) | 26; result.writeUInt32BE(length, 1); return result; }
    throw new Error('Invalid CBOR length');
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) { const data = Buffer.from(value); return Buffer.concat([head(2, data.length), data]); }
  if (typeof value === 'string') { const data = Buffer.from(value); return Buffer.concat([head(3, data.length), data]); }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encodeCbor)]);
  const entries = value instanceof Map ? [...value.entries()] : value && typeof value === 'object' ? Object.entries(value) : null;
  if (entries) return Buffer.concat([head(5, entries.length), ...entries.flatMap(([key, entry]) => [encodeCbor(key), encodeCbor(entry)])]);
  throw new Error('Unsupported CBOR value');
}
export function validateRpId(value: unknown): string {
  if (typeof value !== 'string' || value.length > 253 || value !== value.toLowerCase() || value.endsWith('.') || isIP(value) || !/^[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/.test(value) || value.split('.').some(label => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) throw new Error('Invalid relying party identifier');
  if (value !== 'localhost' && !parse(value, { allowPrivateDomains: true }).domain) throw new Error('Invalid relying party identifier');
  return value;
}
function bytes(value: unknown, label: string, minimum: number, maximum = minimum): Buffer {
  if (typeof value !== 'string' || value.length > 4096 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error(`Invalid ${label}`);
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length < minimum || decoded.length > maximum || decoded.toString('base64') !== value) throw new Error(`Invalid ${label}`);
  return decoded;
}
function credentialIds(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 1000) throw new Error('Invalid credential list');
  return value.map(entry => bytes(entry, 'credential ID', 1, 1024).toString('base64'));
}
function permittedVaults(data: VaultData): Vault[] { return data.vaults.filter(vault => vault.allowBrowser && (!data.settings.travelMode || vault.travelSafe)); }
function permittedItems(data: VaultData, rpId: string): Item[] {
  const vaults = new Set(permittedVaults(data).map(vault => vault.id));
  return data.items.filter(item => item.type === 'passkey' && item.passkey?.rpId === rpId && !item.archived && !item.deletedAt && vaults.has(item.vaultId));
}
function authData(rpId: string, backedUp: boolean, attestation?: { id: Buffer; coseKey: Buffer }): Buffer {
  const flags = 0x01 | 0x04 | 0x08 | (backedUp ? 0x10 : 0) | (attestation ? 0x40 : 0);
  const header = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([flags]), Buffer.alloc(4)]);
  if (!attestation) return header;
  const length = Buffer.alloc(2); length.writeUInt16BE(attestation.id.length);
  return Buffer.concat([header, Buffer.alloc(16), length, attestation.id, attestation.coseKey]);
}
export function createPasskeyProvider(engine: VaultEngine, options: { verifyUser: () => Promise<void> }): (body: any) => Promise<unknown> {
  function stillUnlocked(initial: VaultData) { if (engine.status().locked || engine.data() !== initial) throw new Error('Vault is locked'); }
  return async (body: any): Promise<unknown> => {
    const initial = engine.data();
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid provider request');
    const rpId = validateRpId(body.rpId);
    if (body.action === 'list') return {
      credentials: permittedItems(initial, rpId).map(item => ({ credentialId: item.passkey!.credentialId, rpId, userHandle: item.passkey!.userHandle, userName: item.passkey!.userName, title: item.title })),
      vaults: permittedVaults(initial).map(vault => ({ id: vault.id, name: vault.name })),
    };
    if (!['register', 'assert'].includes(body.action)) throw new Error('Unsupported provider action');
    const clientDataHash = bytes(body.clientDataHash, 'client data hash', 32);
    if (body.action === 'register') {
      const userHandle = bytes(body.userHandle, 'user handle', 1, 64);
      if (typeof body.userName !== 'string' || !body.userName.trim() || body.userName.length > 500) throw new Error('Invalid user name');
      if (body.supportedAlgorithms !== undefined && (!Array.isArray(body.supportedAlgorithms) || !body.supportedAlgorithms.every((value: unknown) => Number.isSafeInteger(value)) || !body.supportedAlgorithms.includes(-7))) throw new Error('Unsupported passkey algorithm');
      const excluded = credentialIds(body.excludedCredentialIds) || [];
      if (permittedItems(initial, rpId).some(item => excluded.includes(item.passkey!.credentialId))) throw new Error('Not allowed, credential already exists');
      const chooseVault = () => permittedVaults(engine.data()).find(vault => body.vaultId ? vault.id === body.vaultId : true);
      if (!chooseVault()) throw new Error('No allowed credential vault');
      await options.verifyUser(); stillUnlocked(initial);
      const vault = chooseVault(); if (!vault) throw new Error('No allowed credential vault');
      if (permittedItems(initial, rpId).some(item => excluded.includes(item.passkey!.credentialId))) throw new Error('Not allowed, credential already exists');
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const privateBytes = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
      const publicBytes = pair.publicKey.export({ format: 'der', type: 'spki' });
      const jwk = pair.publicKey.export({ format: 'jwk' });
      const coseKey = encodeCbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
      const id = randomBytes(32); const credentialId = id.toString('base64');
      try {
        const item = await engine.upsertItem({ ...newItem('passkey', `${body.userName} (${rpId})`, vault.id), username: body.userName, urls: [`https://${rpId}`], tags: ['passkey'], allowAssistant: false, passkey: { credentialId, rpId, userHandle: userHandle.toString('base64'), userName: body.userName, privateKey: privateBytes.toString('base64'), publicKey: publicBytes.toString('base64'), signCount: 0 } });
        await engine.record('passkey.registered', item.id, rpId); stillUnlocked(initial);
        if (!permittedItems(initial, rpId).some(entry => entry.id === item.id)) throw new Error('No allowed credential vault');
        return { relyingParty: rpId, clientDataHash: clientDataHash.toString('base64'), credentialId, attestationObject: encodeCbor({ fmt: 'none', attStmt: {}, authData: authData(rpId, false, { id, coseKey }) }).toString('base64') };
      } finally { privateBytes.fill(0); }
    }
    const credentialId = bytes(body.credentialId, 'credential ID', 1, 1024).toString('base64');
    const allowed = credentialIds(body.allowedCredentialIds);
    if (allowed?.length && !allowed.includes(credentialId)) throw new Error('Not allowed credential');
    const find = () => permittedItems(engine.data(), rpId).find(item => item.passkey!.credentialId === credentialId);
    if (!find()) throw new Error('Item not found');
    await options.verifyUser(); stillUnlocked(initial);
    const item = find(); if (!item) throw new Error('Item not found');
    const credential = item.passkey!; const backedUp = (credential as typeof credential & { backedUp?: boolean }).backedUp === true;
    const authenticatorData = authData(rpId, backedUp);
    const privateBytes = Buffer.from(credential.privateKey, 'base64');
    try {
      const signature = sign('sha256', Buffer.concat([authenticatorData, clientDataHash]), { key: createPrivateKey({ key: privateBytes, format: 'der', type: 'pkcs8' }), dsaEncoding: 'der' });
      // Counter stays zero for a credential eligible for encrypted multi device backup.
      await engine.record('passkey.asserted', item.id, rpId); stillUnlocked(initial);
      if (!find()) throw new Error('Item not found');
      return { relyingParty: rpId, clientDataHash: clientDataHash.toString('base64'), credentialId, signature: signature.toString('base64'), authenticatorData: authenticatorData.toString('base64'), userHandle: credential.userHandle };
    } finally { privateBytes.fill(0); }
  };
}
