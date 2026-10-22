import {randomBytes, createCipheriv, createDecipheriv, hkdfSync} from 'node:crypto';
import {argon2id} from 'hash-wasm';
import {AGENT_PERMISSIONS,type Envelope,type VaultData,type AgentPermission} from './types.ts';

export function generateSecretKey():string {return `JJ1.${randomBytes(32).toString('base64url')}`;}
export function secretBytes(secret:string):Buffer {
  if (!/^JJ1\.[A-Za-z0-9_-]{43}$/.test(secret.trim())) throw new Error('Invalid Secret Key');
  const b=Buffer.from(secret.trim().slice(4),'base64url');
  if(b.length!==32 || b.toString('base64url')!==secret.trim().slice(4)) throw new Error('Invalid Secret Key');
  return b;
}
export function validateEnvelope(x:unknown):asserts x is Envelope {
  const e=x as Envelope;
  if(!e || e.format!=='jjvault'||e.version!==1||typeof e.id!=='string'||!/^[a-zA-Z0-9-]{8,80}$/.test(e.id)||e.kdf?.algorithm!=='argon2id') throw new Error('Unsupported vault format');
  const k=e.kdf;
  if(!Number.isInteger(k.memoryKiB)||k.memoryKiB<65536||k.memoryKiB>262144||!Number.isInteger(k.iterations)||k.iterations<3||k.iterations>10||k.parallelism!==1) throw new Error('Unsafe or unsupported key derivation parameters');
  for(const v of [k.salt,e.iv,e.ciphertext]) if(typeof v!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(v)) throw new Error('Invalid encrypted data');
  if(Buffer.from(k.salt,'base64').length!==16||Buffer.from(e.iv,'base64').length!==12||Buffer.from(e.ciphertext,'base64').length<16||e.ciphertext.length>100_000_000) throw new Error('Invalid encrypted data size');
}
export function aad(e:Envelope):Buffer {return Buffer.from(`JJVault:1:${e.id}:${e.kdf.salt}:${e.kdf.memoryKiB}:${e.kdf.iterations}:${e.kdf.parallelism}`);}
export function newEnvelope():Envelope {return {format:'jjvault',version:1,id:crypto.randomUUID(),kdf:{algorithm:'argon2id',salt:randomBytes(16).toString('base64'),memoryKiB:65536,iterations:3,parallelism:1},iv:randomBytes(12).toString('base64'),ciphertext:''};}
export async function deriveKey(password:string,secret:string,e:Envelope):Promise<Buffer> {
  // Validate before expensive work. A new envelope has no ciphertext yet.
  validateEnvelope({...e,ciphertext:e.ciphertext || Buffer.alloc(16).toString('base64')});
  if(typeof password!=='string'||password.length>4096) throw new Error('Invalid master password');
  const s=secretBytes(secret);
  const intermediate=await argon2id({password:password.normalize('NFKC'),salt:Buffer.from(e.kdf.salt,'base64'),parallelism:1,iterations:e.kdf.iterations,memorySize:e.kdf.memoryKiB,hashLength:32,outputType:'binary'});
  try{return Buffer.from(hkdfSync('sha256',intermediate,s,Buffer.from('JJ Vault root key v1'),32));}
  finally {intermediate.fill(0);s.fill(0);}
}
export function seal(data:VaultData,key:Uint8Array,base:Envelope):Envelope {
  if(key.byteLength!==32) throw new Error('Invalid key');
  const e={...base,kdf:{...base.kdf},iv:randomBytes(12).toString('base64')};
  const cipher=createCipheriv('aes-256-gcm',key,Buffer.from(e.iv,'base64'));
  cipher.setAAD(aad(e));
  const plaintext=Buffer.from(JSON.stringify(data));
  try{e.ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final(),cipher.getAuthTag()]).toString('base64');return e;}
  finally{plaintext.fill(0);}
}
export function open(e:Envelope,key:Uint8Array):VaultData {
  validateEnvelope(e);
  const c=Buffer.from(e.ciphertext,'base64');const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(e.iv,'base64'));
  decipher.setAAD(aad(e));decipher.setAuthTag(c.subarray(-16));
  let plain:Buffer|undefined;
  try{plain=Buffer.concat([decipher.update(c.subarray(0,-16)),decipher.final()]);const d=JSON.parse(plain.toString());validateData(d);return d;}
  catch {throw new Error('Unable to unlock. Check the master password and Secret Key, or restore a valid backup.');}
  finally {plain?.fill(0);}
}
export function validateData(d:unknown):asserts d is VaultData {
  const v=d as VaultData;
  if(v?.schema!==1||!Array.isArray(v.items)||!Array.isArray(v.vaults)||!Array.isArray(v.activity)||!Array.isArray(v.assistantTokens)||!v.settings||!Number.isInteger(v.revision)||typeof v.deviceId!=='string')throw new Error('Invalid vault content');
  if(v.items.length>100000||v.vaults.length>1000)throw new Error('Vault limit exceeded');
  const ids=new Set<string>();
  for(const i of v.items){if(typeof i.id!=='string'||ids.has(i.id)||typeof i.title!=='string'||!Array.isArray(i.urls)||!Array.isArray(i.fields)||!Array.isArray(i.tags)||!Array.isArray(i.passwordHistory)||!Array.isArray(i.attachments)||!v.vaults.some(x=>x.id===i.vaultId))throw new Error('Invalid item');ids.add(i.id);}
  if(v.settings.agentRequireItemApproval===undefined)v.settings.agentRequireItemApproval=false;
  if(typeof v.settings.agentRequireItemApproval!=='boolean')throw new Error('Invalid agent approval setting');
  const clients=new Set<string>();
  for(const t of v.assistantTokens){
    if(!t||typeof t.id!=='string'||typeof t.name!=='string'||t.name.length>128||typeof t.hash!=='string'||!/^[a-f0-9]{64}$/.test(t.hash)||!Array.isArray(t.calls)||t.calls.some(n=>!Number.isFinite(n)||n<0))throw new Error('Invalid agent token');
    if(t.clientName===undefined){
      const known=/\bcodex\b/i.test(t.name)?'codex':/\bdots?\b/i.test(t.name)?'dots':/\bgrok(?:u| bot)?\b/i.test(t.name)?'grok':t.name.toLowerCase().replace(/[^a-z0-9_-]+/g,'_').replace(/^[^a-z]+/,'').slice(0,48)||'agent';
      let candidate=known;let suffix=2;while(clients.has(candidate))candidate=known+'_'+suffix++;t.clientName=candidate;
    }
    if(!/^[a-z][a-z0-9_-]{0,63}$/.test(t.clientName)||clients.has(t.clientName))throw new Error('Invalid or duplicate agent client name');clients.add(t.clientName);
    if(t.permission===undefined)t.permission='full';
    if(!AGENT_PERMISSIONS.includes(t.permission as AgentPermission))throw new Error('Invalid agent permission');
    if(t.vaultIds===undefined)t.vaultIds=v.vaults.filter(vault=>vault.allowAssistant).map(vault=>vault.id);
    if(!Array.isArray(t.vaultIds)||t.vaultIds.some(id=>typeof id!=='string'||!v.vaults.some(vault=>vault.id===id))||new Set(t.vaultIds).size!==t.vaultIds.length)throw new Error('Invalid agent vault access');
    if(t.writeCalls===undefined)t.writeCalls=[];
    if(!Array.isArray(t.writeCalls)||t.writeCalls.some(n=>!Number.isFinite(n)||n<0))throw new Error('Invalid agent write history');
  }
  if(!Number.isFinite(v.settings.idleMinutes)||(v.settings.idleMinutes!==0&&v.settings.idleMinutes<1)||v.settings.idleMinutes>1440)throw new Error('Invalid lock timeout');
}
export async function encryptData(data:VaultData,password:string,secret:string):Promise<Envelope>{const e=newEnvelope();const key=await deriveKey(password,secret,e);try{return seal(data,key,e);}finally{key.fill(0);}}
export async function decryptData(e:Envelope,password:string,secret:string):Promise<VaultData>{validateEnvelope(e);const key=await deriveKey(password,secret,e);try{return open(e,key);}finally{key.fill(0);}}
