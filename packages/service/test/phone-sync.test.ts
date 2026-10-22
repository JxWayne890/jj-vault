import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, readFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { X509Certificate } from 'node:crypto';
import { VaultEngine, newItem, type Envelope } from '../../core/src/index.ts';
import { atomicOwnerWrite } from '../src/security.ts';
import { createPhoneSyncManager, phoneSyncContentFingerprint, validatePhoneCertificate, type PhonePairing, type PhoneSyncOptions } from '../src/phone-sync.ts';

async function fixture(options: Partial<PhoneSyncOptions> = {}) {
  let envelope: Envelope | null = null;
  const engine = new VaultEngine({ read: async () => envelope && structuredClone(envelope), write: async value => { envelope = structuredClone(value); } });
  const created = await engine.initialize('fictional phone master passphrase');
  await engine.upsertItem({ ...newItem('login', 'Synthetic phone login', engine.data().vaults[0].id), password: 'fictional phone item password', urls:['https://example.invalid'] });
  const directory = await mkdtemp(join(tmpdir(), 'jj-phone-sync-')); await chmod(directory, 0o700);
  const manager = await createPhoneSyncManager(directory, engine, { httpPort:0,tlsPort:0,host:'127.0.0.1',hostname:'localhost',addresses:()=>['127.0.0.1'],intervalMs:0,...options });
  return { engine, directory, manager, secretKey:created.secretKey };
}
function pem(pairing:PhonePairing) { return new X509Certificate(Buffer.from(pairing.certificate,'base64')).toString(); }
async function secure(pairing:PhonePairing,path:string,body?:unknown,token?:string,extra:Record<string,string>={},servername='localhost',method?:string,targetHost='127.0.0.1'):Promise<{status:number;body:any;certificate:Buffer}> {
  const address = new URL(pairing.url);
  return new Promise((resolve,reject)=>{
    const request=httpsRequest({hostname:targetHost,port:address.port,path,method:method || (body?'POST':'GET'),servername,ca:pem(pairing),rejectUnauthorized:true,headers:{Host:address.host,...(body?{'Content-Type':'application/json'}:{}),...(token?{Authorization:`Bearer ${token}`} :{}),...extra}},response=>{
      const certificate=(response.socket as import('node:tls').TLSSocket).getPeerCertificate().raw;const chunks:Buffer[]=[];response.on('data',chunk=>chunks.push(Buffer.from(chunk)));response.on('end',()=>{try{resolve({status:response.statusCode!,body:JSON.parse(Buffer.concat(chunks).toString()),certificate});}catch(error){reject(error);}});
    });request.on('error',reject);request.setTimeout(5000,()=>request.destroy(new Error('Synthetic request timed out')));request.end(body?JSON.stringify(body):undefined);
  });
}
async function pair(f:Awaited<ReturnType<typeof fixture>>) { const qr=await f.manager.startPairing();const response=await secure(qr,'/pair',{nonce:qr.nonce});assert.equal(response.status,200);return {qr,...response.body as {token:string;revision:number;envelope:Envelope}}; }

test('phone sync is disabled by default and creates no private folder, listener, or certificate',async t=>{
  const f=await fixture();t.after(()=>f.manager.close());assert.deepEqual(f.manager.status(),{enabled:false,running:false,paired:false});await assert.rejects(lstat(join(f.directory,'phone-sync')),/ENOENT/);
});

test('pairing uses an owner pinned TLS certificate and one time nonce without unlock secrets',async t=>{
  const f=await fixture();t.after(()=>f.manager.close());const qr=await f.manager.startPairing();
  assert.equal(qr.type,'jjvault-pairing');assert.equal(qr.version,1);assert.match(qr.nonce,/^[A-Za-z0-9_-]{43}$/);assert(Math.abs(Date.parse(qr.expiresAt)-Date.now()-120000)<3000);
  assert(!JSON.stringify(qr).includes(f.secretKey));assert(!JSON.stringify(qr).includes('fictional phone'));assert(!JSON.stringify(qr).includes('jjv_'));
  const bad=await secure(qr,'/pair',{nonce:'wrong'});assert.equal(bad.status,401);
  const paired=await secure(qr,'/pair',{nonce:qr.nonce});assert.equal(paired.status,200);assert.deepEqual(paired.certificate,Buffer.from(qr.certificate,'base64'));assert.equal(paired.body.envelope.id,qr.vaultId);assert.equal(typeof paired.body.revision,'number');assert.equal(paired.body.envelope.format,'jjvault');assert(!JSON.stringify(paired.body).includes('fictional phone item password'));
  assert.equal((await secure(qr,'/pair',{nonce:qr.nonce})).status,401);assert.equal(f.manager.status().paired,true);
  assert.equal((await secure(qr,'/status')).status,401);const status=await secure(qr,'/status',undefined,paired.body.token);assert.equal(status.status,200);assert.deepEqual(Object.keys(status.body).sort(),['revision','vaultId']);assert.equal(status.body.vaultId,qr.vaultId);
  assert.equal((await secure(qr,'/status',undefined,paired.body.token,{Origin:'https://malicious.invalid'})).status,403);assert.equal((await secure(qr,'/status',undefined,paired.body.token,{Host:'malicious.invalid'})).status,403);
  for(const name of ['config.json','certificate.pem','private-key.pem','relay-token','relay.json'])assert.equal((await lstat(join(f.directory,'phone-sync',name))).mode&0o7777,0o600);
  assert.equal((await lstat(join(f.directory,'phone-sync'))).mode&0o7777,0o700);
  const files=await Promise.all(['config.json','certificate.pem','private-key.pem','relay-token','relay.json'].map(name=>readFile(join(f.directory,'phone-sync',name),'utf8')));for(const content of files){assert(!content.includes(f.secretKey));assert(!content.includes('fictional phone master passphrase'));assert(!content.includes('fictional phone item password'));}
});

test('phone pairing rejects expiration, cancellation, replacement, and vault lock',async t=>{
  let now=Date.now();const f=await fixture({now:()=>now});t.after(()=>f.manager.close());const expired=await f.manager.startPairing();now+=120001;assert.equal((await secure(expired,'/pair',{nonce:expired.nonce})).status,401);
  const cancelled=await f.manager.startPairing();f.manager.cancelPairing();assert.equal((await secure(cancelled,'/pair',{nonce:cancelled.nonce})).status,401);
  const replaced=await f.manager.startPairing();const newest=await f.manager.startPairing();assert.equal((await secure(replaced,'/pair',{nonce:replaced.nonce})).status,401);
  const key=f.engine.exportSessionKey();f.engine.lock();await f.engine.unlockWithKey(key);key.fill(0);assert.equal((await secure(newest,'/pair',{nonce:newest.nonce})).status,401);
  f.engine.lock();await assert.rejects(f.manager.startPairing(),/^Error: Vault is locked$/);
});

test('phone TLS enforces hostname and certificate validity instead of accepting arbitrary self signed certificates',async t=>{
  const f=await fixture();t.after(()=>f.manager.close());const qr=await f.manager.startPairing();const cert=await readFile(join(f.directory,'phone-sync','certificate.pem'),'utf8');const key=await readFile(join(f.directory,'phone-sync','private-key.pem'),'utf8');
  const leaf=validatePhoneCertificate(cert,key,'localhost',['127.0.0.1']);assert(leaf.checkHost('localhost'));assert(leaf.checkIP('127.0.0.1'));
  assert.throws(()=>validatePhoneCertificate(cert,key,'wrong.local',['127.0.0.1']),/Invalid/);assert.throws(()=>validatePhoneCertificate(cert,key,'localhost',['127.0.0.2']),/Invalid/);assert.throws(()=>validatePhoneCertificate(cert,key,'localhost',['127.0.0.1'],Date.parse(leaf.validTo)+1),/Invalid/);assert.throws(()=>validatePhoneCertificate(cert,key,'localhost',['127.0.0.1'],Date.parse(leaf.validFrom)-1),/Invalid/);
  await assert.rejects(secure(qr,'/status',undefined,undefined,{},'wrong.local'),/Hostname|altnames|certificate/i);
  const other=await fixture();t.after(()=>other.manager.close());const otherQR=await other.manager.startPairing();await assert.rejects(secure({...qr,certificate:otherQR.certificate},'/status'),/certificate|self.signed|signature/i);
});

test('Mac and phone exchange only ciphertext and merge edits through real HTTP and TLS revision checks',async t=>{
  const f=await fixture();t.after(()=>f.manager.close());const paired=await pair(f);let phoneEnvelope=paired.envelope;const key=f.engine.exportSessionKey();
  const phone=new VaultEngine({read:async()=>phoneEnvelope,write:async value=>{phoneEnvelope=structuredClone(value);}});await phone.unlockWithKey(key);key.fill(0);
  await phone.upsertItem({...newItem('secureNote','Phone added note',phone.data().vaults[0].id),notes:'fictional private phone note'});
  const current=await secure(paired.qr,'/vault',undefined,paired.token);const outgoing=await phone.exportForSync();
  const response=await secure(paired.qr,'/vault',{expectedRevision:current.body.revision,envelope:outgoing},paired.token,{},'localhost','PUT');assert.equal(response.status,200);assert.equal(typeof response.body.revision,'number');
  const conflict=await secure(paired.qr,'/vault',{expectedRevision:current.body.revision,envelope:outgoing},paired.token,{},'localhost','PUT');assert.equal(conflict.status,409);
  await f.manager.poll();assert(f.engine.data().items.some(item=>item.title==='Phone added note'));
  const relay=await readFile(join(f.directory,'phone-sync','relay.json'),'utf8');assert(!relay.includes('fictional private phone note'));assert(!relay.includes('Phone added note'));
});

test('content polling ignores activity and agent quota changes, while item changes cause a sync',async t=>{
  const f=await fixture();t.after(()=>f.manager.close());await pair(f);const first=f.manager.status().revision;const fingerprint=phoneSyncContentFingerprint(f.engine);await f.engine.record('synthetic.activity');
  const agent=await f.engine.createToken('Synthetic agent');f.engine.data().assistantTokens[0].calls.push(Date.now());await f.engine.save();assert.equal(phoneSyncContentFingerprint(f.engine),fingerprint);
  await f.manager.poll();assert.equal(f.manager.status().revision,first);
  await f.engine.upsertItem({...newItem('login','New Mac login',f.engine.data().vaults[0].id),password:'fictional new secret'});await f.manager.poll();assert(f.manager.status().revision!>first!);assert(f.engine.authenticateToken(agent.token));
});

test('disable stops listeners and revokes the old phone credential, while app close preserves enabled configuration',async t=>{
  const f=await fixture();const first=await pair(f);await f.manager.close();assert.equal(f.manager.status().enabled,true);assert.equal(f.manager.status().running,false);
  const restored=await createPhoneSyncManager(f.directory,f.engine,{httpPort:0,tlsPort:0,host:'127.0.0.1',hostname:'localhost',addresses:()=>['127.0.0.1'],intervalMs:0});t.after(()=>restored.close());assert.equal(restored.status().running,true);assert.equal(restored.status().paired,true);
  const next=await restored.startPairing();assert.equal((await secure(next,'/status',undefined,first.token)).status,200);await restored.disable();assert.equal(restored.status().enabled,false);const rotated=await restored.startPairing();assert.equal((await secure(rotated,'/status',undefined,first.token)).status,401);
});

test('unsafe phone sync directories are rejected without starting a listener',async t=>{
  const f=await fixture();t.after(()=>f.manager.close());const elsewhere=await mkdtemp(join(tmpdir(),'jj-phone-outside-'));await symlink(elsewhere,join(f.directory,'phone-sync'));await assert.rejects(f.manager.startPairing(),/Unable to start/);assert.equal(f.manager.status().running,false);
});

test('a lock and resumed session during pairing setup cannot return a QR for the new session',async t=>{
  const f=await fixture();t.after(()=>f.manager.close());const key=f.engine.exportSessionKey();const starting=f.manager.startPairing();f.engine.lock();await f.engine.unlockWithKey(key);key.fill(0);await assert.rejects(starting,/Vault is locked/);
});

test('cancelling while certificate creation is pending prevents the eventual pairing QR',async t=>{
  const f=await fixture();t.after(()=>f.manager.close());const starting=f.manager.startPairing();f.manager.cancelPairing();await assert.rejects(starting,/cancelled/);
});

test('configured startup failures are reported in metadata without locking or crashing the vault',async t=>{
  const f=await fixture();await pair(f);await f.manager.close();
  const restored=await createPhoneSyncManager(f.directory,f.engine,{httpPort:0,tlsPort:0,addresses:()=>[],intervalMs:0});t.after(()=>restored.close());assert.equal(restored.status().running,false);assert.equal(restored.status().enabled,true);assert(restored.status().lastError);assert.equal(f.engine.status().locked,false);
});


test('owner pairing refreshes a changed LAN address set and rotates the pinned identity and credential',async t=>{
  const f=await fixture();await f.manager.close();let addresses=['127.0.0.1'];
  const manager=await createPhoneSyncManager(f.directory,f.engine,{httpPort:0,tlsPort:0,host:'127.0.0.1',hostname:'localhost',addresses:()=>addresses,intervalMs:0});t.after(()=>manager.close());
  const first=await manager.startPairing();const paired=await secure(first,'/pair',{nonce:first.nonce});assert.equal(paired.status,200);
  addresses=['127.0.0.1','127.0.0.2'];const updated=await manager.startPairing();assert.notEqual(updated.certificate,first.certificate);assert.equal(manager.status().paired,false);
  assert.equal((await secure(updated,'/status',undefined,paired.body.token,{},'localhost',undefined,'127.0.0.1')).status,401);
  const repaired=await secure(updated,'/pair',{nonce:updated.nonce},undefined,{},'localhost',undefined,'127.0.0.1');assert.equal(repaired.status,200);assert.notEqual(repaired.body.token,paired.body.token);
  await assert.rejects(secure({...updated,certificate:first.certificate},'/status',undefined,repaired.body.token,{},'localhost',undefined,'127.0.0.1'),/certificate|self.signed|signature/i);
});


for (const boundary of ['cancel', 'lock', 'resume', 'expire', 'none'] as const) {
  test(`queued phone pairing revalidates its consumed nonce lease after ${boundary}`, async t => {
    let clock = Date.now(); let pauseNext = false; let entered!: () => void; let release!: () => void;
    const blocked = new Promise<void>(resolve => { release = resolve; });
    const waiting = new Promise<void>(resolve => { entered = resolve; });
    const f = await fixture({ now: () => clock, writeRelay: async (file, value) => { if (pauseNext) { pauseNext = false; entered(); await blocked; } await atomicOwnerWrite(file, value); } });
    t.after(async () => { release(); await f.manager.close(); });
    const existing = await pair(f); const pending = await f.manager.startPairing();
    const before = f.engine.data().activity.filter(entry => entry.action === 'phone.paired').length;
    const revision = f.manager.status().revision!; const envelope = await f.engine.exportForSync();
    pauseNext = true;
    const writing = secure(pending, '/vault', { expectedRevision: revision, envelope }, existing.token, {}, 'localhost', 'PUT');
    await waiting;
    // Exactly one request consumes the nonce and waits for the relay queue. The other
    // returns 401 immediately, proving that the winning request crossed that boundary.
    const first = secure(pending, '/pair', { nonce: pending.nonce });
    const second = secure(pending, '/pair', { nonce: pending.nonce });
    assert.equal((await Promise.race([first, second])).status, 401);
    if (boundary === 'cancel') f.manager.cancelPairing();
    if (boundary === 'lock') f.engine.lock();
    if (boundary === 'resume') { const key = f.engine.exportSessionKey(); f.engine.lock(); await f.engine.unlockWithKey(key); key.fill(0); }
    if (boundary === 'expire') clock += 120001;
    release(); assert.equal((await writing).status, 200);
    const replies = await Promise.all([first, second]);
    if (boundary === 'none') {
      assert.deepEqual(replies.map(reply => reply.status).sort(), [200, 401]);
      assert.equal(replies.find(reply => reply.status === 200)!.body.token, existing.token);
    } else {
      assert.deepEqual(replies.map(reply => reply.status), [401, 401]);
      for (const reply of replies) { assert.equal(reply.body.token, undefined); assert.equal(reply.body.envelope, undefined); assert(!JSON.stringify(reply.body).includes(existing.token)); }
      if (!f.engine.status().locked) assert.equal(f.engine.data().activity.filter(entry => entry.action === 'phone.paired').length, before);
    }
    assert.equal((await secure(pending, '/pair', { nonce: pending.nonce })).status, 401);
  });
}
