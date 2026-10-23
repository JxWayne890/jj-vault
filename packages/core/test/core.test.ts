import test from 'node:test';
import assert from 'node:assert/strict';
import {VaultEngine,generateSecretKey,decryptData,encryptData,validateData,matchesUrl,totp,generatePassword,newItem,mergeData,watchtower,checkBreach,importCSV,import1PUX} from '../src/index.ts';
import {zipSync,strToU8} from 'fflate';
import type {Envelope} from '../src/types.ts';
async function fixture(){let disk:Envelope|null=null;const engine=new VaultEngine({read:async()=>disk&&structuredClone(disk),write:async x=>{disk=structuredClone(x);}});const password='A fixture master password with 32 chars';const {secretKey}=await engine.initialize(password);return {engine,password,secretKey,disk:()=>disk!};}
test('new vaults start with generic names and assistant access disabled',async()=>{
  const {engine}=await fixture();
  assert.deepEqual(engine.data().vaults.map(v=>v.name),['Personal','Business','Social Media']);
  assert.equal(new Set(engine.data().vaults.map(v=>v.id)).size,3);
  assert.ok(engine.data().vaults.every(v=>v.allowAssistant===false));
});
test('existing vault names survive loading, saving and locking without a migration',async()=>{
  const f=await fixture();
  const existing=structuredClone(f.engine.data());
  existing.vaults[1].name='MCC Business';
  existing.vaults[2].name='Existing Team Vault';
  const names=existing.vaults.map(v=>v.name);
  let disk=await encryptData(existing,f.password,f.secretKey);
  const engine=new VaultEngine({read:async()=>structuredClone(disk),write:async envelope=>{disk=structuredClone(envelope);}});
  await engine.load();
  await engine.unlock(f.password,f.secretKey);
  assert.deepEqual(engine.data().vaults.map(v=>v.name),names);
  await engine.save();
  engine.lock();
  await engine.unlock(f.password,f.secretKey);
  assert.deepEqual(engine.data().vaults.map(v=>v.name),names);
  assert.equal(engine.data().schema,1);
});
test('both secrets required, random nonces, ciphertext authentication and parameter bounds',async()=>{const f=await fixture();const d=f.engine.data();const i=newItem('login','Example',d.vaults[0].id);i.password='Never stored in plaintext';await f.engine.upsertItem(i);const e=f.disk();assert.ok(!JSON.stringify(e).includes(i.password));assert.equal((await decryptData(e,f.password,f.secretKey)).items[0].password,i.password);await assert.rejects(decryptData(e,'wrong',f.secretKey));await assert.rejects(decryptData(e,f.password,generateSecretKey()));const tampered=structuredClone(e);tampered.ciphertext=Buffer.from('0'.repeat(100)).toString('base64');await assert.rejects(decryptData(tampered,f.password,f.secretKey));const changed=structuredClone(e);changed.id=crypto.randomUUID();await assert.rejects(decryptData(changed,f.password,f.secretKey));const expensive=structuredClone(e);expensive.kdf.memoryKiB=2**30;await assert.rejects(decryptData(expensive,f.password,f.secretKey),/parameters/);await f.engine.save();assert.notEqual(e.iv,f.disk().iv);});
test('lock clears access and biometric session key unlocks the encrypted document',async()=>{const f=await fixture();const key=f.engine.exportSessionKey();f.engine.lock();assert.throws(()=>f.engine.data(),/Vault is locked/);await f.engine.unlockWithKey(key);key.fill(0);assert.equal(f.engine.status().locked,false);f.engine.data().settings.idleMinutes=1;(f.engine as any).lastTouch=Date.now()-61000;f.engine.checkIdle();assert.equal(f.engine.status().locked,true);await f.engine.unlock(f.password,f.secretKey);assert.ok(f.engine.data().activity.some(a=>a.action==='vault.locked'));});
test('Never idle policy survives encrypted reload and leaves manual locking available',async()=>{
  const f=await fixture();
  f.engine.data().settings.idleMinutes=0;
  await f.engine.save();
  let encrypted=structuredClone(f.disk());
  assert.equal((await decryptData(encrypted,f.password,f.secretKey)).settings.idleMinutes,0);
  const reloaded=new VaultEngine({read:async()=>structuredClone(encrypted),write:async envelope=>{encrypted=structuredClone(envelope);}});
  await reloaded.load();
  await reloaded.unlock(f.password,f.secretKey);
  assert.equal(reloaded.data().settings.idleMinutes,0);
  (reloaded as any).lastTouch=Date.now()-24*60*60*1000;
  reloaded.checkIdle();
  assert.equal(reloaded.status().locked,false);
  assert.equal(reloaded.data().settings.idleMinutes,0);
  const invalid=structuredClone(reloaded.data());
  for(const minutes of [-1,0.5,1441,NaN]){
    invalid.settings.idleMinutes=minutes;
    assert.throws(()=>validateData(invalid),/Invalid lock timeout/);
  }
  reloaded.lock();
  assert.equal(reloaded.status().locked,true);
  assert.throws(()=>reloaded.exportSessionKey(),/Vault is locked/);
});
test('positive idle policy still locks after its timeout',async()=>{
  const {engine}=await fixture();
  assert.equal(engine.data().settings.idleMinutes,5);
  engine.data().settings.idleMinutes=1;
  engine.touch();
  engine.checkIdle();
  assert.equal(engine.status().locked,false);
  (engine as any).lastTouch=Date.now()-61000;
  engine.checkIdle();
  assert.equal(engine.status().locked,true);
  assert.throws(()=>engine.data(),/Vault is locked/);
});
test('full password history and recently deleted restore do not reenable assistant',async()=>{const {engine}=await fixture();const v=engine.data().vaults[0];const i=await engine.upsertItem({...newItem('login','History',v.id),password:'old',allowAssistant:true});await engine.upsertItem({...i,password:'new'});assert.equal(engine.data().items[0].passwordHistory[0].password,'old');await engine.deleteItem(i.id);assert.equal(engine.browserList('https://example.com').length,0);await engine.restoreItem(i.id);assert.equal(engine.data().items[0].allowAssistant,false);assert.equal(engine.data().items[0].deletedAt,undefined);});
test('assistant rules deny default vault access, bank, X Money, archives, travel and revoked tokens',async()=>{const {engine}=await fixture();const vaultId=engine.data().vaults[0].id;const {token,id}=await engine.createToken('Fixture',{vaultIds:[vaultId]});const i=await engine.upsertItem({...newItem('login','Example',vaultId),urls:['https://example.com'],password:'fixture',allowAssistant:true});assert.deepEqual(await engine.listAssistantLogins(token),[]);engine.data().vaults[0].allowAssistant=true;assert.equal((await engine.listAssistantLogins(token)).length,1);assert.equal((await engine.getAssistantLogin(token,i.title)).password,'fixture');for(const [type,title,url]of [['bankAccount','Bank','https://bank.example'],['login','X Money','https://x.com'],['login','Payment','https://money.x.com']] as const){await engine.upsertItem({...newItem(type,title,vaultId),urls:[url],allowAssistant:true});}assert.equal((await engine.listAssistantLogins(token)).length,1);engine.data().settings.travelMode=true;assert.deepEqual(await engine.listAssistantLogins(token),[]);engine.data().settings.travelMode=false;await engine.revokeToken(id);await assert.rejects(engine.getAssistantLogin(token,i.title),/Invalid API token/);engine.lock();await assert.rejects(engine.getAssistantLogin(token,i.title),/Vault is locked/);});
test('assistant rate limit is per agent and survives lock and concurrent requests',async()=>{const f=await fixture();const v=f.engine.data().vaults[0];v.allowAssistant=true;await f.engine.upsertItem({...newItem('login','Test',v.id),allowAssistant:true});const a=await f.engine.createToken('a');const b=await f.engine.createToken('b');const r=await Promise.allSettled(Array.from({length:24},(_,n)=>f.engine.getAssistantLogin(n%2?a.token:b.token,'Test')));assert.equal(r.filter(x=>x.status==='fulfilled').length,20);f.engine.lock();await f.engine.unlock(f.password,f.secretKey);await assert.rejects(f.engine.getAssistantLogin(a.token,'Test'),/Rate limit/);});
test('autofill exact origin semantics reject suffix spoofing, subdomains, ports and HTTP downgrade',()=>{assert.ok(matchesUrl('https://example.com/login','https://example.com/path'));for(const url of ['http://example.com','https://example.com.evil.test','https://evil.example.com','https://example.com:444','https://user:pass@example.com'])assert.equal(matchesUrl('https://example.com',url),false);assert.ok(matchesUrl('http://localhost:3000','http://localhost:3000/login'));});
test('RFC 6238 TOTP vectors and generator controls',async()=>{const s='otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8';assert.equal(await totp(s,59000),'94287082');assert.equal(await totp(s,1111111109000),'07081804');assert.match(generatePassword({mode:'pin',length:8}),/^\d{8}$/);assert.equal(generatePassword({mode:'passphrase',words:6}).split(' ').length,6);assert.match(generatePassword({length:32,upper:false,lower:false,symbols:false}),/^\d{32}$/);assert.throws(()=>generatePassword({upper:false,lower:false,digits:false,symbols:false}));});
test('Watchtower findings, breach range sends only five hash characters and padded request',async()=>{const i={...newItem('login','Weak','v'),password:'password',urls:['http://example.com'],expiresAt:'2020-01-01'};const report=await watchtower([i,{...i,id:'other'}]);assert.equal(report.score,0);for(const kind of ['weak','reused','missing2fa','http','expiring'])assert.ok(report.findings.some(f=>f.kind===kind));const fetcher=(async(input:any,init:any)=>{assert.equal(input,'https://api.pwnedpasswords.com/range/5BAA6');assert.equal(init.headers['Add-Padding'],'true');assert.ok(!JSON.stringify(init).includes('password'));return new Response('1E4C9B93F3F0682250B6CF8331B7EE68FD8:123\r\n00000000000000000000000000000000000:0');})as typeof fetch;assert.equal(await checkBreach('password',fetcher),123);});
test('encrypted backup roundtrip, travel export and sync tombstones',async()=>{const f=await fixture();const v=f.engine.data().vaults[0];await f.engine.upsertItem({...newItem('login','Travel secret',v.id),password:'hidden'});v.travelSafe=false;f.engine.data().settings.travelMode=true;const sync=await f.engine.exportForSync();const syncData=await decryptData(sync,f.password,f.secretKey);assert.equal(syncData.items.length,0);assert.equal(syncData.assistantTokens.length,0);const backup=await f.engine.exportEncrypted();assert.equal((await decryptData(backup,f.password,f.secretKey)).items.length,1);const local=structuredClone(f.engine.data());const remote=structuredClone(local);local.items[0].deletedAt=new Date().toISOString();remote.items[0].updatedAt='9999';const merged=mergeData(local,remote);assert.ok(merged.items[0].deletedAt);});
test('CSV imports quote handling and 1PUX attachments',()=>{const items=importCSV('name,url,username,password,notes\r\n"A, B",https://example.com,joe,"p""ass","line1\nline2"','v');assert.equal(items[0].password,'p"ass');assert.equal(items[0].notes,'line1\nline2');assert.equal(items[0].allowAssistant,false);const archive=zipSync({'export.data':strToU8(JSON.stringify({accounts:[{vaults:[{attrs:{name:'Personal'},items:[{categoryUuid:'001',overview:{title:'Test'},details:{loginFields:[{designation:'password',value:'fixture'}],documentAttributes:{documentId:'abc',fileName:'test.txt'}}}]}]}]})),'files/abc__test.txt':strToU8('attachment fixture')});const r=import1PUX(archive);assert.equal(r.items[0].password,'fixture');assert.equal(Buffer.from(r.items[0].attachments[0].data,'base64').toString(),'attachment fixture');});
test('1Password current headers, original category IDs and imported password history survive saving',async()=>{const csv=importCSV('Title,Website,Username,Password,One-time password,Favorite status,Archived status\nFixture,https://example.test,user,fixture,JBSWY3DPEHPK3PXP,true,true','v');assert.equal(csv[0].totp,'JBSWY3DPEHPK3PXP');assert.ok(csv[0].favorite&&csv[0].archived);const archive=zipSync({'export.data':strToU8(JSON.stringify({accounts:[{vaults:[{attrs:{name:'Imported'},items:[{categoryUuid:'005',favIndex:1,overview:{title:'Password'},details:{password:'current',passwordHistory:[{value:'previous',time:1700000000}]}},...['105','106','109','114'].map(categoryUuid=>({categoryUuid,overview:{title:categoryUuid},details:{}}))]}]}]}))});const r=import1PUX(archive);assert.deepEqual(r.items.map(i=>i.type),['password','membership','passport','wifi','sshKey']);assert.equal(r.items[0].password,'current');assert.ok(r.items[0].favorite);const {engine}=await fixture();engine.data().vaults.push(...r.vaults);await engine.upsertItem(r.items[0]);assert.equal(engine.data().items[0].passwordHistory[0].password,'previous');});

test('PIN key unlock preserves recovery secrets and records the correct unlock reason',async()=>{
  const f=await fixture();
  const key=f.engine.exportSessionKey();
  const before=structuredClone(f.disk());
  try{
    f.engine.lock();
    await f.engine.unlockWithKey(key,'pin');
    assert.equal(f.engine.status().locked,false);
    assert.ok(f.engine.data().activity.some(a=>a.action==='vault.pinUnlock'));
    assert.equal(f.disk().id,before.id);
    assert.deepEqual(f.disk().kdf,before.kdf);
    f.engine.lock();
    await f.engine.unlock(f.password,f.secretKey);
    assert.equal(f.engine.status().locked,false);
  }finally{key.fill(0);}
});

test('restore invalidates device credentials only after verification and before replacement',async()=>{
  const current=await fixture(),backup=await fixture();
  const old=structuredClone(current.disk());
  let invalidated=false;
  const invalidate=()=>{invalidated=true;assert.deepEqual(current.disk(),old);};
  await assert.rejects(current.engine.importEncrypted(backup.disk(),'Incorrect recovery password',backup.secretKey,invalidate));
  assert.equal(invalidated,false);
  assert.deepEqual(current.disk(),old);
  await assert.rejects(current.engine.importEncrypted(backup.disk(),backup.password,backup.secretKey,()=>{throw new Error('Unable to remove protected cache');}),/Unable to remove/);
  assert.deepEqual(current.disk(),old);
  assert.equal(current.engine.status().locked,false);
  await current.engine.importEncrypted(backup.disk(),backup.password,backup.secretKey,invalidate);
  assert.equal(invalidated,true);
  assert.equal(current.disk().id,backup.disk().id);
});
