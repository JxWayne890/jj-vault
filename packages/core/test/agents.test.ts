import test from 'node:test';
import assert from 'node:assert/strict';
import {VaultEngine,newItem,decryptData,seal} from '../src/index.ts';
import type {Envelope,AgentPermission,VaultData} from '../src/types.ts';
async function fixture(){
  let disk:Envelope|null=null;let interceptor:((e:Envelope)=>Promise<void>)|undefined;
  const storage={read:async()=>disk&&structuredClone(disk),write:async(e:Envelope)=>{if(interceptor)await interceptor(e);disk=structuredClone(e);}};
  const engine=new VaultEngine(storage);const password='Private fixture master passphrase';const {secretKey}=await engine.initialize(password);
  engine.data().settings.idleMinutes=0;for(const v of engine.data().vaults)v.allowAssistant=true;
  const vaultIds=engine.data().vaults.map(v=>v.id);
  await engine.upsertItem({...newItem('login','Example',vaultIds[0]),urls:['https://example.test'],username:'fixture-user',password:'old fixture secret',notes:'private fixture notes',totp:'JBSWY3DPEHPK3PXP'});
  return {engine,password,secretKey,vaultIds,storage,disk:()=>disk!,intercept:(fn:typeof interceptor)=>{interceptor=fn;}};
}
const login=(vault:string,name='Added')=>({vault,name,website:'https://added.test',username:'someone',notes:'private new notes'});
test('agent permission levels are cumulative and default full with explicit per vault scope',async()=>{
  const f=await fixture();const {engine}=f;
  const defaults=await engine.createToken('Default agent',{clientName:'default_agent',vaultIds:[f.vaultIds[0]]});assert.equal(engine.authenticateToken(defaults.token)!.permission,'full');
  for(const [n,permission]of (['read','read_add','read_add_edit','full'] as AgentPermission[]).entries()){
    const a=await engine.createToken('Agent '+permission,{clientName:'agent_'+n,permission,vaultIds:[f.vaultIds[0]]});
    assert.equal((await engine.listAssistantLogins(a.token))[0].name,'Example');assert.equal((await engine.getAssistantLogin(a.token,'Example')).username,'fixture-user');
    const create=()=>engine.addAssistantLogin(a.token,login(f.vaultIds[0],'New '+n));if(n>=1)await create();else await assert.rejects(create(),/Permission denied/);
    const edit=()=>engine.updateAssistantLogin(a.token,'Example',{notes:'changed '+n});if(n>=2)await edit();else await assert.rejects(edit(),/Permission denied/);
    const remove=()=>engine.deleteAssistantLogin(a.token,'Example');if(n>=3)await remove();else await assert.rejects(remove(),/Permission denied/);
  }
});
test('agent client identity is unique and immutable, owner may rename, restrict and revoke it',async()=>{
  const {engine,vaultIds}=await fixture();const a=await engine.createToken('Grok Bot',{clientName:'grok18',vaultIds:[vaultIds[0]]});
  await assert.rejects(engine.createToken('Duplicate',{clientName:'grok18'}),/already exists/);
  for(const clientName of ['owner','admin','cli','browser','provider','admin-token','browser-token','provider-token','../grok','UPPER','18grok','a'.repeat(65)])await assert.rejects(engine.createToken('Bad',{clientName}),/client name/);
  await engine.updateAgent(a.id,{name:'Renamed Grok',permission:'read',vaultIds:[]});const record=engine.authenticateToken(a.token)!;assert.equal(record.clientName,'grok18');assert.equal(record.name,'Renamed Grok');assert.deepEqual(await engine.listAssistantLogins(a.token),[]);
  await assert.rejects(engine.updateAgent(a.id,{clientName:'evil'} as any),/Invalid agent settings/);await engine.revokeToken(a.id);await assert.rejects(engine.listAssistantLogins(a.token),/Invalid API token/);
});
test('vault scope, global vault permission, travel and archive boundaries are enforced without item opt in',async()=>{
  const f=await fixture();const a=await f.engine.createToken('Scoped',{vaultIds:[f.vaultIds[0]]});
  const extra=await f.engine.upsertItem({...newItem('login','Other vault',f.vaultIds[1]),urls:['https://other.test']});
  assert.equal(f.engine.data().items[0].allowAssistant,false);assert.equal((await f.engine.listAssistantLogins(a.token)).length,1);
  await assert.rejects(f.engine.getAssistantLogin(a.token,extra.title),/not found/);await assert.rejects(f.engine.addAssistantLogin(a.token,login(f.vaultIds[1])),/vault access denied/);
  f.engine.data().vaults[0].allowAssistant=false;assert.deepEqual(await f.engine.listAssistantLogins(a.token),[]);f.engine.data().vaults[0].allowAssistant=true;
  f.engine.data().settings.travelMode=true;assert.deepEqual(await f.engine.listAssistantLogins(a.token),[]);f.engine.data().settings.travelMode=false;
  await f.engine.upsertItem({...f.engine.data().items[0],archived:true});assert.deepEqual(await f.engine.listAssistantLogins(a.token),[]);
});
test('bank and X Money blocks include disguised item types, title, URL and candidate edits',async()=>{
  const {engine,vaultIds}=await fixture();const {token}=await engine.createToken('Bank test',{vaultIds});
  for(const [type,title,url]of [['bankAccount','Account','https://example.test'],['xMoney','Payments','https://example.test'],['login','X Money','https://x.com'],['login','Bank account','https://example.test'],['login','Payments site','https://money.x.com'],['login','Everyday account','https://secure.chase.com']] as const)await engine.upsertItem({...newItem(type,title,vaultIds[0]),urls:[url],password:'blocked fixture secret',allowAssistant:true});
  assert.deepEqual((await engine.listAssistantLogins(token)).map(i=>i.name),['Example']);assert.deepEqual(await engine.searchAssistantItems(token,'account'),[]);
  for(const name of ['Account','Payments','X Money','Bank account','Payments site','Everyday account']){
    await assert.rejects(engine.getAssistantLogin(token,name),/not found/);await assert.rejects(engine.updateAssistantLogin(token,name,{password:'new'}),/not found/);await assert.rejects(engine.deleteAssistantLogin(token,name),/not found/);
  }
  await assert.rejects(engine.addAssistantLogin(token,{...login(vaultIds[0]),name:'My Bank account'}),/blocked/);
  await assert.rejects(engine.addAssistantLogin(token,{...login(vaultIds[0]),website:'https://money.x.com'}),/blocked/);
  for(const fields of [{name:'X Money'},{website:'https://login.bankofamerica.com'},{name:'My savings account'}])await assert.rejects(engine.updateAssistantLogin(token,'Example',fields),/blocked/);
  assert.equal(engine.data().items.find(i=>i.title==='Example')!.password,'old fixture secret');
});
test('generated passwords, strict edit fields and password history preserve item security',async()=>{
  const {engine,vaultIds}=await fixture();const {token}=await engine.createToken('Writer',{vaultIds});
  const added=await engine.addAssistantLogin(token,login(vaultIds[0]));assert.deepEqual(Object.keys(added).sort(),['name','tags','vault','website']);const generated=(await engine.getAssistantLogin(token,'Added')).password;assert.equal(generated.length,32);
  await engine.updateAssistantLogin(token,'Added',{password:'replacement fixture password',totp_secret:'JBSWY3DPEHPK3PXP',tags:['test']});assert.equal(engine.data().items.find(i=>i.title==='Added')!.passwordHistory[0].password,generated);
  for(const fields of [{allowAssistant:true},{vaultId:vaultIds[1]},{type:'bankAccount'},{passwordHistory:[]},{__proto__:null,permission:'full'}])await assert.rejects(engine.updateAssistantLogin(token,'Added',fields as any),/Invalid login fields/);
  assert.match((await engine.generateAssistantPassword(token,{length:24,upper:false,lower:false,symbols:false})).password,/^\d{24}$/);
  await engine.upsertItem({...newItem('secureNote','Public note name',vaultIds[0]),notes:'hidden note secret'});const metadata=await engine.searchAssistantItems(token,'Public note');assert.deepEqual(metadata,[{name:'Public note name',website:''}]);assert.ok(!JSON.stringify(await engine.listAssistantLogins(token)).includes('fixture password'));
});
test('delete is a thirty day restorable tombstone with password history preserved',async()=>{
  const {engine,vaultIds}=await fixture();const {token}=await engine.createToken('Deleter',{vaultIds});const original=engine.data().items[0];const before=Date.now();const response=await engine.deleteAssistantLogin(token,'Example');const deleted=engine.data().items.find(i=>i.id===original.id)!;
  assert.equal(response.deleted,true);assert.ok(Date.parse(response.restoreUntil)>=before+30*86400000);assert.ok(deleted.deletedAt);assert.equal(deleted.password,'old fixture secret');assert.equal(deleted.passwordHistory.length,0);assert.deepEqual(await engine.listAssistantLogins(token),[]);await assert.rejects(engine.getAssistantLogin(token,'Example'),/not found/);
  await engine.restoreItem(original.id);assert.equal(engine.data().items.find(i=>i.id===original.id)!.deletedAt,undefined);assert.equal((await engine.getAssistantLogin(token,'Example')).password,'old fixture secret');
});
test('duplicate accessible item names fail without selecting an arbitrary login',async()=>{
  const {engine,vaultIds}=await fixture();const {token}=await engine.createToken('Ambiguous',{vaultIds});await engine.upsertItem({...newItem('login','Example',vaultIds[1]),password:'second secret'});
  await assert.rejects(engine.getAssistantLogin(token,'Example'),/Multiple/);await assert.rejects(engine.updateAssistantLogin(token,'Example',{notes:'change'}),/Multiple/);await assert.rejects(engine.deleteAssistantLogin(token,'Example'),/Multiple/);
});
test('per agent read quotas are independent, serialized, count misses and survive reload',async()=>{
  const f=await fixture();const a=await f.engine.createToken('A',{vaultIds:f.vaultIds});const b=await f.engine.createToken('B',{vaultIds:f.vaultIds});
  const results=await Promise.allSettled(Array.from({length:12},()=>f.engine.getAssistantLogin(a.token,'Example')));assert.equal(results.filter(r=>r.status==='fulfilled').length,10);assert.equal((await f.engine.getAssistantLogin(b.token,'Example')).password,'old fixture secret');
  const reloaded=new VaultEngine(f.storage);await reloaded.unlock(f.password,f.secretKey);await assert.rejects(reloaded.getAssistantLogin(a.token,'Example'),/Rate limit/);await assert.rejects(reloaded.getAssistantLogin(b.token,'Missing'),/not found/);assert.equal(reloaded.authenticateToken(b.token)!.calls.length,2);
});
test('per agent write quota limits thirty attempts and persists independently',async()=>{
  const f=await fixture();const a=await f.engine.createToken('Writes A',{vaultIds:f.vaultIds});const b=await f.engine.createToken('Writes B',{vaultIds:f.vaultIds});
  const results=await Promise.allSettled(Array.from({length:32},(_,i)=>f.engine.addAssistantLogin(a.token,login(f.vaultIds[0],'Write '+i))));assert.equal(results.filter(r=>r.status==='fulfilled').length,30);await f.engine.addAssistantLogin(b.token,login(f.vaultIds[0],'Independent write'));
  const reloaded=new VaultEngine(f.storage);await reloaded.unlock(f.password,f.secretKey);await assert.rejects(reloaded.updateAssistantLogin(a.token,'Example',{notes:'denied'}),/Rate limit/);assert.equal(reloaded.authenticateToken(b.token)!.writeCalls.length,1);
});
test('audit identifies each agent, action, item, time and denied attempts without secret payloads',async()=>{
  const f=await fixture();const a=await f.engine.createToken('Audited Agent',{clientName:'audited',vaultIds:f.vaultIds});await f.engine.getAssistantLogin(a.token,'Example');await f.engine.updateAssistantLogin(a.token,'Example',{password:'brand new secret not for log',notes:'secret note not for log'});await assert.rejects(f.engine.getAssistantLogin(a.token,'Missing'),/not found/);await f.engine.revokeToken(a.id);await assert.rejects(f.engine.listAssistantLogins(a.token),/Invalid API token/);
  const records=f.engine.data().activity.filter(a=>a.outcome);for(const a of records){assert.ok(a.at);assert.equal(a.agentId,a.agentId==='unknown'?'unknown':f.engine.data().assistantTokens[0].id);assert.equal(a.agentClientName,'audited');assert.equal(a.agentName,'Audited Agent');}assert.ok(records.some(a=>a.action==='assistant.get'&&a.itemName==='Example'&&a.outcome==='success'));assert.ok(records.some(a=>a.action==='assistant.get'&&a.itemName==='Missing'&&a.outcome==='denied'));assert.ok(records.some(a=>a.action==='assistant.list'&&a.outcome==='denied'));for(const secret of ['old fixture secret','brand new secret not for log','private fixture notes','secret note not for log','JBSWY3DPEHPK3PXP',a.token])assert.ok(!JSON.stringify(records).includes(secret));
});
test('legacy token migration preserves credentials and revocations while adding owner scoped metadata',async()=>{
  const f=await fixture();await f.engine.createToken('Codex on Mac',{vaultIds:f.vaultIds});const t=await f.engine.createToken('Grok Bot on Mac',{vaultIds:f.vaultIds});await f.engine.revokeToken(t.id);const d=structuredClone(f.engine.data());const before=d.assistantTokens.map(t=>({hash:t.hash,revokedAt:t.revokedAt,calls:t.calls}));delete d.settings.agentRequireItemApproval;for(const t of d.assistantTokens){delete (t as any).clientName;delete (t as any).permission;delete (t as any).vaultIds;delete (t as any).writeCalls;}
  const e=seal(d,f.engine.exportSessionKey(),f.disk());const migrated=await decryptData(e,f.password,f.secretKey);assert.deepEqual(migrated.assistantTokens.map(t=>({hash:t.hash,revokedAt:t.revokedAt,calls:t.calls})),before);assert.deepEqual(migrated.assistantTokens.map(t=>t.clientName),['codex','grok']);assert.ok(migrated.assistantTokens.every(t=>t.permission==='full'&&t.vaultIds.length===3&&t.writeCalls.length===0));assert.equal(migrated.settings.agentRequireItemApproval,false);
});
test('failed encrypted persistence cannot leave a newly added or edited item in memory',async()=>{
  const f=await fixture();const a=await f.engine.createToken('Atomic Writer',{vaultIds:f.vaultIds});let writes=0;f.intercept(async()=>{if(++writes===2)throw new Error('fixture disk unavailable');});await assert.rejects(f.engine.addAssistantLogin(a.token,login(f.vaultIds[0])),/disk unavailable/);f.intercept(undefined);assert.ok(!f.engine.data().items.some(i=>i.title==='Added'));
  writes=0;f.intercept(async()=>{if(++writes===2)throw new Error('fixture disk unavailable');});await assert.rejects(f.engine.updateAssistantLogin(a.token,'Example',{password:'unsaved secret'}),/disk unavailable/);f.intercept(undefined);assert.equal(f.engine.data().items.find(i=>i.title==='Example')!.password,'old fixture secret');
});
test('concurrent locking prevents a secret response and logs the locked denial after unlock',async()=>{
  const f=await fixture();const a=await f.engine.createToken('Lock Race',{vaultIds:f.vaultIds});let once=true;f.intercept(async()=>{if(once){once=false;f.engine.lock();}});await assert.rejects(f.engine.getAssistantLogin(a.token,'Example'),/Vault is locked/);f.intercept(undefined);await f.engine.unlock(f.password,f.secretKey);assert.ok(f.engine.data().activity.some(e=>e.action==='assistant.get'&&e.outcome==='denied'&&e.agentClientName==='lock_race'));
});
test('revocation and permission changes during an awaited read block the response',async()=>{
  for(const change of ['revoke','scope'] as const){const f=await fixture();const a=await f.engine.createToken('Racing agent',{vaultIds:f.vaultIds});let once=true;let ownerChange:Promise<void>|undefined;f.intercept(async()=>{if(once){once=false;ownerChange=change==='revoke'?f.engine.revokeToken(a.id):f.engine.updateAgent(a.id,{vaultIds:[]});}});await assert.rejects(f.engine.getAssistantLogin(a.token,'Example'),/changed|Invalid API token|not found/);f.intercept(undefined);await ownerChange;assert.ok(change==='revoke'?!f.engine.authenticateToken(a.token):f.engine.authenticateToken(a.token)!.vaultIds.length===0);}
});

test('owner vault access changes remain private until encrypted persistence succeeds',async()=>{
  const f=await fixture();const a=await f.engine.createToken('Vault policy writer',{vaultIds:f.vaultIds});
  await f.engine.updateVault(f.vaultIds[0],{allowAssistant:false});assert.deepEqual(await f.engine.listAssistantLogins(a.token),[]);
  f.intercept(async()=>{throw new Error('fixture unavailable');});await assert.rejects(f.engine.updateVault(f.vaultIds[0],{allowAssistant:true}),/fixture unavailable/);f.intercept(undefined);assert.equal(f.engine.data().vaults[0].allowAssistant,false);assert.deepEqual(await f.engine.listAssistantLogins(a.token),[]);
  await f.engine.updateVault(f.vaultIds[0],{name:'Renamed vault',allowAssistant:true});assert.equal((await f.engine.listAssistantLogins(a.token))[0].vault,'Renamed vault');
  await assert.rejects(f.engine.updateVault(f.vaultIds[0],{allowAssistant:'true'} as any),/Invalid/);
});
