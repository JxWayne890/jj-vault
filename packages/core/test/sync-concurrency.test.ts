import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {VaultEngine,newItem,open,seal} from '../src/index.ts';
import type {Envelope,VaultData} from '../src/types.ts';
function deferred(){let resolve!:()=>void;const promise=new Promise<void>(done=>{resolve=done;});return {promise,resolve};}
async function fixture(){
  let disk:Envelope|null=null;
  let intercept:((envelope:Envelope)=>Promise<void>)|undefined;
  const storage={read:async()=>disk&&structuredClone(disk),write:async(envelope:Envelope)=>{if(intercept)await intercept(envelope);disk=structuredClone(envelope);}};
  const engine=new VaultEngine(storage);const {secretKey}=await engine.initialize('Private sync concurrency fixture password');
  engine.data().settings.idleMinutes=0;engine.data().vaults[0].allowAssistant=true;engine.data().vaults[0].travelSafe=true;
  const vaultId=engine.data().vaults[0].id;
  await engine.upsertItem({...newItem('login','Existing login',vaultId),urls:['https://existing.test'],username:'fixture user',password:'original fixture password'});
  const agent=await engine.createToken('Sync agent',{clientName:'sync_agent',permission:'full',vaultIds:[vaultId]});
  const key=engine.exportSessionKey();
  function remote(change:(data:VaultData)=>void){const data=structuredClone(engine.data());change(data);return seal(data,key,disk!);}
  function block(predicate:(data:VaultData)=>boolean){const entered=deferred(),release=deferred();let used=false;let failure:Error|undefined;intercept=async envelope=>{if(!used&&predicate(open(envelope,key))){used=true;entered.resolve();await release.promise;if(failure)throw failure;}};return {entered:entered.promise,release:()=>release.resolve(),fail:()=>{failure=new Error('Fixture sync disk unavailable');release.resolve();},clear:()=>{intercept=undefined;}};}
  function phoneItem(data:VaultData,name='Phone added'){data.items.push({...newItem('login',name,vaultId),urls:['https://phone.test'],password:'phone fixture password',updatedAt:'2030-01-02T00:00:00.000Z'});}
  return {engine,storage,key,secretKey,vaultId,agent,remote,block,phoneItem,disk:()=>disk!};
}
test('sync waits for an agent add and preserves both acknowledged updates on disk',async()=>{
  const f=await fixture();const incoming=f.remote(data=>f.phoneItem(data));const gate=f.block(data=>data.items.some(item=>item.title==='Agent added'));
  const add=f.engine.addAssistantLogin(f.agent.token,{vault:f.vaultId,name:'Agent added',website:'https://agent.test',username:'fixture user',password:'agent fixture password'});await gate.entered;
  const merge=f.engine.mergeEncrypted(incoming);let mergeDone=false;void merge.then(()=>{mergeDone=true;});await new Promise(done=>setImmediate(done));assert.equal(mergeDone,false);
  gate.release();await add;await merge;gate.clear();
  for(const data of [f.engine.data(),open(f.disk(),f.key)]){assert.ok(data.items.some(item=>item.title==='Agent added'));assert.ok(data.items.some(item=>item.title==='Phone added'));assert.equal(data.settings.idleMinutes,0);assert.equal(data.assistantTokens[0].writeCalls.length,1);}
});
test('sync waits for an agent edit and keeps password history plus phone data',async()=>{
  const f=await fixture();const incoming=f.remote(data=>f.phoneItem(data));const gate=f.block(data=>data.items.some(item=>item.password==='edited fixture password'));
  const update=f.engine.updateAssistantLogin(f.agent.token,'Existing login',{password:'edited fixture password'});await gate.entered;const merge=f.engine.mergeEncrypted(incoming);gate.release();await update;await merge;gate.clear();
  for(const data of [f.engine.data(),open(f.disk(),f.key)]){const item=data.items.find(item=>item.title==='Existing login')!;assert.equal(item.password,'edited fixture password');assert.ok(item.passwordHistory.some(entry=>entry.password==='original fixture password'));assert.ok(data.items.some(item=>item.title==='Phone added'));}
});
test('an agent write queued behind sync uses the merged snapshot and retains phone items',async()=>{
  const f=await fixture();const incoming=f.remote(data=>f.phoneItem(data));const gate=f.block(data=>data.activity.some(entry=>entry.action==='sync.merged'));
  const merge=f.engine.mergeEncrypted(incoming);await gate.entered;const update=f.engine.updateAssistantLogin(f.agent.token,'Existing login',{notes:'Agent notes after sync'});gate.release();await merge;await update;gate.clear();
  for(const data of [f.engine.data(),open(f.disk(),f.key)]){assert.ok(data.items.some(item=>item.title==='Phone added'));assert.equal(data.items.find(item=>item.title==='Existing login')!.notes,'Agent notes after sync');}
});
test('failed sync persistence leaves acknowledged local writes intact and later agent writes succeed',async()=>{
  const f=await fixture();await f.engine.addAssistantLogin(f.agent.token,{vault:f.vaultId,name:'Acknowledged agent login',website:'https://agent.test',username:'fixture'});
  const incoming=f.remote(data=>f.phoneItem(data));const gate=f.block(data=>data.activity.some(entry=>entry.action==='sync.merged'));
  const merge=f.engine.mergeEncrypted(incoming);const rejected=assert.rejects(merge,/Fixture sync disk unavailable/);await gate.entered;const update=f.engine.updateAssistantLogin(f.agent.token,'Existing login',{notes:'Queued after failed sync'});gate.fail();await rejected;await update;gate.clear();
  for(const data of [f.engine.data(),open(f.disk(),f.key)]){assert.ok(data.items.some(item=>item.title==='Acknowledged agent login'));assert.ok(!data.items.some(item=>item.title==='Phone added'));assert.equal(data.items.find(item=>item.title==='Existing login')!.notes,'Queued after failed sync');assert.equal(data.assistantTokens[0].writeCalls.length,2);}
});
test('locking during sync persistence cancels the merge and never reopens the vault',async()=>{
  const f=await fixture();const incoming=f.remote(data=>f.phoneItem(data));const gate=f.block(data=>data.activity.some(entry=>entry.action==='sync.merged'));
  const merge=f.engine.mergeEncrypted(incoming);const rejected=assert.rejects(merge,/Vault is locked/);await gate.entered;f.engine.lock();gate.release();await rejected;gate.clear();assert.equal(f.engine.status().locked,true);
  await f.engine.unlockWithKey(f.key,'deviceResume');assert.ok(!f.engine.data().items.some(item=>item.title==='Phone added'));assert.ok(f.engine.data().activity.some(entry=>entry.action==='vault.deviceResumed'));assert.equal(f.engine.data().settings.idleMinutes,0);
});
test('a sync request queued in an old session stays cancelled after lock and device resume',async()=>{
  const f=await fixture();const incoming=f.remote(data=>f.phoneItem(data));const gate=f.block(data=>data.items.some(item=>item.title==='Agent pending'));
  const add=f.engine.addAssistantLogin(f.agent.token,{vault:f.vaultId,name:'Agent pending',website:'https://agent.test',username:'fixture'});const addRejected=assert.rejects(add,/Vault is locked/);await gate.entered;
  const merge=f.engine.mergeEncrypted(incoming);const rejected=assert.rejects(merge,/Vault is locked/);f.engine.lock();const resume=f.engine.unlockWithKey(f.key,'deviceResume');gate.release();await addRejected;await resume;await rejected;gate.clear();assert.equal(f.engine.status().locked,false);assert.ok(!f.engine.data().items.some(item=>item.title==='Phone added'));
});
test('owner token policy changes during pending sync remain effective immediately and are not overwritten',async()=>{
  for(const change of ['scope','revoke'] as const){
    const f=await fixture();const incoming=f.remote(data=>f.phoneItem(data));const gate=f.block(data=>data.activity.some(entry=>entry.action==='sync.merged'));
    const merge=f.engine.mergeEncrypted(incoming);const rejected=assert.rejects(merge,/changed/);await gate.entered;
    const ownerChange=change==='scope'?f.engine.updateAgent(f.agent.id,{vaultIds:[],permission:'read'}):f.engine.revokeToken(f.agent.id);
    const live=f.engine.authenticateToken(f.agent.token);if(change==='scope'){assert.equal(live!.permission,'read');assert.deepEqual(live!.vaultIds,[]);}else assert.equal(live,null);
    gate.release();await rejected;await ownerChange;gate.clear();const saved=open(f.disk(),f.key).assistantTokens[0];assert.ok(!f.engine.data().items.some(item=>item.title==='Phone added'));if(change==='scope'){assert.equal(saved.permission,'read');assert.deepEqual(saved.vaultIds,[]);}else assert.ok(saved.revokedAt);
  }
});
test('phone sync cannot expand local agent grants, reset quotas, import activity or change Never settings',async()=>{
  const f=await fixture();await f.engine.getAssistantLogin(f.agent.token,'Existing login');await f.engine.updateAssistantLogin(f.agent.token,'Existing login',{notes:'Local acknowledged activity'});const before=structuredClone(f.engine.data());const newVaultId=randomUUID();
  const incoming=f.remote(data=>{data.settings.idleMinutes=1;data.settings.travelMode=true;data.settings.agentRequireItemApproval=true;data.settings.notifyAssistant=!before.settings.notifyAssistant;data.assistantTokens[0].permission='read';data.assistantTokens[0].vaultIds.push(newVaultId);data.assistantTokens[0].calls=[];data.assistantTokens[0].writeCalls=[];data.vaults[0].allowAssistant=false;data.vaults[0].allowBrowser=false;data.vaults.push({id:newVaultId,name:'Phone vault',allowAssistant:true,allowBrowser:false,travelSafe:false});data.items.push({...newItem('login','Phone private vault login',newVaultId),urls:['https://private.test'],allowAssistant:true});data.activity.push({id:randomUUID(),at:new Date().toISOString(),action:'remote.fake_activity'});});
  await f.engine.mergeEncrypted(incoming);const after=f.engine.data();assert.deepEqual(after.settings,before.settings);assert.deepEqual(after.assistantTokens,before.assistantTokens);assert.equal(after.vaults[0].allowAssistant,true);assert.equal(after.vaults[0].allowBrowser,true);assert.equal(after.vaults.find(vault=>vault.id===newVaultId)!.allowAssistant,false);assert.ok(!after.activity.some(entry=>entry.action==='remote.fake_activity'));for(const entry of before.activity)assert.ok(after.activity.some(saved=>saved.id===entry.id));
  assert.ok(!(await f.engine.listAssistantLogins(f.agent.token)).some(item=>item.name==='Phone private vault login'));await assert.rejects(f.engine.getAssistantLogin(f.agent.token,'Phone private vault login'),/not found/);
});
test('sync preserves remote password histories and deletion tombstones',async()=>{
  const f=await fixture();const original=f.engine.data().items[0];const incoming=f.remote(data=>{const item=data.items.find(item=>item.id===original.id)!;item.password='phone updated fixture password';item.passwordHistory.push({password:'phone earlier fixture password',changedAt:'2029-01-01T00:00:00.000Z'});item.updatedAt='2030-01-02T00:00:00.000Z';item.deletedAt=item.updatedAt;item.restoreUntil='2030-02-01T00:00:00.000Z';});
  await f.engine.mergeEncrypted(incoming);const item=f.engine.data().items.find(item=>item.id===original.id)!;assert.equal(item.deletedAt,'2030-01-02T00:00:00.000Z');assert.equal(item.restoreUntil,'2030-02-01T00:00:00.000Z');for(const password of ['phone earlier fixture password','original fixture password'])assert.ok(item.passwordHistory.some(entry=>entry.password===password));assert.deepEqual(await f.engine.listAssistantLogins(f.agent.token),[]);
});
test('sync exports an isolated filtered snapshot without replacing state or dropping pending agent writes',async()=>{
  const f=await fixture();const privateVault=f.engine.data().vaults[1];await f.engine.upsertItem({...newItem('login','Not travel safe',privateVault.id),password:'private fixture password'});f.engine.data().settings.travelMode=true;await f.engine.save();
  const gate=f.block(data=>data.items.some(item=>item.title==='Agent pending export'));const add=f.engine.addAssistantLogin(f.agent.token,{vault:f.vaultId,name:'Agent pending export',website:'https://agent.test',username:'fixture'});await gate.entered;
  const live=f.engine.data();const revision=live.revision;const exported=open(await f.engine.exportForSync(),f.key);assert.equal(f.engine.data(),live);assert.equal(f.engine.data().revision,revision);assert.deepEqual(exported.assistantTokens,[]);assert.deepEqual(exported.activity,[]);assert.ok(!exported.items.some(item=>item.title==='Not travel safe'));assert.ok(!exported.items.some(item=>item.title==='Agent pending export'));assert.ok(exported.vaults.every(vault=>vault.travelSafe));
  exported.items[0].title='Changed exported copy';assert.equal(f.engine.data().items[0].title,'Existing login');gate.release();await add;gate.clear();assert.ok(f.engine.data().items.some(item=>item.title==='Agent pending export'));assert.ok(f.engine.data().items.some(item=>item.title==='Not travel safe'));
});
