import test from 'node:test';
import assert from 'node:assert/strict';
import {VaultEngine,newItem,open,seal} from '../src/index.ts';
import type {Envelope,SyncLimits} from '../src/index.ts';

function size(envelope:Envelope){return {maxCiphertextBytes:Buffer.from(envelope.ciphertext,'base64').byteLength,maxEnvelopeBytes:Buffer.byteLength(JSON.stringify(envelope),'utf8')};}
async function fixture(){
  let disk:Envelope|null=null;let writes=0;
  const engine=new VaultEngine({read:async()=>disk&&structuredClone(disk),write:async envelope=>{disk=structuredClone(envelope);writes++;}});
  await engine.initialize('Private sync size limits fixture password');
  engine.data().settings.idleMinutes=0;
  const vault=engine.data().vaults[0];vault.allowAssistant=true;vault.travelSafe=true;
  const item=await engine.upsertItem({...newItem('login','Local login',vault.id),urls:['https://local.test'],password:'fixture password',notes:'Local information λ '.repeat(256)});
  const agent=await engine.createToken('Sync limits agent',{clientName:'sync_limits',permission:'full',vaultIds:[vault.id]});
  await engine.getAssistantLogin(agent.token,item.title);
  await engine.updateAssistantLogin(agent.token,item.title,{username:'Acknowledged local change'});
  const key=engine.exportSessionKey();
  async function incoming(){
    const remote=open(await engine.exportForSync(),key);
    remote.items=[{...newItem('login','Remote login',vault.id),urls:['https://remote.test'],password:'remote fixture password',notes:'Remote information 界 '.repeat(256)}];
    return seal(remote,key,disk!);
  }
  return {engine,key,agent,incoming,disk:()=>structuredClone(disk!),writes:()=>writes};
}

test('sync rejects an oversized merged union before changing memory, disk, grants or quotas',async()=>{
  const f=await fixture();const incoming=await f.incoming();const localSize=size(await f.engine.exportForSync());const remoteSize=size(incoming);
  const live=f.engine.data();const before=structuredClone(live);const beforeDisk=f.disk();const beforeWrites=f.writes();
  assert.equal(before.assistantTokens[0].calls.length,1);assert.equal(before.assistantTokens[0].writeCalls.length,1);
  for(const field of ['maxCiphertextBytes','maxEnvelopeBytes'] as const){
    const limits:SyncLimits={maxCiphertextBytes:100_000_000,maxEnvelopeBytes:100_000_000};
    limits[field]=Math.max(localSize[field],remoteSize[field]);
    for(const individual of [localSize,remoteSize]){assert.ok(individual.maxCiphertextBytes<=limits.maxCiphertextBytes);assert.ok(individual.maxEnvelopeBytes<=limits.maxEnvelopeBytes);}
    await assert.rejects(f.engine.mergeEncrypted(incoming,limits),/Merged vault exceeds the sync service size limit/);
    assert.equal(f.engine.data(),live);assert.deepEqual(f.engine.data(),before);assert.deepEqual(f.disk(),beforeDisk);assert.equal(f.writes(),beforeWrites);
    assert.deepEqual(f.engine.authenticateToken(f.agent.token),before.assistantTokens[0]);
  }
});

test('a merged vault within both size limits saves the union and keeps local agent policy',async()=>{
  const f=await fixture();const incoming=await f.incoming();const localSize=size(await f.engine.exportForSync());const remoteSize=size(incoming);
  const grants=structuredClone(f.engine.data().assistantTokens);
  const limits={maxCiphertextBytes:localSize.maxCiphertextBytes+remoteSize.maxCiphertextBytes,maxEnvelopeBytes:localSize.maxEnvelopeBytes+remoteSize.maxEnvelopeBytes};
  await f.engine.mergeEncrypted(incoming,limits);
  for(const data of [f.engine.data(),open(f.disk(),f.key)]){assert.deepEqual(data.items.map(item=>item.title),['Local login','Remote login']);assert.deepEqual(data.assistantTokens,grants);assert.ok(data.activity.some(entry=>entry.action==='sync.merged'));}
  const actual=size(await f.engine.exportForSync());assert.ok(actual.maxCiphertextBytes<=limits.maxCiphertextBytes);assert.ok(actual.maxEnvelopeBytes<=limits.maxEnvelopeBytes);
});

test('sync size preflight uses the travel filtered export and excludes local activity and agent tokens',async()=>{
  const f=await fixture();const privateVault=f.engine.data().vaults[1];
  await f.engine.upsertItem({...newItem('login','Private large item',privateVault.id),notes:'private fixture information '.repeat(10_000)});
  f.engine.data().settings.travelMode=true;
  await f.engine.save();
  const incoming=await f.incoming();const localSize=size(await f.engine.exportForSync());const remoteSize=size(incoming);
  const limits={maxCiphertextBytes:localSize.maxCiphertextBytes+remoteSize.maxCiphertextBytes,maxEnvelopeBytes:localSize.maxEnvelopeBytes+remoteSize.maxEnvelopeBytes};
  assert.ok(size(f.disk()).maxCiphertextBytes>limits.maxCiphertextBytes);
  const grants=structuredClone(f.engine.data().assistantTokens);
  await f.engine.mergeEncrypted(incoming,limits);
  assert.ok(f.engine.data().items.some(item=>item.title==='Private large item'));assert.deepEqual(f.engine.data().assistantTokens,grants);
  const exported=await f.engine.exportForSync();const snapshot=open(exported,f.key);
  assert.deepEqual(snapshot.assistantTokens,[]);assert.deepEqual(snapshot.activity,[]);assert.ok(snapshot.vaults.every(vault=>vault.travelSafe));assert.ok(!snapshot.items.some(item=>item.title==='Private large item'));
  assert.deepEqual(snapshot.items.map(item=>item.title),['Local login','Remote login']);const actual=size(exported);assert.ok(actual.maxCiphertextBytes<=limits.maxCiphertextBytes);assert.ok(actual.maxEnvelopeBytes<=limits.maxEnvelopeBytes);
});

test('sync refuses invalid or unbounded size limits without any local write',async()=>{
  const f=await fixture();const incoming=await f.incoming();const before=structuredClone(f.engine.data());const beforeDisk=f.disk();const beforeWrites=f.writes();
  const invalid:unknown[]=[null,{},[],{maxCiphertextBytes:1},{maxEnvelopeBytes:1}];
  for(const field of ['maxCiphertextBytes','maxEnvelopeBytes'] as const)for(const value of [0,-1,0.5,NaN,Infinity,Number.MAX_SAFE_INTEGER,100_000_001,'2000'])invalid.push({...{maxCiphertextBytes:1_000_000,maxEnvelopeBytes:1_000_000},[field]:value});
  for(const limits of invalid)await assert.rejects(f.engine.mergeEncrypted(incoming,limits as SyncLimits),/Invalid sync size limits/);
  assert.deepEqual(f.engine.data(),before);assert.deepEqual(f.disk(),beforeDisk);assert.equal(f.writes(),beforeWrites);
});
