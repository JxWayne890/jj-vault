import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,verify} from 'node:crypto';
import {mkdtemp,writeFile,chmod,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {apnsJWT,validatePushConfig,phonePushPayload,getPhonePushReadiness,sendConfiguredPhonePush,type AgentPhonePushEvent} from '../src/apns.ts';
test('APNs JWT uses ES256 P1363 signature, scoped Apple identifiers and current issuance time',()=>{const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});const pem=privateKey.export({type:'pkcs8',format:'pem'}).toString();const token=apnsJWT({keyId:'ABCDEF1234',teamId:'TEAM123456'},pem,1700000000000);const [h,p,s]=token.split('.');assert.deepEqual(JSON.parse(Buffer.from(h,'base64url').toString()),{alg:'ES256',kid:'ABCDEF1234'});assert.deepEqual(JSON.parse(Buffer.from(p,'base64url').toString()),{iss:'TEAM123456',iat:1700000000});assert.equal(Buffer.from(s,'base64url').length,64);assert.equal(verify('sha256',Buffer.from(`${h}.${p}`),{key:publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(s,'base64url')),true);assert.throws(()=>apnsJWT({keyId:'wrong',teamId:'TEAM123456'},pem));});
test('phone push config has fixed delivery hosts and rejects relative keys or token URL injection',()=>{const config={enabled:true,teamId:'TEAM123456',keyId:'ABCDEF1234',p8File:'/private/key.p8',deviceToken:'a'.repeat(64),topic:'com.john.jjvault',sandbox:true};assert.doesNotThrow(()=>validatePushConfig(config));assert.throws(()=>validatePushConfig({...config,p8File:'relative.p8'}));assert.throws(()=>validatePushConfig({...config,deviceToken:'a'.repeat(64)+'/extra'}));assert.throws(()=>validatePushConfig({...config,topic:'bad\r\nheader'}));assert.throws(()=>validatePushConfig({...config,keyId:'invalid_id'}));});
test('phone notifications preserve default read message and send only a generic write action',()=>{
  assert.deepEqual(phonePushPayload(),{aps:{alert:{title:'JJ Vault assistant access',body:'An assistant requested an allowed login.'},sound:'default'}});
  const bodies={add:'An agent added a vault login.',edit:'An agent edited a vault login.',delete:'An agent moved a vault login to Recently Deleted.'};
  for(const action of ['add','edit','delete'] as const){
    const event={action,agentClientName:'private-client',agentName:'Private agent',itemName:'Private account',password:'never-send-password',username:'never-send-username',totp_secret:'never-send-totp'};
    const payload=phonePushPayload(event);
    assert.deepEqual(payload,{aps:{alert:{title:'JJ Vault agent activity',body:bodies[action]},sound:'default'}});
    for(const forbidden of ['private-client','Private agent','Private account','never-send-password','never-send-username','never-send-totp'])assert.equal(JSON.stringify(payload).includes(forbidden),false);
  }
  assert.throws(()=>phonePushPayload({action:'unknown'} as unknown as AgentPhonePushEvent));
  assert.throws(()=>phonePushPayload({action:'toString'} as unknown as AgentPhonePushEvent));
});
test('phone readiness reports only enabled and configured without sending a request',async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),'jj-vault-push-'));
  try {
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:false,configured:false});
    assert.equal(await sendConfiguredPhonePush(directory),false);
    const p8File=path.join(directory,'key.p8');
    const {privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
    await writeFile(p8File,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
    const config={enabled:true,teamId:'TEAM123456',keyId:'ABCDEF1234',p8File,deviceToken:'a'.repeat(64),topic:'com.john.jjvault',sandbox:true};
    const configFile=path.join(directory,'push.json');
    await writeFile(configFile,JSON.stringify(config),{mode:0o600});
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:true,configured:true});
    await chmod(configFile,0o644);
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:false,configured:false});
    await chmod(configFile,0o600);await chmod(p8File,0o644);
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:true,configured:false});
    await chmod(p8File,0o600);await writeFile(p8File,'invalid key');
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:true,configured:false});
    await writeFile(configFile,JSON.stringify({...config,enabled:false,p8File:path.join(directory,'missing.p8')}));
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:false,configured:false});
    assert.equal(await sendConfiguredPhonePush(directory,{action:'add'}),false);
    await writeFile(configFile,'not JSON');
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:false,configured:false});
  } finally {await rm(directory,{recursive:true,force:true});}
});
test('phone readiness rejects symbolic config and private key files and non P256 keys',async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),'jj-vault-push-links-'));
  try {
    const p8File=path.join(directory,'key.p8');
    const {privateKey}=generateKeyPairSync('ec',{namedCurve:'secp384r1'});
    await writeFile(p8File,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
    const config={enabled:true,teamId:'TEAM123456',keyId:'ABCDEF1234',p8File,deviceToken:'a'.repeat(64),topic:'com.john.jjvault',sandbox:true};
    const configFile=path.join(directory,'push.json');
    await writeFile(configFile,JSON.stringify(config),{mode:0o600});
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:true,configured:false});
    const linkedKey=path.join(directory,'linked.p8');await symlink(p8File,linkedKey);
    await writeFile(configFile,JSON.stringify({...config,p8File:linkedKey}));
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:true,configured:false});
    await rm(configFile);await symlink(path.join(directory,'real.json'),configFile);
    await writeFile(path.join(directory,'real.json'),JSON.stringify(config),{mode:0o600});
    assert.deepEqual(await getPhonePushReadiness(directory),{enabled:false,configured:false});
  } finally {await rm(directory,{recursive:true,force:true});}
});
