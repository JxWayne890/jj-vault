import {_electron as electron,type ElectronApplication,type Page} from '@playwright/test';
import assert from 'node:assert/strict';
import {X509Certificate} from 'node:crypto';
import {request as httpsRequest} from 'node:https';
import {mkdtemp,readFile,rm,stat,writeFile} from 'node:fs/promises';
import {networkInterfaces,tmpdir} from 'node:os';
import {createRequire} from 'node:module';
import path from 'node:path';
import jsQR from 'jsqr';

// A disposable vault, real local phone manager, ephemeral listeners and a fixture
// OS encryption adapter. No user vault, Keychain, clipboard, or phone is used.
const data=await mkdtemp(path.join(tmpdir(),'jjvault-phone-ui-'));
const master='Synthetic phone pairing fixture master password 2026';
const fixturePassword='Synthetic phone item password 762891!';
const bootstrap=path.join(data,'phone-fixture-bootstrap.cjs');
const errors:string[]=[];
let running:ElectronApplication|undefined;
let page:Page;
let secretKey='';
interface Pairing {type:'jjvault-pairing';version:1;url:string;name:string;certificate:string;nonce:string;vaultId:string;expiresAt:string}
await writeFile(bootstrap,`
const electron=require('electron');
const crypto=require('node:crypto');
const protectionKey=crypto.createHash('sha256').update('Disposable JJ Vault phone UI protection adapter').digest();
electron.safeStorage.isEncryptionAvailable=()=>true;
electron.safeStorage.encryptString=value=>{const nonce=crypto.randomBytes(12);const cipher=crypto.createCipheriv('aes-256-gcm',protectionKey,nonce);return Buffer.concat([nonce,cipher.update(value,'utf8'),cipher.final(),cipher.getAuthTag()]);};
electron.safeStorage.decryptString=value=>{const cipher=crypto.createDecipheriv('aes-256-gcm',protectionKey,value.subarray(0,12));cipher.setAuthTag(value.subarray(-16));return Buffer.concat([cipher.update(value.subarray(12,-16)),cipher.final()]).toString('utf8');};
electron.powerMonitor.getSystemIdleTime=()=>0;
electron.clipboard.readText=async()=>'';
electron.clipboard.writeText=async()=>{};
electron.clipboard.clear=()=>{};
electron.Notification.prototype.show=function(){};
const childProcess=require('node:child_process');const originalSpawn=childProcess.spawn;
childProcess.spawn=(file,args,options)=>{if(!String(file).endsWith('JJBiometric'))return originalSpawn(file,args,options);const child=new(require('node:events').EventEmitter)();const PassThrough=require('node:stream').PassThrough;child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>true;child.stdin.on('finish',()=>process.nextTick(()=>child.emit('close',0)));return child;};
require(${JSON.stringify(path.resolve('dist/desktop/main.cjs'))});
`,{mode:0o600});
async function bridge(action:string,payload:unknown={}){return page.evaluate(({action,payload})=>(window as any).vault.invoke(action,payload),{action,payload});}
async function settings(){
  await page.locator('.sidebar').getByRole('button',{name:'Settings',exact:false}).click();
  await page.getByRole('heading',{name:'Settings & connections',exact:true}).waitFor();
}
async function unlock(){
  await page.getByLabel('Master password',{exact:true}).fill(master);
  if(await page.getByLabel('Secret Key',{exact:true}).isVisible())await page.getByLabel('Secret Key',{exact:true}).fill(secretKey);
  await page.getByRole('button',{name:'Unlock JJ Vault',exact:true}).click();
  await page.getByRole('button',{name:'Lock',exact:true}).waitFor();
  await skipPinSetup(page);
}
async function waitFor(check:()=>Promise<boolean>,message:string){
  const end=Date.now()+10000;
  while(Date.now()<end){if(await check())return;await page.waitForTimeout(30);}
  assert.fail(message);
}
async function decodePairing():Promise<Pairing>{
  const image=page.locator('#phonePairQR');await image.waitFor({state:'visible'});
  assert.match((await image.getAttribute('src'))??'',/^data:image\/png;base64,/);
  const source=(await image.getAttribute('src'))!;
  const png=(createRequire(import.meta.url)('pngjs') as {PNG:{sync:{read:(bytes:Buffer)=>{width:number;height:number;data:Buffer}}}}).PNG.sync.read(Buffer.from(source.split(',')[1],'base64'));
  let decoded=jsQR(new Uint8ClampedArray(png.data),png.width,png.height);
  assert.ok(decoded,`Pairing image must be a scannable QR code (${png.width} by ${png.height} pixels)`);
  const value=JSON.parse(decoded.data) as Pairing;
  assert.deepEqual(Object.keys(value).sort(),['certificate','expiresAt','name','nonce','type','url','vaultId','version']);
  assert.equal(value.type,'jjvault-pairing');assert.equal(value.version,1);assert.match(value.nonce,/^[A-Za-z0-9_-]{43}$/);assert.equal(new URL(value.url).protocol,'https:');
  assert.ok(Date.parse(value.expiresAt)>Date.now());assert.ok(Date.parse(value.expiresAt)<=Date.now()+125000);
  for(const forbidden of [master,secretKey,fixturePassword])assert.ok(!decoded.data.includes(forbidden),'Pairing QR never contains vault unlock secrets or item passwords');
  await assertPrivateUI(value);
  return value;
}
async function assertPrivateUI(pairing:Pairing,relayToken?:string){
  const state=JSON.stringify(await bridge('state'));const status=JSON.stringify(await bridge('phoneStatus'));
  const dom=await page.content();const text=await page.locator('body').innerText();
  for(const secret of [master,secretKey,fixturePassword,pairing.nonce,pairing.certificate,...(relayToken?[relayToken]:[])]){
    assert.ok(!state.includes(secret),'Public state excludes phone capabilities and vault secrets');assert.ok(!status.includes(secret),'Phone status excludes pairing capabilities and vault secrets');
    assert.ok(!dom.includes(secret),'Raw pairing payload and secrets are absent from DOM markup');assert.ok(!text.includes(secret),'Raw pairing payload and secrets are absent from visible text');
  }
  assert.ok(!dom.includes('jjvault-pairing'),'Raw QR payload is never rendered as text or an attribute');
}
async function pairRequest(pairing:Pairing):Promise<{status:number;body:Record<string,any>}>{
  const url=new URL(pairing.url);const certificate=new X509Certificate(Buffer.from(pairing.certificate,'base64'));
  const addresses=Object.values(networkInterfaces()).flatMap(entries=>(entries??[]).filter(entry=>entry.family==='IPv4').map(entry=>entry.address));
  const address=addresses.find(value=>certificate.checkIP(value));assert.ok(address,'Fixture connects directly to an address present in the pinned Mac certificate');
  const bytes=Buffer.from(JSON.stringify({nonce:pairing.nonce}));
  return new Promise((resolve,reject)=>{
    const request=httpsRequest({hostname:address,port:Number(url.port),servername:url.hostname,path:'/pair',method:'POST',ca:certificate.toString(),headers:{Host:url.host,'Content-Type':'application/json','Content-Length':bytes.length},timeout:5000},response=>{
      const chunks:Buffer[]=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>2*1024*1024){request.destroy(new Error('Fixture pairing response exceeded its bound'));return;}chunks.push(chunk);});
      response.on('end',()=>{try{resolve({status:response.statusCode??0,body:JSON.parse(Buffer.concat(chunks).toString('utf8'))});}catch{reject(new Error('Fixture pairing response is invalid JSON'));}});
    });
    request.on('timeout',()=>request.destroy(new Error('Fixture pairing request timed out')));request.on('error',()=>reject(new Error('Fixture phone endpoint is unavailable')));request.end(bytes);
  });
}
async function openPairing(){
  await page.locator('#pairPhone').click();try{await waitFor(async()=>{if(await page.getByRole('dialog').getByRole('heading',{name:'Pair your iPhone',exact:true}).isVisible())return true;const status=await bridge('phoneStatus');if(status.lastErrorCode)throw new Error('Phone manager rejected startup');return false;},'Pairing dialog did not open');}catch{const message=await page.locator('#toast').textContent();const status=await bridge('phoneStatus');const runtime=await running!.evaluate(({app})=>({packaged:app.isPackaged,uid:process.getuid?.()}));const directory=await stat(path.join(data,'phone-sync')).then(info=>({mode:(info.mode&0o7777).toString(8),uid:info.uid})).catch(()=>null);throw new Error(`Pairing dialog unavailable: ${message??'No message'}; enabled=${status.enabled}, running=${status.running}, error=${status.lastError??'none'}, code=${status.lastErrorCode??'none'}, runtime=${JSON.stringify(runtime)}, directory=${JSON.stringify(directory)}`);}return decodePairing();
}
async function cancelPairing(){
  const dialog=page.getByRole('dialog');await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'hidden'});
}

try{
  running=await electron.launch({args:[bootstrap],env:{...process.env,JJ_VAULT_DATA_DIR:data,JJ_VAULT_PORT:'0',JJ_VAULT_REMEMBER_SECRET:'0',JJ_VAULT_PHONE_TEST_LOOPBACK:'1',JJ_VAULT_PHONE_HTTPS_PORT:'0',JJ_VAULT_PHONE_LOOPBACK_PORT:'0'},timeout:30000});
  page=await running.firstWindow({timeout:15000});page.setDefaultTimeout(15000);page.on('pageerror',error=>errors.push(error.message));
  await page.getByRole('button',{name:'Create JJ Vault',exact:true}).waitFor();
  const fixtureRuntime=await running.evaluate(({app})=>({packaged:app.isPackaged,loopback:process.env.JJ_VAULT_PHONE_TEST_LOOPBACK,remember:process.env.JJ_VAULT_REMEMBER_SECRET}));assert.deepEqual(fixtureRuntime,{packaged:false,loopback:'1',remember:'0'},'Phone listener uses the isolated loopback fixture options');
  for(const action of ['startPhonePairing','syncPhone','disablePhoneSync'])await assert.rejects(bridge(action),/Vault is locked/);
  assert.equal(await page.locator('#phonePairQR').count(),0);
  await page.getByLabel('Master password',{exact:true}).fill(master);await page.getByLabel('Confirm master password',{exact:true}).fill(master);await page.getByRole('button',{name:'Create JJ Vault',exact:true}).click();
  await page.getByRole('heading',{name:'Your vault is ready.',exact:true}).waitFor();secretKey=(await page.locator('.hint.secretkey').textContent())!.trim();assert.match(secretKey,/^JJ1\./);await page.getByRole('button',{name:'I saved my Secret Key',exact:true}).click();
  await skipPinSetup(page);
  await bridge('settings',{idleMinutes:0});const initial=await bridge('state');assert.equal(initial.settings.idleMinutes,0);
  await bridge('saveItem',{item:{type:'login',title:'Phone synthetic login',vaultId:initial.vaults[0].id,username:'phone@example.invalid',password:fixturePassword,urls:['https://phone.example.invalid']}});
  await settings();assert.equal((await bridge('phoneStatus')).enabled,false);

  const cancelled=await openPairing();await cancelPairing();assert.equal(await page.locator('#phonePairQR').count(),0);assert.equal((await pairRequest(cancelled)).status,401,'Cancel invalidates the one time pairing nonce');
  const locked=await openPairing();await bridge('lock');await page.getByRole('heading',{name:'Unlock your vault',exact:true}).waitFor();assert.equal(await page.locator('#phonePairQR').count(),0,'Lock destroys the QR image');
  for(const action of ['startPhonePairing','syncPhone','disablePhoneSync'])await assert.rejects(bridge(action),/Vault is locked/);
  assert.equal((await pairRequest(locked)).status,401,'Lock invalidates the one time pairing nonce');await unlock();assert.equal((await bridge('state')).settings.idleMinutes,0);await settings();

  const pairing=await openPairing();const result=await pairRequest(pairing);assert.equal(result.status,200,'The displayed synthetic QR pairs through the actual TLS manager');assert.equal(typeof result.body.token,'string');assert.ok(result.body.envelope?.ciphertext);
  const relayToken=result.body.token as string;await assertPrivateUI(pairing,relayToken);assert.equal((await pairRequest(pairing)).status,401,'A successful pairing nonce cannot be replayed');
  await cancelPairing();await waitFor(async()=>(await bridge('phoneStatus')).paired===true,'Phone pairing metadata becomes visible');
  await settings();await page.locator('#syncPhone').click();await waitFor(async()=>!!(await bridge('phoneStatus')).lastSyncAt,'Sync button triggers an owner sync');
  const pairedState=await bridge('state');assert.equal(pairedState.settings.idleMinutes,0);assert.equal(pairedState.phoneSync?.paired,true);
  const protectedToken=path.join(data,'phone-sync','relay-token');assert.equal((await stat(protectedToken)).mode&0o777,0o600);assert.equal((await stat(path.dirname(protectedToken))).mode&0o777,0o700);assert.ok((await readFile(protectedToken,'utf8')).trim()===relayToken,'Phone stores its relay capability privately');
  await assertPrivateUI(pairing,relayToken);
  await page.locator('#disconnectPhone').click();await waitFor(async()=>(await bridge('phoneStatus')).enabled===false,'Disconnect disables the phone manager');
  const disconnected=await bridge('state');assert.equal(disconnected.settings.idleMinutes,0,'Pairing and disconnect never change Never');assert.equal(disconnected.locked,false);assert.equal(disconnected.phoneSync?.paired,false);assert.equal(await page.locator('#phonePairQR').count(),0);
  await waitFor(async()=>(await readFile(protectedToken,'utf8')).trim()!==relayToken,'Disconnect completes relay capability rotation');assert.deepEqual(errors,[]);
  process.stdout.write('Phone pairing UI passed: locked owner actions refused, real scannable QR, private state and markup, cancel and lock invalidate nonces, pinned TLS pairing and replay rejection, private relay token, sync and disconnect, and Never preserved. Disposable fixture only.\n');
}catch(error){process.stderr.write(`Phone pairing UI failed: ${error instanceof Error?error.message:String(error)}\n`);throw error;}
finally{
  if(running){let timeout:NodeJS.Timeout|undefined;await Promise.race([running.close(),new Promise<void>(resolve=>{timeout=setTimeout(()=>{running!.process().kill('SIGKILL');resolve();},5000);})]);if(timeout)clearTimeout(timeout);}
  await rm(data,{recursive:true,force:true});
}


async function skipPinSetup(page: import('@playwright/test').Page) {
  const state = await page.evaluate(() => (window as any).vault.invoke('state'));
  if (state.pinAvailable && !state.pinEnabled) await page.getByRole('button', { name: 'Not now', exact: true }).click();
}
