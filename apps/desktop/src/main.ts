import {app,BrowserWindow,ipcMain,protocol,net,clipboard,powerMonitor,globalShortcut,dialog,Notification,session,safeStorage} from 'electron';
import {readFile,writeFile,mkdir,chmod,rename,access,lstat} from 'node:fs/promises';
import path from 'node:path';
import {homedir} from 'node:os';
import {spawn} from 'node:child_process';
import {mkdirSync,lstatSync,chmodSync} from 'node:fs';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {VaultEngine,ITEM_TYPES,generatePassword,totp,importCSV,import1PUX,importBitwarden,secretBytes,isAssistantForbidden,type Envelope} from '../../../packages/core/src/index.ts';
import {startLocalService,randomToken,atomicOwnerWrite,readOwnerFile,syncVault,createShare} from '../../../packages/service/src/index.ts';
import {PDFDocument,StandardFonts,rgb} from 'pdf-lib';
import {sendConfiguredPhonePush,getPhonePushReadiness,type PhonePushReadiness} from '../../../packages/service/src/apns.ts';
import {createPasskeyProvider} from '../../../packages/service/src/passkeys.ts';
import {timingSafeEqual} from 'node:crypto';
import {createDeviceSecretStore} from '../../../packages/service/src/device-secret.ts';
import {createDeviceSessionStore,deviceSessionIdentity} from '../../../packages/service/src/device-session.ts';
import {createPhoneSyncManager,type PhoneSyncManager} from '../../../packages/service/src/phone-sync.ts';
import {installBrowserHost} from '../../../packages/service/src/browser-install.ts';
import QRCode from 'qrcode';

const root=process.env.JJ_VAULT_DATA_DIR||path.join(homedir(),'Library','Application Support','JJ Vault');
app.setName('JJ Vault');
const rememberOnly=process.argv.includes('--remember-secret-key');
let rememberedSecretKey:string|undefined;let vaultIdentity:string|undefined;let deviceIdlePreference:number|undefined;let deviceSecretStore:ReturnType<typeof createDeviceSecretStore>|undefined;
let deviceSessionStore:ReturnType<typeof createDeviceSessionStore>|undefined;let sessionIdentity:string|undefined;let hasRememberedSession=false;let quitting=false;let sessionForgetFailed=false;
let phonePushReadiness:PhonePushReadiness={enabled:false,configured:false};
let phoneSync:PhoneSyncManager|undefined;
mkdirSync(root,{recursive:true,mode:0o700});if(lstatSync(root).isSymbolicLink())throw new Error('JJ Vault data folder must be a real directory');chmodSync(root,0o700);app.setPath('userData',root);
let window:BrowserWindow;let service:Awaited<ReturnType<typeof startLocalService>>|undefined;let clipboardTimer:NodeJS.Timeout|undefined;let kitSecret:string|undefined;let rememberedLocked=true;let sessionGeneration=0;let clipboardMarker:string|undefined;
const engine=new VaultEngine({read:async()=>{try{return JSON.parse(await readFile(path.join(root,'vault.json'),'utf8'));}catch(e:any){if(e.code==='ENOENT')return null;throw e;}},write:async e=>atomicOwnerWrite(path.join(root,'vault.json'),JSON.stringify(e))},()=>{phoneSync?.cancelPairing();if(!quitting)forgetDeviceSession();});
protocol.registerSchemesAsPrivileged([{scheme:'jjvault',privileges:{standard:true,secure:true,supportFetchAPI:true}}]);
if(!rememberOnly&&!app.requestSingleInstanceLock())app.quit();
app.on('second-instance',()=>{window?.show();window?.focus();});
function forgetDeviceSession(){const forgotten=deviceSessionStore?.forget()!==false;hasRememberedSession=false;if(!forgotten&&!sessionForgetFailed){sessionForgetFailed=true;if(app.isReady())dialog.showErrorBox('JJ Vault could not forget this session','The vault is locked in memory, but this Mac could not remove its saved session. Make the application data folder writable before reopening the app.');}else if(forgotten)sessionForgetFailed=false;return forgotten;}
function lock(preserveSession=false){if(!preserveSession)forgetDeviceSession();sessionGeneration++;engine.lock();kitSecret=undefined;const marker=clipboardMarker;clipboardMarker=undefined;if(marker!==undefined)void clipboard.readText().then(value=>{if(value===marker)clipboard.clear();}).catch(()=>{});if(clipboardTimer)clearTimeout(clipboardTimer);window?.webContents.send('vault:locked');rememberedLocked=true;}
function automaticLock(){if(!engine.status().locked&&engine.data().settings.idleMinutes>0)lock();}
async function loadVaultIdentity(){try{const envelope=JSON.parse(await readOwnerFile(path.join(root,'vault.json')));vaultIdentity=typeof envelope.id==='string'?envelope.id:undefined;sessionIdentity=deviceSessionIdentity(envelope);}catch{vaultIdentity=undefined;sessionIdentity=undefined;}return vaultIdentity;}
async function rememberDeviceSecret(secret:string){const previousIdentity=vaultIdentity;await loadVaultIdentity();if(vaultIdentity&&previousIdentity===vaultIdentity&&rememberedSecretKey===secret)return;rememberedSecretKey=undefined;if(vaultIdentity&&deviceSecretStore?.remember(vaultIdentity,secret))rememberedSecretKey=secret;}
async function applyDevicePreferences(){if(deviceIdlePreference!==undefined&&engine.data().settings.idleMinutes!==deviceIdlePreference){engine.data().settings.idleMinutes=deviceIdlePreference;await engine.record('settings.changed',undefined,deviceIdlePreference===0?'Automatic lock disabled':'Automatic lock updated');}}
function rememberSessionSnapshot(){
  if(engine.status().locked||engine.data().settings.idleMinutes!==0){forgetDeviceSession();return;}
  if(!sessionIdentity||!deviceSessionStore)return;
  const key=engine.exportSessionKey();try{hasRememberedSession=deviceSessionStore.remember(sessionIdentity,key)||hasRememberedSession;}finally{key.fill(0);}
}
async function rememberDeviceSession(){
  if(engine.status().locked||engine.data().settings.idleMinutes!==0){forgetDeviceSession();return;}
  const generation=sessionGeneration,version=engine.sessionVersion();await loadVaultIdentity();
  if(generation!==sessionGeneration||version!==engine.sessionVersion()||engine.status().locked)return;
  rememberSessionSnapshot();
}
async function resumeDeviceSession(){
  if(deviceIdlePreference!==0||!sessionIdentity){forgetDeviceSession();return;}
  const key=deviceSessionStore?.recall(sessionIdentity);if(!key)return;
  try{await engine.unlockWithKey(key,'deviceResume');await applyDevicePreferences();hasRememberedSession=true;rememberedLocked=false;}
  catch{forgetDeviceSession();engine.lock();}
  finally{key.fill(0);}
}
function visibleVaults(){const d=engine.data();return d.vaults.filter(v=>!d.settings.travelMode||v.travelSafe);}
function state(){const status=engine.status();if(status.locked)return {...status,hasRememberedSecretKey:!!rememberedSecretKey,hasRememberedSession,types:ITEM_TYPES,biometricAvailable:process.platform==='darwin',servicePort:service?.port};const d=engine.data();const ids=new Set(visibleVaults().map(v=>v.id));const now=Date.now();return {...status,hasRememberedSecretKey:!!rememberedSecretKey,hasRememberedSession,types:ITEM_TYPES,vaults:visibleVaults(),items:d.items.filter(i=>ids.has(i.vaultId)).map(i=>({id:i.id,vaultId:i.vaultId,type:i.type,title:i.title,username:i.username,urls:i.urls,tags:i.tags,favorite:i.favorite,archived:i.archived,deletedAt:i.deletedAt,restoreUntil:i.restoreUntil,updatedAt:i.updatedAt,allowAssistant:i.allowAssistant})),settings:d.settings,tokens:d.assistantTokens.map(({id,name,clientName,permission,vaultIds,createdAt,revokedAt,calls,writeCalls})=>({id,name,clientName,permission,vaultIds,createdAt,revokedAt,readCount:calls.filter(at=>at>now-3600000).length,writeCount:writeCalls.filter(at=>at>now-3600000).length})),phonePush:phonePushReadiness,phoneSync:phoneSync?.status()||{enabled:false,running:false,paired:false},activity:d.activity.slice(-500).reverse(),servicePort:service?.port};}
async function createAgent(p:any){
  if(!service)throw new Error('The local agent service is not ready');
  const helperFile=path.join(root,'agent-client.mjs');
  await atomicOwnerWrite(helperFile,await readFile(path.join(__dirname,'../service/agent-client.mjs')));
  const result=await engine.createToken(p.name,{...(p.clientName!==undefined?{clientName:p.clientName}:{}),...(p.permission!==undefined?{permission:p.permission}:{}),...(p.vaultIds!==undefined?{vaultIds:p.vaultIds}:{})});
  const record=engine.data().assistantTokens.find(t=>t.id===result.id)!;
  const directory=path.join(root,'agent-tokens');
  try{
    await mkdir(directory,{mode:0o700});
  }catch(error:any){if(error.code!=='EEXIST'){await engine.revokeToken(result.id);throw error;}}
  try{
    const info=await lstat(directory);
    if(!info.isDirectory()||info.isSymbolicLink()||info.uid!==process.getuid?.()||(info.mode&0o7777)!==0o700)throw new Error('Agent token folder must belong to you and be private');
    const filename=path.join(directory,record.clientName);
    try{await lstat(filename);throw new Error('An agent pairing file already uses this client name');}catch(error:any){if(error.code!=='ENOENT')throw error;}
    await atomicOwnerWrite(filename,result.token+'\n');
  }catch(error){await engine.revokeToken(result.id);throw error;}
  const quote=(value:string)=>`'${value.replaceAll("'","'\\''")}'`;
  const runtime=app.isPackaged?`ELECTRON_RUN_AS_NODE=1 ${quote(process.execPath)}`:'node';
  const helperCommand=`env JJ_VAULT_AGENT_DIR=${quote(directory)} JJ_VAULT_PORT=${service.port} ${runtime} ${quote(helperFile)} check ${quote(record.clientName)}`;
  return {...result,clientName:record.clientName,helperCommand};
}
function itemById(id:string){const i=engine.data().items.find(i=>i.id===id);if(!i||!visibleVaults().some(v=>v.id===i.vaultId))throw new Error('Item not found');return i;}
async function placeClipboard(value:string,generation=sessionGeneration){await clipboard.writeText(value);if(generation!==sessionGeneration||engine.status().locked){clipboard.clear();throw new Error('Vault is locked');}if(clipboardTimer)clearTimeout(clipboardTimer);clipboardMarker=value;const marker=value;clipboardTimer=setTimeout(async()=>{if(await clipboard.readText()===marker)clipboard.clear();if(clipboardMarker===marker)clipboardMarker=undefined;},90000);}
async function chooseSave(defaultPath:string,bytes:Uint8Array|string){const generation=sessionGeneration;const r=await dialog.showSaveDialog(window,{defaultPath});if(r.canceled||!r.filePath)return false;if(generation!==sessionGeneration||engine.status().locked)throw new Error('Vault is locked');await atomicOwnerWrite(r.filePath,bytes);return true;}
async function biometric(command:'enroll'|'unlock'|'delete',key?:Uint8Array):Promise<Buffer>{const helper=app.isPackaged?path.join(process.resourcesPath,'JJBiometric'):path.resolve(__dirname,'../../apple/build/JJBiometric');return new Promise((resolve,reject)=>{const child=spawn(helper,[command],{stdio:['pipe','pipe','pipe']});let output='',error='';child.stdout.on('data',b=>{output+=b.toString();if(output.length>10000)child.kill();});child.stderr.on('data',b=>error+=b.toString());child.on('error',()=>reject(new Error('Build the Touch ID helper with npm run build')));child.on('close',code=>{if(code!==0){reject(new Error(error.trim()||'Touch ID was cancelled'));return;}resolve(Buffer.from(output.trim(),'base64'));});child.stdin.end(key?Buffer.from(key).toString('base64')+'\n':'');});}
async function emergencyKit(secret:string){secretBytes(secret).fill(0);const pdf=await PDFDocument.create();const page=pdf.addPage([612,792]);const font=await pdf.embedFont(StandardFonts.Helvetica);const bold=await pdf.embedFont(StandardFonts.HelveticaBold);page.drawText('JJ Vault',{x:48,y:724,size:32,font:bold,color:rgb(.25,.15,.6)});page.drawText('Emergency Kit',{x:48,y:685,size:20,font:bold});let y=630;const lines=['Keep this document somewhere private and offline.','','Secret Key',secret,'','Recovery steps','1. Install JJ Vault from your trusted local source.','2. Restore your latest encrypted .jjbackup file.','3. Enter your master password and the Secret Key above.','4. Verify your items, then pair your other device again.','','Your master password is not included in this kit.','Neither secret can be reset to decrypt an existing vault.','Keep an encrypted backup separate from this printed kit.','','Master password (optional handwritten reminder):','','__________________________________________________'];for(const line of lines){page.drawText(line,{x:48,y,size:line===secret?10:12,font:line==='Secret Key'?bold:font});y-=25;}await chooseSave('JJ Vault Emergency Kit.pdf',await pdf.save());}
async function invoke(action:string,p:any={}){
  if(action==='state')return state();
  if(action==='initialize'){const r=await engine.initialize(p.password);kitSecret=r.secretKey;await rememberDeviceSecret(r.secretKey);await applyDevicePreferences();await rememberDeviceSession();return {...r,state:state()};}
  if(action==='unlock'){const secret=typeof p.secretKey==='string'&&p.secretKey.trim()?p.secretKey.trim():rememberedSecretKey;if(!secret)throw new Error('Enter your Secret Key once to pair this Mac');await engine.unlock(p.password,secret);await rememberDeviceSecret(secret);await applyDevicePreferences();await rememberDeviceSession();return state();}
  if(action==='biometricUnlock'){const key=await biometric('unlock');try{await engine.unlockWithKey(key);}finally{key.fill(0);}await applyDevicePreferences();await rememberDeviceSession();return state();}
  if(action==='lock'){lock();return state();}
  if(action==='touch'){engine.data();engine.touch();return true;}
  if(action==='restore'){const generation=sessionGeneration;const r=await dialog.showOpenDialog(window,{properties:['openFile'],filters:[{name:'Encrypted vault',extensions:['jjbackup','jjvault','json']}]});if(r.canceled)return false;if(generation!==sessionGeneration)throw new Error('Vault is locked');const backup=JSON.parse(await readFile(r.filePaths[0],'utf8'));if(generation!==sessionGeneration)throw new Error('Vault is locked');forgetDeviceSession();await engine.importEncrypted(backup,p.password,p.secretKey);await rememberDeviceSecret(p.secretKey);await applyDevicePreferences();await rememberDeviceSession();await biometric('delete').catch(()=>{});return true;}
  // Remaining routes require an unlocked vault.
  engine.data();
  if(action==='item'){const generation=sessionGeneration;const i=itemById(p.id);await engine.record('item.viewed',i.id);const code=i.totp?await totp(i.totp):undefined;if(generation!==sessionGeneration)throw new Error('Vault is locked');itemById(p.id);return {...i,passkey:i.passkey?{...i.passkey,privateKey:undefined}:undefined,attachments:i.attachments.map(({id,name,mime})=>({id,name,mime})),currentTotp:code,assistantForbidden:isAssistantForbidden(i)};}
  if(action==='totp'){const i=itemById(p.id);return i.totp?await totp(i.totp):null;}
  if(action==='saveItem'){const old=p.item.id?itemById(p.item.id):undefined;const input={...p.item};if(old){input.attachments=old.attachments;input.passkey=old.passkey;}else{if(input.type==='passkey')throw new Error('Create a passkey from a website using the native JJ Vault provider');input.attachments=[];delete input.passkey;}const i=await engine.upsertItem(input);return i.id;}
  if(action==='deleteItem'){await engine.deleteItem(p.id);return true;}
  if(action==='restoreItem'){await engine.restoreItem(p.id);return true;}
  if(action==='addVault')return engine.addVault(p.name);
  if(action==='updateVault'){const {id,...changes}=p;await engine.updateVault(id,changes);return true;}
  if(action==='settings'){const s=engine.data().settings;if(Number.isInteger(p.idleMinutes)&&p.idleMinutes>=0&&p.idleMinutes<=1440){s.idleMinutes=p.idleMinutes;deviceIdlePreference=p.idleMinutes;await atomicOwnerWrite(path.join(root,'device-preferences.json'),JSON.stringify({version:1,idleMinutes:p.idleMinutes}));}if(typeof p.travelMode==='boolean')s.travelMode=p.travelMode;if(typeof p.notifyAssistant==='boolean')s.notifyAssistant=p.notifyAssistant;await engine.record('settings.changed');await rememberDeviceSession();return true;}
  if(action==='generate')return generatePassword(p);
  if(action==='copy'){const generation=sessionGeneration;const i=itemById(p.id);let value:string;if(p.field==='totp')value=i.totp?await totp(i.totp):'';else if(p.field==='username')value=i.username||'';else if(p.field==='password')value=i.password||'';else if(p.field==='custom')value=i.fields.find(f=>f.id===p.fieldId)?.value||'';else throw new Error('Unsupported copy field');if(generation!==sessionGeneration||engine.status().locked)throw new Error('Vault is locked');await placeClipboard(value,generation);await engine.record('clipboard.copied',i.id,p.field);return true;}
  if(action==='copyToken'){if(typeof p.token!=='string'||!p.token.startsWith('jjv_'))throw new Error('Invalid token');await placeClipboard(p.token);return true;}
  if(action==='copyBrowserToken'){const generation=sessionGeneration;const token=(await readOwnerFile(path.join(root,'browser-token'))).trim();if(generation!==sessionGeneration)throw new Error('Vault is locked');await placeClipboard(token,generation);await engine.record('browser.tokenCopied');return true;}
  if(action==='copyProviderToken'){const generation=sessionGeneration;const token=(await readOwnerFile(path.join(root,'provider-token'))).trim();if(generation!==sessionGeneration)throw new Error('Vault is locked');await placeClipboard(token,generation);await engine.record('provider.tokenCopied');return true;}
  if(action==='createToken'||action==='createAgent')return createAgent(p);
  if(action==='updateAgent'){await engine.updateAgent(p.id,p.changes);return true;}
  if(action==='phoneStatus')return phoneSync?.status()||{enabled:false,running:false,paired:false};
  if(action==='startPhonePairing'){
    if(!phoneSync)throw new Error('Phone sync is not ready');
    const generation=sessionGeneration,version=engine.sessionVersion();
    const pairing=await phoneSync.startPairing();
    let qrDataUrl:string;
    try{qrDataUrl=await QRCode.toDataURL(JSON.stringify(pairing),{errorCorrectionLevel:'M',scale:8,margin:4});}
    catch(error){phoneSync.cancelPairing();throw error;}
    if(generation!==sessionGeneration||version!==engine.sessionVersion()||engine.status().locked){phoneSync.cancelPairing();throw new Error('Vault is locked');}
    return {qrDataUrl,expiresAt:pairing.expiresAt,url:pairing.url,name:pairing.name};
  }
  if(action==='cancelPhonePairing'){phoneSync?.cancelPairing();return true;}
  if(action==='syncPhone'){if(!phoneSync)throw new Error('Phone sync is not ready');return phoneSync.syncNow();}
  if(action==='disablePhoneSync'){if(!phoneSync)throw new Error('Phone sync is not ready');await phoneSync.disable();await engine.record('phone.disconnected');return true;}
  if(action==='notificationStatus'){phonePushReadiness=await getPhonePushReadiness(root);return phonePushReadiness;}
  if(action==='revokeToken'){await engine.revokeToken(p.id);return true;}
  if(action==='watchtower')return engine.watchtower(p.checkBreaches===true);
  if(action==='enrollBiometric'){const key=engine.exportSessionKey();try{await biometric('enroll',key);}finally{key.fill(0);}await engine.record('biometric.enabled');return true;}
  if(action==='removeBiometric'){await biometric('delete');return true;}
  if(action==='emergencyKit'){await emergencyKit(p.secretKey||kitSecret||rememberedSecretKey||'');kitSecret=undefined;return true;}
  if(action==='backup'){const envelope=await engine.exportEncrypted();return chooseSave(`JJ Vault ${new Date().toISOString().slice(0,10)}.jjbackup`,JSON.stringify(envelope));}
  if(action==='import'){const r=await dialog.showOpenDialog(window,{properties:['openFile'],filters:[{name:'Vault export',extensions:['csv','1pux','json']}]});if(r.canceled)return {count:0};const file=r.filePaths[0];const bytes=await readFile(file);let items;let warnings:string[]=[];if(file.endsWith('.1pux')){const result=import1PUX(bytes);engine.data().vaults.push(...result.vaults);items=result.items;warnings=result.warnings;}else{const vaultId=p.vaultId||visibleVaults()[0]?.id;if(!vaultId)throw new Error('Create a vault first');items=file.endsWith('.csv')?importCSV(bytes.toString(),vaultId):importBitwarden(bytes.toString(),vaultId);}for(const i of items)await engine.upsertItem(i);await engine.record('items.imported',undefined,String(items.length));return {count:items.length,warnings};}
  if(action==='attach'){const i=itemById(p.id);const r=await dialog.showOpenDialog(window,{properties:['openFile']});if(r.canceled)return false;const bytes=await readFile(r.filePaths[0]);if(bytes.length>18_000_000)throw new Error('Attachment exceeds 18 MB');await engine.upsertItem({...i,attachments:[...i.attachments,{id:crypto.randomUUID(),name:path.basename(r.filePaths[0]),mime:'application/octet-stream',data:bytes.toString('base64')}]});return true;}
  if(action==='downloadAttachment'){const i=itemById(p.id);const a=i.attachments.find(a=>a.id===p.attachmentId);if(!a)throw new Error('Attachment missing');return chooseSave(a.name,Buffer.from(a.data,'base64'));}
  if(action==='sync'){if(typeof p.url!=='string'||typeof p.token!=='string')throw new Error('Enter relay address and token');return syncVault(engine,{url:p.url,token:p.token});}
  if(action==='share'){const i=itemById(p.id);return createShare(i,{url:p.url,token:p.token,expiresAt:p.expiresAt});}
  if(action==='pairBrowser'){
    if(typeof p.id!=='string'||(!/^[a-p]{32}$/.test(p.id)&&!/^\{[0-9a-f-]{36}\}$|^[a-z0-9@._-]{3,128}$/i.test(p.id)))throw new Error('Invalid extension ID');
    const r=await dialog.showMessageBox(window,{type:'question',buttons:['Cancel','Pair extension'],defaultId:0,message:'Allow this browser extension to use JJ Vault?',detail:'Only pair an extension ID shown in your own browser extension settings. This installs the local connection for that extension. Browser access works while JJ Vault is unlocked.'});
    if(r.response!==1)return false;
    engine.data();
    if(!service)throw new Error('The local browser service is not ready');
    await installBrowserHost({operations:[{action:/^[a-p]{32}$/.test(p.id)?'chrome':'firefox',id:p.id}],homeDirectory:app.getPath('home'),dataDirectory:root,sourceHostFile:path.join(__dirname,'../service/native-host.cjs'),runtimePath:process.execPath,runAsNode:true,port:service.port,browserTokenFile:path.join(root,'browser-token')});
    await engine.record('browser.paired',undefined,p.id);return true;
  }
  throw new Error('Unsupported action');
}
app.whenReady().then(async()=>{
  await mkdir(root,{recursive:true,mode:0o700});await chmod(root,0o700);
  if(process.env.JJ_VAULT_REMEMBER_SECRET!=='0'){deviceSecretStore=createDeviceSecretStore(root,safeStorage);deviceSessionStore=createDeviceSessionStore(root,safeStorage);}
  if(rememberOnly){let input='';for await(const bytes of process.stdin){input+=bytes.toString();if(input.length>4096)throw new Error('Device pairing input too large');}const pairing=JSON.parse(input);input='';await loadVaultIdentity();if(!vaultIdentity||typeof pairing.secretKey!=='string'||!deviceSecretStore?.remember(vaultIdentity,pairing.secretKey))throw new Error('Unable to save Secret Key in protected device storage');if(pairing.idleMinutes===0)await atomicOwnerWrite(path.join(root,'device-preferences.json'),JSON.stringify({version:1,idleMinutes:0}));pairing.secretKey='';process.stdout.write('Device pairing saved.\n');app.exit(0);return;}
  await engine.load();await loadVaultIdentity();if(vaultIdentity)rememberedSecretKey=deviceSecretStore?.read(vaultIdentity)||undefined;
  phonePushReadiness=await getPhonePushReadiness(root);
  try{const preferences=JSON.parse(await readOwnerFile(path.join(root,'device-preferences.json')));if(preferences.version===1&&Number.isInteger(preferences.idleMinutes)&&preferences.idleMinutes>=0&&preferences.idleMinutes<=1440)deviceIdlePreference=preferences.idleMinutes;}catch{}
  await resumeDeviceSession();
  const phoneTestLoopback=!app.isPackaged&&process.env.JJ_VAULT_PHONE_TEST_LOOPBACK==='1'&&process.env.JJ_VAULT_REMEMBER_SECRET==='0'&&!!process.env.JJ_VAULT_DATA_DIR;
  phoneSync=await createPhoneSyncManager(root,engine,{...(phoneTestLoopback?{host:'127.0.0.1',hostname:'localhost',addresses:()=>['127.0.0.1']}:{}),...(process.env.JJ_VAULT_PHONE_LOOPBACK_PORT!==undefined?{httpPort:Number(process.env.JJ_VAULT_PHONE_LOOPBACK_PORT)}:{}),...(process.env.JJ_VAULT_PHONE_HTTPS_PORT!==undefined?{tlsPort:Number(process.env.JJ_VAULT_PHONE_HTTPS_PORT)}:{})});

  const getToken=async(name:string)=>{try{return (await readOwnerFile(path.join(root,name))).trim();}catch(e:any){if(e.code!=='ENOENT')throw e;const t=randomToken();await atomicOwnerWrite(path.join(root,name),t);return t;}};
  const adminToken=await getToken('admin-token');const browserToken=await getToken('browser-token');const providerToken=await getToken('provider-token');
  const provider=createPasskeyProvider(engine,{verifyUser:async()=>{const generation=sessionGeneration;engine.data();const verified=await biometric('unlock');let expected:Uint8Array|undefined;try{if(generation!==sessionGeneration)throw new Error('Vault is locked');expected=engine.exportSessionKey();if(verified.length!==expected.length||!timingSafeEqual(verified,expected))throw new Error('Enable Touch ID again in JJ Vault Settings');}finally{verified.fill(0);expected?.fill(0);}}});
  service=await startLocalService(engine,{port:Number(process.env.JJ_VAULT_PORT||17373),adminToken,browserToken,providerToken,provider,notify:async event=>{
    const write=event.type==='assistant_write';
    const verb=({add:'added',edit:'edited',delete:'moved to Recently Deleted',get:'requested'})[event.action];
    const body=write?(event.action==='delete'?'An agent moved a vault login to Recently Deleted.':`An agent ${verb} a vault login.`):'An agent requested an allowed login.';
    try{const notification=new Notification({title:write?'JJ Vault item changed':'JJ Vault agent access',body});notification.on('failed',()=>{void engine.record('notification.macFailed',event.itemId,event.agentClientName).catch(()=>{});});notification.show();}
    catch{await engine.record('notification.macFailed',event.itemId,event.agentClientName).catch(()=>{});}
    void sendConfiguredPhonePush(root,write?{action:event.action as 'add'|'edit'|'delete'}:undefined).then(async sent=>{
      if(write&&!sent)await engine.record('notification.phoneUnavailable',event.itemId,event.agentClientName).catch(()=>{});
    }).catch(async()=>{await engine.record('notification.phoneFailed',event.itemId,event.agentClientName).catch(()=>{});});
  }});
  const assets=path.join(__dirname,'ui');
  protocol.handle('jjvault',async request=>{const u=new URL(request.url);if(u.hostname!=='app')return new Response('Forbidden',{status:403});const file=path.resolve(assets,'.'+decodeURIComponent(u.pathname==='/'?'/index.html':u.pathname));if(!file.startsWith(assets+path.sep))return new Response('Forbidden',{status:403});return net.fetch(pathToFileURL(file).href);});
  session.defaultSession.setPermissionRequestHandler((_wc,_permission,callback)=>callback(false));
  window=new BrowserWindow({width:1360,height:900,minWidth:1000,minHeight:680,title:'JJ Vault',backgroundColor:'#f7f7fb',webPreferences:{preload:path.join(__dirname,'preload.cjs'),nodeIntegration:false,contextIsolation:true,sandbox:true,webSecurity:true,devTools:!app.isPackaged}});
  window.on('close',event=>{if(!quitting&&deviceIdlePreference===0){event.preventDefault();window.hide();}});
  app.on('activate',()=>{if(!window.isDestroyed()){window.show();window.focus();}});
  window.webContents.setWindowOpenHandler(()=>({action:'deny'}));window.webContents.on('will-navigate',(e,url)=>{if(!url.startsWith('jjvault://app/'))e.preventDefault();});
  ipcMain.handle('vault:invoke',async(event,action,payload)=>{if(event.sender!==window.webContents||event.senderFrame!==window.webContents.mainFrame||!event.senderFrame?.url.startsWith('jjvault://app/'))throw new Error('Forbidden IPC sender');const generation=sessionGeneration;try{const value=await invoke(action,payload);if(generation!==sessionGeneration&&!['state','lock'].includes(action))throw new Error('Vault is locked');if(!['state','lock','touch'].includes(action)&&engine.status().locked)throw new Error('Vault is locked');return {ok:true,value};}catch(error){return {ok:false,error:error instanceof Error?error.message:'Unable to complete request'};}});
  await window.loadURL('jjvault://app/');
  powerMonitor.on('suspend',automaticLock);powerMonitor.on('lock-screen',automaticLock);powerMonitor.on('user-did-resign-active',automaticLock);
  globalShortcut.register('CommandOrControl+Shift+Space',()=>{window.show();window.focus();window.webContents.send('vault:quickAccess');});
  setInterval(()=>{const timeout=engine.status().locked?0:engine.data().settings.idleMinutes*60;if(timeout&&powerMonitor.getSystemIdleTime()>=timeout)automaticLock();if(timeout)engine.checkIdle();const locked=engine.status().locked;if(locked&&!rememberedLocked)lock();rememberedLocked=locked;},1000).unref();
}).catch(error=>{dialog.showErrorBox('JJ Vault could not start',error.message);app.quit();});
app.on('before-quit',()=>{if(quitting)return;rememberSessionSnapshot();quitting=true;lock(true);globalShortcut.unregisterAll();void service?.close();void phoneSync?.close();});
app.on('window-all-closed',()=>app.quit());
