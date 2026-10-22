import {createPrivateKey,sign,createHash} from 'node:crypto';
import {connect,type ClientHttp2Session} from 'node:http2';
import path from 'node:path';
import {readOwnerFile} from './security.ts';

export interface PhonePushConfig {enabled:boolean;teamId:string;keyId:string;p8File:string;deviceToken:string;topic:string;sandbox:boolean}
export interface AgentPhonePushEvent {action:'add'|'edit'|'delete';agentClientName?:string;agentName?:string;itemName?:string}
export interface PhonePushReadiness {enabled:boolean;configured:boolean}
/** Only the action is included in Apple's payload. Agent and item names stay local. */
export function phonePushPayload(event?:AgentPhonePushEvent):{aps:{alert:{title:string;body:string};sound:string}} {
  const messages={add:'An agent added a vault login.',edit:'An agent edited a vault login.',delete:'An agent moved a vault login to Recently Deleted.'};
  if(event&&!Object.hasOwn(messages,event.action))throw new Error('Invalid agent notification action');
  return {aps:{alert:{title:event?'JJ Vault agent activity':'JJ Vault assistant access',body:event?messages[event.action]:'An assistant requested an allowed login.'},sound:'default'}};
}
const tokenCache=new Map<string,{jwt:string;at:number}>();
const sessions=new Map<string,ClientHttp2Session>();
export function validatePushConfig(config:unknown):asserts config is PhonePushConfig {
  const c=config as PhonePushConfig;
  if(!c||typeof c.enabled!=='boolean'||!/^[A-Z0-9]{10}$/.test(c.teamId)||!/^[A-Z0-9]{10}$/.test(c.keyId)||typeof c.p8File!=='string'||!path.isAbsolute(c.p8File)||!/^[a-fA-F0-9]{64,200}$/.test(c.deviceToken)||!/^[a-zA-Z0-9][a-zA-Z0-9.-]{2,200}$/.test(c.topic)||typeof c.sandbox!=='boolean')throw new Error('Invalid phone push configuration');
}
export function apnsJWT(config:Pick<PhonePushConfig,'teamId'|'keyId'>,privatePEM:string,now=Date.now()):string {
  if(!/^[A-Z0-9]{10}$/.test(config.teamId)||!/^[A-Z0-9]{10}$/.test(config.keyId))throw new Error('Invalid Apple signing identifiers');
  const key=createPrivateKey(privatePEM);
  if(key.asymmetricKeyType!=='ec'||key.asymmetricKeyDetails?.namedCurve!=='prime256v1')throw new Error('APNs requires a P256 private key');
  const header=Buffer.from(JSON.stringify({alg:'ES256',kid:config.keyId})).toString('base64url');
  const payload=Buffer.from(JSON.stringify({iss:config.teamId,iat:Math.floor(now/1000)})).toString('base64url');
  const input=`${header}.${payload}`;
  return `${input}.${sign('sha256',Buffer.from(input),{key,dsaEncoding:'ieee-p1363'}).toString('base64url')}`;
}
/** Apple delivery, with no credentials, agent names, or item names in the payload. */
export async function sendPhonePush(config:PhonePushConfig,privatePEM:string,event?:AgentPhonePushEvent):Promise<void>{
  validatePushConfig(config);if(!config.enabled)return;
  const payload=JSON.stringify(phonePushPayload(event));
  const identity=createHash('sha256').update(config.teamId+config.keyId+privatePEM).digest('hex');let cached=tokenCache.get(identity);if(!cached||Date.now()-cached.at>50*60000){cached={jwt:apnsJWT(config,privatePEM),at:Date.now()};tokenCache.clear();tokenCache.set(identity,cached);}const jwt=cached.jwt;
  const endpoint=config.sandbox?'https://api.sandbox.push.apple.com':'https://api.push.apple.com';
  let client=sessions.get(endpoint);if(!client||client.closed||client.destroyed){client=connect(endpoint);sessions.set(endpoint,client);const connection=client;connection.on('error',()=>{sessions.delete(endpoint);connection.destroy();});connection.on('goaway',()=>{sessions.delete(endpoint);connection.close();});connection.setTimeout(60000,()=>{sessions.delete(endpoint);connection.close();});}const connection=client;
  await new Promise<void>((resolve,reject)=>{let done=false;const onError=()=>finish(new Error('Unable to connect to Apple notification service'));const finish=(error?:Error)=>{if(done)return;done=true;clearTimeout(timeout);connection.off('error',onError);error?reject(error):resolve();};const timeout=setTimeout(()=>{connection.destroy();finish(new Error('Phone notification timed out'));},15000);connection.once('error',onError);
    const req=connection.request({':method':'POST',':path':`/3/device/${config.deviceToken}`,authorization:`bearer ${jwt}`,'apns-topic':config.topic,'apns-push-type':'alert','apns-priority':'10','apns-expiration':'0','content-type':'application/json'});
    let status=0,bytes=0;req.on('response',headers=>status=Number(headers[':status']));req.on('data',chunk=>{bytes+=chunk.length;if(bytes>16384)finish(new Error('Invalid Apple notification response'));});req.on('error',()=>finish(new Error('Phone notification request failed')));req.on('end',()=>finish(status===200?undefined:new Error(`Apple rejected phone notification (${status})`)));req.end(payload);
  });
}
export async function sendConfiguredPhonePush(directory:string,event?:AgentPhonePushEvent):Promise<boolean>{
  let raw:string;try{raw=await readOwnerFile(path.join(directory,'push.json'));}catch(e:any){if(e.code==='ENOENT')return false;throw e;}
  const config=JSON.parse(raw);validatePushConfig(config);if(!config.enabled)return false;const pem=await readOwnerFile(config.p8File);await sendPhonePush(config,pem,event);return true;
}
/** Local configuration checks only. A configured sender does not prove phone delivery. */
export async function getPhonePushReadiness(directory:string):Promise<PhonePushReadiness>{
  let enabled=false;
  try {
    const config=JSON.parse(await readOwnerFile(path.join(directory,'push.json')));
    validatePushConfig(config);enabled=config.enabled;
    if(!enabled)return {enabled:false,configured:false};
    const key=createPrivateKey(await readOwnerFile(config.p8File));
    return {enabled:true,configured:key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails?.namedCurve==='prime256v1'};
  } catch {return {enabled,configured:false};}
}
