import {randomInt,randomUUID,createHmac} from 'node:crypto';
import type {Item,ItemType} from './types.ts';
import {WORDS} from './words.ts';
export function newItem(type:ItemType,title:string,vaultId:string):Item {const at=new Date().toISOString();return {id:randomUUID(),vaultId,type,title,urls:[],fields:[],tags:[],favorite:false,archived:false,createdAt:at,updatedAt:at,passwordHistory:[],allowAssistant:false,attachments:[]};}
export function matchesUrl(saved:string,page:string):boolean {
  try {const s=new URL(saved),p=new URL(page);return ['https:','http:'].includes(s.protocol)&&['https:','http:'].includes(p.protocol)&&!s.username&&!s.password&&!p.username&&!p.password&&s.hostname===p.hostname&&s.port===p.port&&!(s.protocol==='https:'&&p.protocol!=='https:');}catch{return false;}
}
export function isAssistantForbidden(item:Item):boolean {
  if(item.type==='bankAccount'||item.type==='xMoney'||/\bx[\s_-]*money\b|\bbank(?:ing| account)?\b|\bcredit union\b|\b(?:checking|savings) account\b|\b(?:chase|wells fargo|bank of america|capital one|citibank|us bank|pnc|truist)\b/i.test(item.title))return true;
  const bankHosts=['chase.com','bankofamerica.com','wellsfargo.com','capitalone.com','citi.com','citibank.com','usbank.com','pnc.com','truist.com','tdbank.com','ally.com','regions.com','huntington.com','citizensbank.com','bmo.com','fifththird.com','53.com'];
  return item.urls.some(u=>{try{const h=new URL(u).hostname.toLowerCase().replace(/\.$/,'');return h==='x.money'||h.endsWith('.x.money')||h==='money.x.com'||h.endsWith('.money.x.com')||h.endsWith('.bank')||/(?:^|\.)bank(?:ing)?(?:\.|$)/.test(h)||bankHosts.some(bank=>h===bank||h.endsWith('.'+bank));}catch{return false;}});
}
export interface GeneratorOptions {mode?:'random'|'passphrase'|'pin';length?:number;upper?:boolean;lower?:boolean;digits?:boolean;symbols?:boolean;separator?:string;words?:number}
export function generatePassword(o:GeneratorOptions={}):string {
  const mode=o.mode||'random';
  if(mode==='passphrase'){const n=o.words??6;if(!Number.isInteger(n)||n<4||n>20)throw new Error('Choose 4 to 20 words');return Array.from({length:n},()=>WORDS[randomInt(WORDS.length)]).join(o.separator??' ');}
  const n=o.length??(mode==='pin'?6:24);if(!Number.isInteger(n)||n<4||n>256)throw new Error('Choose length 4 to 256');
  const groups=mode==='pin'?['0123456789']:[o.upper!==false?'ABCDEFGHIJKLMNOPQRSTUVWXYZ':'',o.lower!==false?'abcdefghijklmnopqrstuvwxyz':'',o.digits!==false?'0123456789':'',o.symbols!==false?'!@#$%^&*()_+=[]{}:,.?':''].filter(Boolean);
  if(!groups.length)throw new Error('Select at least one character group');
  const all=groups.join('');const chars=groups.map(g=>g[randomInt(g.length)]);while(chars.length<n)chars.push(all[randomInt(all.length)]);
  for(let i=chars.length-1;i>0;i--){const j=randomInt(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}return chars.join('');
}
export function decodeBase32(s:string):Buffer {let bits=0,value=0;const bytes:number[]=[];const clean=s.toUpperCase().replace(/[\s=]/g,'');if(!/^[A-Z2-7]+$/.test(clean))throw new Error('Invalid TOTP secret');for(const c of clean){value=(value<<5)|'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);bits+=5;if(bits>=8){bytes.push((value>>>(bits-8))&255);bits-=8;}}if(bytes.length<10)throw new Error('TOTP secret is too short');return Buffer.from(bytes);}
export function parseTotp(input:string):{secret:string;period:number;digits:number;algorithm:string} {let secret=input,period=30,digits=6,algorithm='SHA1';if(input.startsWith('otpauth://')){const u=new URL(input);if(u.hostname!=='totp')throw new Error('Only TOTP is supported');secret=u.searchParams.get('secret')||'';period=Number(u.searchParams.get('period')||30);digits=Number(u.searchParams.get('digits')||6);algorithm=(u.searchParams.get('algorithm')||'SHA1').toUpperCase();}if(![6,7,8].includes(digits)||!Number.isInteger(period)||period<15||period>120||!['SHA1','SHA256','SHA512'].includes(algorithm))throw new Error('Invalid TOTP settings');decodeBase32(secret);return {secret,period,digits,algorithm};}
export async function totp(input:string,nowMs=Date.now()):Promise<string>{const p=parseTotp(input);const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(nowMs/1000/p.period)));const key=decodeBase32(p.secret);try{const h=createHmac(p.algorithm.toLowerCase(),key).update(counter).digest();const offset=h[h.length-1]&15;return String((h.readUInt32BE(offset)&0x7fffffff)%10**p.digits).padStart(p.digits,'0');}finally{key.fill(0);}}
