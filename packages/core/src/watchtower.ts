import {createHash} from 'node:crypto';
import type {Item,WatchtowerReport} from './types.ts';
export function weakPassword(p:string):boolean {
  if(p.length<12)return true;
  if(/^(.)\1+$/.test(p)||/^(password|qwerty|letmein|welcome|123456|admin|iloveyou)/i.test(p))return true;
  if(/^(0123456789|1234567890|abcdefghijklmnopqrstuvwxyz|qwertyuiop)+$/i.test(p))return true;
  const words=p.split(/[\s._-]+/);if(words.length>=5&&new Set(words).size>=5&&p.length>=24)return false;
  const unique=new Set(p.toLowerCase()).size;return unique<7 || (/^[a-z]+$/i.test(p)&&p.length<20);
}
export async function checkBreach(password:string,fetcher:typeof fetch=fetch):Promise<number>{
  const hash=createHash('sha1').update(password).digest('hex').toUpperCase();
  const r=await fetcher(`https://api.pwnedpasswords.com/range/${hash.slice(0,5)}`,{headers:{'Add-Padding':'true','User-Agent':'JJVault/0.1'},signal:AbortSignal.timeout(15000),redirect:'error'});
  if(!r.ok)throw new Error('Breach check unavailable');
  const text=await r.text();if(text.length>2_000_000)throw new Error('Invalid breach response');
  for(const line of text.split(/\r?\n/)){const [suffix,count]=line.split(':');if(suffix===hash.slice(5)&&/^\d+$/.test(count))return Number(count);}
  return 0;
}
export async function watchtower(items:Item[],checkBreaches=false,fetcher:typeof fetch=fetch,now=Date.now()):Promise<WatchtowerReport>{
  const active=items.filter(i=>!i.deletedAt&&!i.archived);const findings:WatchtowerReport['findings']=[];const errors:string[]=[];
  const counts=new Map<string,number>();for(const i of active)if(i.password)counts.set(i.password,(counts.get(i.password)||0)+1);
  const cache=new Map<string,number>();
  for(const i of active){const add=(kind:WatchtowerReport['findings'][number]['kind'],detail:string)=>findings.push({itemId:i.id,title:i.title,kind,detail});
    if(i.password){if(weakPassword(i.password))add('weak','Use a longer, unpredictable password');if((counts.get(i.password)||0)>1)add('reused','This password is used by another item');
      if(checkBreaches)try{let count=cache.get(i.password);if(count===undefined){count=await checkBreach(i.password,fetcher);cache.set(i.password,count);}if(count>0)add('breached',`Found in ${count.toLocaleString()} known breach records`);}catch{errors.push(`Breach check unavailable for ${i.title}`);}
    }
    if(i.type==='login'&&!i.totp&&!i.passkey&&!i.tags.includes('2fa-enabled'))add('missing2fa','No authenticator recorded. Add the 2fa-enabled tag if using another factor');
    if(i.urls.some(u=>u.startsWith('http://')))add('http','Website uses unencrypted HTTP');
    const expiry=i.expiresAt||i.fields.find(f=>/expir/i.test(f.label))?.value;
    if(expiry){let date=Date.parse(expiry);if(/^\d{2}\/\d{2,4}$/.test(expiry)){const [m,y]=expiry.split('/').map(Number);date=new Date(y<100?2000+y:y,m,0).getTime();}if(Number.isFinite(date)&&date-now<30*86400000)add('expiring',date<now?'Expired':'Expires within 30 days');}
  }
  const affected=new Set(findings.map(f=>f.itemId));return {score:active.length?Math.max(0,Math.round(100*(1-affected.size/active.length))):100,findings,checked:active.length,breachCheck:checkBreaches?(errors.length?'partial':'complete'):'notRequested',errors};
}
