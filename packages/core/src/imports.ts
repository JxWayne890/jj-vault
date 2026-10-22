import {unzipSync,strFromU8} from 'fflate';
import {newItem} from './utilities.ts';
import type {Item,ItemType,Vault} from './types.ts';
export function parseCSV(text:string):Record<string,string>[] {
  if(text.length>50_000_000)throw new Error('Import exceeds 50 MB');
  const rows:string[][]=[];let row:string[]=[],field='',quoted=false;
  for(let n=0;n<text.length;n++){const c=text[n];if(c==='"'){if(quoted&&text[n+1]==='"'){field+='"';n++;}else if(quoted||field==='')quoted=!quoted;else field+=c;}
    else if(c===','&&!quoted){row.push(field);field='';}else if((c==='\n'||c==='\r')&&!quoted){if(c==='\r'&&text[n+1]==='\n')n++;row.push(field);if(row.some(Boolean))rows.push(row);row=[];field='';}else field+=c;}
  if(quoted)throw new Error('Unclosed CSV quotation');if(field||row.length){row.push(field);rows.push(row);}const headers=rows.shift()?.map(x=>x.replace(/^\uFEFF/,'').trim().toLowerCase())||[];
  if(!headers.length||!['password','login_password','type','title','name','url','website'].some(h=>headers.includes(h)))throw new Error('Unrecognized CSV headers');
  return rows.map(r=>Object.fromEntries(headers.map((h,i)=>[h,r[i]||''])));
}
export function importCSV(text:string,vaultId:string):Item[]{return parseCSV(text).map(r=>{const title=r.title||r.name||r.url||r.website||'Imported item';const type:ItemType=r.type==='note'?'secureNote':r.type==='card'?'creditCard':r.type==='identity'?'identity':'login';const i=newItem(type,title,vaultId);i.username=r.username||r.login_username||r['login username']||'';i.password=r.password||r.login_password||r['login password']||'';const url=r.url||r.website||r.login_uri||r['login uri'];i.urls=url?url.split(/[,\n]/).map(x=>x.trim()).filter(x=>/^https?:\/\//.test(x)):[];i.notes=r.notes||r.extra||'';i.totp=r.otpsecret||r.login_totp||r.totp||r['otp secret']||r['one-time password']||r['otp auth']||undefined;i.tags=(r.tags||r.grouping||'').split(/[;,]/).filter(Boolean);i.favorite=/^(1|true|yes)$/i.test(r.favorite||r['favorite status']||'');i.archived=/^(1|true|yes)$/i.test(r.archived||r['archived status']||'');return i;});}
export function importBitwarden(text:string,vaultId:string):Item[]{const d=JSON.parse(text);if(d.encrypted)throw new Error('Use an unencrypted Bitwarden export locally, then delete the export');if(!Array.isArray(d.items))throw new Error('Invalid Bitwarden export');return d.items.map((x:any)=>{const type:ItemType=({1:'login',2:'secureNote',3:'creditCard',4:'identity'} as Record<number,ItemType>)[x.type]||'secureNote';const i=newItem(type,x.name||'Imported item',vaultId);i.username=x.login?.username||'';i.password=x.login?.password||'';i.urls=(x.login?.uris||[]).map((u:any)=>u.uri).filter((u:unknown)=>typeof u==='string'&&/^https?:\/\//.test(u));i.totp=x.login?.totp||undefined;i.notes=x.notes||'';i.favorite=!!x.favorite;i.fields=(x.fields||[]).map((f:any)=>({id:crypto.randomUUID(),label:f.name||'Field',value:f.value||'',kind:f.type===1?'password':'text'}));for(const [label,value]of Object.entries(x.card||x.identity||{}))if(value)i.fields.push({id:crypto.randomUUID(),label,value:String(value),kind:/number|code/i.test(label)?'password':'text'});return i;});}
const CATEGORIES:Record<string,ItemType>={'001':'login','002':'creditCard','003':'secureNote','004':'identity','005':'password','006':'document','100':'softwareLicense','101':'bankAccount','102':'apiCredential','103':'driversLicense','104':'membership','105':'membership','106':'passport','107':'membership','108':'identity','109':'wifi','110':'apiCredential','111':'login','112':'apiCredential','113':'secureNote','114':'sshKey'};
const FIELD_LABELS:Record<string,string>={ccnum:'Card number',cvv:'CVV',cardholder:'Cardholder name',expiry:'Expiry',firstname:'First name',lastname:'Last name',initial:'Middle name',defphone:'Phone',email:'Email'};
export function import1PUX(bytes:Uint8Array):{vaults:Vault[];items:Item[];warnings:string[]}{
  if(bytes.byteLength>100_000_000)throw new Error('Import exceeds 100 MB');let total=0;
  const files=unzipSync(bytes,{filter:file=>{total+=file.originalSize;if(total>250_000_000)throw new Error('Expanded import exceeds 250 MB');return true;}});
  if(!files['export.data'])throw new Error('Missing 1PUX export.data');const d=JSON.parse(strFromU8(files['export.data']));const vaults:Vault[]=[];const items:Item[]=[];const warnings:string[]=[];
  for(const account of d.accounts||[])for(const vault of account.vaults||[]){const v={id:crypto.randomUUID(),name:vault.attrs?.name||'Imported vault',allowAssistant:false,allowBrowser:true,travelSafe:false};vaults.push(v);
    for(const x of vault.items||[]){const ov=x.overview||{},details=x.details||{};let type=CATEGORIES[x.categoryUuid]||'secureNote';if(type==='database' as ItemType)type='apiCredential';const i=newItem(type,ov.title||'Imported item',v.id);i.urls=(ov.urls||[]).map((u:any)=>u.url).filter((u:unknown)=>typeof u==='string'&&/^https?:\/\//.test(u));if(ov.url&&!i.urls.includes(ov.url)&&/^https?:\/\//.test(ov.url))i.urls.unshift(ov.url);i.notes=details.notesPlain||'';i.tags=ov.tags||[];i.favorite=(x.favIndex||ov.favIndex||ov.faveIndex||0)>0;i.archived=!!x.state&&x.state!=='active';
      if(typeof details.password==='string')i.password=details.password;
      if(Number.isFinite(x.createdAt))i.createdAt=new Date(x.createdAt*1000).toISOString();
      for(const f of details.loginFields||[]){if(!f)continue;if(f.designation==='username')i.username=f.value;else if(f.designation==='password')i.password=f.value;else if(f.value)i.fields.push({id:crypto.randomUUID(),label:f.name||'Web form field',value:String(f.value),kind:f.fieldType==='P'?'password':'text',section:'Web form details'});}
      for(const section of details.sections||[])for(const f of section.fields||[]){if(!f)continue;const value=f.value||{};let raw=value.string??value.concealed??value.creditCardNumber??value.email??value.phone??value.url??value.totp??value.date??value.monthYear??value.menu??value.gender??value.creditCardType??JSON.stringify(value);
        if(value.email&&typeof value.email==='object')raw=value.email.email_address||JSON.stringify(value.email);else if(typeof raw==='object')raw=JSON.stringify(raw);
        if(Number.isFinite(value.date))raw=new Date(value.date*1000).toISOString().slice(0,10);
        if(value.monthYear&&/^\d{6}$/.test(String(value.monthYear))){const ym=String(value.monthYear);raw=`${ym.slice(4)}/${ym.slice(0,4)}`;}
        const label=FIELD_LABELS[f.id]||f.title||f.id||'Field';if(value.totp||/^TOTP_/.test(f.id||''))i.totp=String(raw);
        if(i.type==='login'||i.type==='password'){if(!i.password&&/^password$/i.test(f.id||f.title||''))i.password=String(raw);if(!i.username&&/^username$/i.test(f.id||f.title||''))i.username=String(raw);}
        i.fields.push({id:crypto.randomUUID(),label,value:String(raw),kind:value.concealed||value.sshKey?'password':value.date?'date':'text',section:section.title||''});
        if(value.address&&typeof value.address==='object'){for(const [key,label]of Object.entries({street:'Address',city:'City',country:'Country',zip:'Postal code',state:'State'}))if(value.address[key])i.fields.push({id:crypto.randomUUID(),label,value:String(value.address[key]),kind:'text',section:section.title||''});}
        if(/expir/i.test(label)&&Number.isFinite(value.date))i.expiresAt=String(raw);
      }
      i.passwordHistory=(details.passwordHistory||[]).map((h:any)=>({password:h.value||h.password||'',changedAt:new Date((h.time||0)*1000).toISOString()})).filter((h:any)=>h.password);
      for(const doc of [details.documentAttributes,...(details.sections||[]).flatMap((s:any)=>(s.fields||[]).map((f:any)=>f.value?.file))].filter(Boolean)){const id=doc.documentId||doc.fileId;const name=doc.fileName||doc.name||'Attachment';const key=Object.keys(files).find(k=>k.startsWith('files/')&&(k.includes(id)||k.endsWith(name)));if(key)i.attachments.push({id:crypto.randomUUID(),name,mime:'application/octet-stream',data:Buffer.from(files[key]).toString('base64')});else warnings.push(`Attachment missing for ${i.title}: ${name}`);}
      items.push(i);
    }
  }
  if(!vaults.length)throw new Error('No vaults found in export');return {vaults,items,warnings};
}
