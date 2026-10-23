import {randomUUID,randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {deriveKey,newEnvelope,seal,open,generateSecretKey,validateEnvelope} from './crypto.ts';
import {newItem,totp,matchesUrl,isAssistantForbidden,parseTotp,generatePassword,type GeneratorOptions} from './utilities.ts';
import {watchtower} from './watchtower.ts';
import {ITEM_TYPES,AGENT_PERMISSIONS,type Activity,type AgentPermission,type AgentOptions,type AgentUpdate,type AssistantLoginInput,type AssistantLoginFields,type AssistantLoginSummary,type AssistantDeletion,type VaultStorage,type VaultData,type Envelope,type Item,type Vault,type TokenRecord} from './types.ts';

export interface SyncLimits {maxCiphertextBytes:number;maxEnvelopeBytes:number}

export class VaultEngine {
  private current:VaultData|null=null;private key:Buffer|null=null;private envelope:Envelope|null=null;private initialized=false;private lastTouch=Date.now();private generation=0;private writes:Promise<void>=Promise.resolve();private operations:Promise<unknown>=Promise.resolve();private pendingAgentActivity:Activity[]=[];private agentIdentities=new Map<string,TokenRecord>();
  constructor(private storage:VaultStorage,private onLock?:()=>void){}
  async load():Promise<void>{this.envelope=await this.storage.read();if(this.envelope)validateEnvelope(this.envelope);this.initialized=!!this.envelope;}
  status(){this.checkIdle();return {initialized:this.initialized,locked:!this.current};}
  private async exclusive<T>(fn:()=>Promise<T>):Promise<T>{const result=this.operations.then(fn,fn);this.operations=result.then(()=>undefined,()=>undefined);return result;}
  async initialize(password:string,secret=generateSecretKey()):Promise<{secretKey:string}>{
    return this.exclusive(async()=>{const generation=this.generation;await this.load();if(this.initialized)throw new Error('Vault already exists');if(password.length<14)throw new Error('Use at least 14 characters for the master password');const e=newEnvelope();const key=await deriveKey(password,secret,e);if(generation!==this.generation){key.fill(0);throw new Error('Unlock cancelled');}
      const at=new Date().toISOString();const d:VaultData={schema:1,deviceId:randomUUID(),vaults:['Personal','Business','Social Media'].map(name=>({id:randomUUID(),name,allowAssistant:false,allowBrowser:true,travelSafe:false})),items:[],activity:[{id:randomUUID(),at,action:'vault.created'}],settings:{idleMinutes:5,travelMode:false,notifyAssistant:false,agentRequireItemApproval:false},assistantTokens:[],revision:0};
      const encrypted=seal(d,key,e);try{await this.storage.write(encrypted);}catch(error){key.fill(0);throw error;}if(generation!==this.generation){key.fill(0);throw new Error('Unlock cancelled');}this.key=key;this.envelope=encrypted;this.current=d;this.initialized=true;this.generation++;this.touch();return {secretKey:secret};});
  }
  async unlock(password:string,secret:string):Promise<void>{const generation=this.generation;await this.writes;const e=await this.storage.read();if(!e)throw new Error('Create a vault first');validateEnvelope(e);const key=await deriveKey(password,secret,e);if(generation!==this.generation){key.fill(0);throw new Error('Unlock cancelled');}let data:VaultData;try{data=open(e,key);}catch(error){key.fill(0);throw error;}this.key?.fill(0);this.key=key;this.current=data;this.envelope=e;this.initialized=true;this.generation++;this.touch();await this.flushAgentActivity();await this.record('vault.unlocked');}
  async unlockWithKey(key:Uint8Array,reason:'biometric'|'deviceResume'|'pin'='biometric'):Promise<void>{const generation=this.generation;await this.writes;const e=await this.storage.read();if(!e)throw new Error('No vault');const k=Buffer.from(key);let data:VaultData;try{data=open(e,k);}catch(error){k.fill(0);throw error;}if(generation!==this.generation){k.fill(0);throw new Error('Unlock cancelled');}this.key?.fill(0);this.key=k;this.current=data;this.envelope=e;this.initialized=true;this.generation++;this.touch();await this.flushAgentActivity();await this.record(reason==='deviceResume'?'vault.deviceResumed':reason==='pin'?'vault.pinUnlock':'vault.biometricUnlock');}
  private async flushAgentActivity():Promise<void>{if(this.pendingAgentActivity.length&&this.current){this.current.activity.push(...this.pendingAgentActivity.splice(0));await this.save();}}
  sessionVersion():number{return this.generation;}
  exportSessionKey():Uint8Array{return Buffer.from(this.requireKey());}
  lock():void{if(this.current)for(const t of this.current.assistantTokens)this.agentIdentities.set(t.hash,structuredClone(t));if(this.current&&this.key&&this.envelope){this.current.activity.push({id:randomUUID(),at:new Date().toISOString(),action:'vault.locked'});this.current.revision++;const e=seal(this.current,this.key,this.envelope);this.envelope=e;this.writes=this.writes.then(()=>this.storage.write(e)).catch(()=>{});}this.generation++;this.key?.fill(0);this.key=null;this.current=null;try{this.onLock?.();}catch{}}
  data():VaultData {this.checkIdle();if(!this.current)throw new Error('Vault is locked');return this.current;}
  private requireKey():Buffer {this.checkIdle();if(!this.key||!this.current)throw new Error('Vault is locked');return this.key;}
  touch():void{this.lastTouch=Date.now();}
  checkIdle():void{if(this.current&&this.current.settings.idleMinutes>0&&Date.now()-this.lastTouch>=this.current.settings.idleMinutes*60000)this.lock();}
  async save():Promise<void>{const key=this.requireKey();const data=this.current!;if(!this.envelope)throw new Error('No vault');data.revision++;const e=seal(data,key,this.envelope);this.envelope=e;const write=this.writes.then(()=>this.storage.write(e));this.writes=write.catch(()=>{});await write;}
  async record(action:string,itemId?:string,detail?:string):Promise<void>{const d=this.data();d.activity.push({id:randomUUID(),at:new Date().toISOString(),action,itemId,detail});await this.save();}
  async addVault(name:string):Promise<Vault>{const d=this.data();if(!name.trim()||name.length>128)throw new Error('Enter a vault name');const v={id:randomUUID(),name:name.trim(),allowAssistant:false,allowBrowser:true,travelSafe:false};d.vaults.push(v);await this.record('vault.added',undefined,v.id);return v;}
  async updateVault(id:string,changes:Partial<Pick<Vault,'name'|'allowAssistant'|'allowBrowser'|'travelSafe'>>):Promise<Vault>{return this.exclusive(async()=>{
    if(!changes||typeof changes!=='object'||Array.isArray(changes)||Object.keys(changes).some(key=>!['name','allowAssistant','allowBrowser','travelSafe'].includes(key)))throw new Error('Invalid vault settings');
    if(changes.name!==undefined&&(typeof changes.name!=='string'||!changes.name.trim()||changes.name.trim().length>128))throw new Error('Enter a vault name');
    for(const key of ['allowAssistant','allowBrowser','travelSafe'] as const)if(changes[key]!==undefined&&typeof changes[key]!=='boolean')throw new Error('Invalid vault settings');
    const base=this.data();const draft=structuredClone(base);const vault=draft.vaults.find(v=>v.id===id);if(!vault)throw new Error('Unknown vault');for(const [key,value]of Object.entries(changes))if(value!==undefined)(vault as unknown as Record<string,unknown>)[key]=key==='name'?(value as string).trim():value;
    draft.activity.push({id:randomUUID(),at:new Date().toISOString(),action:'vault.settingsChanged',detail:id});await this.commitDraft(base,draft);return structuredClone(vault);
  });}
  async upsertItem(input:Partial<Item>&{title:string;vaultId:string;type:Item['type']}):Promise<Item>{
    const d=this.data();if(!d.vaults.some(v=>v.id===input.vaultId))throw new Error('Unknown vault');if(!ITEM_TYPES.includes(input.type)||!input.title?.trim()||input.title.length>512)throw new Error('Invalid item');
    if(input.totp)parseTotp(input.totp);for(const url of input.urls||[]){const u=new URL(url);if(!['https:','http:'].includes(u.protocol)||u.username||u.password)throw new Error('Use a website URL without embedded credentials');}
    const old=input.id?d.items.find(i=>i.id===input.id):undefined;const item:Item={...(old||newItem(input.type,input.title,input.vaultId)),...structuredClone(input),updatedAt:new Date().toISOString()};
    item.passwordHistory=old?structuredClone(old.passwordHistory):(input.passwordHistory||[]).map(h=>{if(typeof h.password!=='string'||typeof h.changedAt!=='string')throw new Error('Invalid password history');return {password:h.password,changedAt:h.changedAt};});if(old?.password&&old.password!==item.password)item.passwordHistory.push({password:old.password,changedAt:item.updatedAt});
    if(isAssistantForbidden(item)||item.type!=='login')item.allowAssistant=false;
    if(JSON.stringify(item.attachments).length>25_000_000)throw new Error('Attachments exceed the 18 MB per item limit');
    if(old)d.items[d.items.indexOf(old)]=item;else d.items.push(item);await this.record(old?'item.edited':'item.created',item.id);return structuredClone(item);
  }
  async deleteItem(id:string):Promise<void>{const i=this.data().items.find(i=>i.id===id);if(!i)throw new Error('Item not found');i.deletedAt=new Date().toISOString();i.restoreUntil=new Date(Date.now()+30*24*60*60*1000).toISOString();i.updatedAt=i.deletedAt;i.allowAssistant=false;await this.record('item.deleted',id);}
  async restoreItem(id:string):Promise<void>{const i=this.data().items.find(i=>i.id===id);if(!i)throw new Error('Item not found');delete i.deletedAt;delete i.restoreUntil;i.updatedAt=new Date().toISOString();i.restoredAt=i.updatedAt;i.allowAssistant=false;await this.record('item.restored',id);}
  async createToken(name:string,options:AgentOptions={}):Promise<{id:string;token:string}>{
    const d=this.data();const displayName=this.agentDisplayName(name);const clientName=options.clientName??this.availableClientName(displayName);
    if(!/^[a-z][a-z0-9_-]{0,63}$/.test(clientName)||['owner','admin','cli','browser','provider','admin-token','browser-token','provider-token'].includes(clientName))throw new Error('Use a unique agent client name starting with a lowercase letter');
    if(d.assistantTokens.some(t=>t.clientName===clientName))throw new Error('Agent client name already exists');
    const permission=options.permission??'full';const vaultIds=options.vaultIds??d.vaults.filter(v=>v.allowAssistant).map(v=>v.id);this.validateAgentAccess(permission,vaultIds,d);
    const token=`jjv_${randomBytes(48).toString('base64url')}`;const id=randomUUID();
    const draft=structuredClone(d);draft.assistantTokens.push({id,name:displayName,clientName,permission,vaultIds:[...vaultIds],hash:tokenHash(token),createdAt:new Date().toISOString(),calls:[],writeCalls:[]});
    draft.activity.push({id:randomUUID(),at:new Date().toISOString(),action:'assistant.tokenCreated',detail:id,agentId:id,agentClientName:clientName,agentName:displayName});await this.commitDraft(d,draft);return {id,token};
  }
  async updateAgent(id:string,changes:AgentUpdate):Promise<void>{
    const d=this.data();const t=d.assistantTokens.find(t=>t.id===id);if(!t)throw new Error('Token not found');
    if(Object.keys(changes).some(k=>!['name','permission','vaultIds'].includes(k)))throw new Error('Invalid agent settings');
    const name=changes.name===undefined?t.name:this.agentDisplayName(changes.name);const permission=changes.permission??t.permission;const vaultIds=changes.vaultIds??t.vaultIds;this.validateAgentAccess(permission,vaultIds,d);
    // Apply owner permission changes immediately so an in flight assistant response cannot retain access.
    const old={name:t.name,permission:t.permission,vaultIds:t.vaultIds};Object.assign(t,{name,permission,vaultIds:[...vaultIds]});
    try{await this.record('assistant.permissionsChanged',undefined,id);}catch(error){if(this.current===d)Object.assign(t,old);throw error;}
  }
  async revokeToken(id:string):Promise<void>{const d=this.data();const t=d.assistantTokens.find(t=>t.id===id);if(!t)throw new Error('Token not found');const old=t.revokedAt;t.revokedAt=new Date().toISOString();try{await this.record('assistant.tokenRevoked',undefined,id);}catch(error){if(this.current===d)t.revokedAt=old;throw error;}}
  authenticateToken(token:string):TokenRecord|null{if(typeof token!=='string'||token.length<40||token.length>256)return null;const hash=Buffer.from(tokenHash(token),'hex');return this.data().assistantTokens.find(t=>!t.revokedAt&&t.hash.length===64&&timingSafeEqual(hash,Buffer.from(t.hash,'hex')))||null;}
  private agentDisplayName(name:string):string{if(typeof name!=='string'||!name.trim()||name.trim().length>128||/[\u0000-\u001f\u007f]/.test(name))throw new Error('Enter an agent name');return name.trim();}
  private availableClientName(name:string):string{const base=name.toLowerCase().replace(/[^a-z0-9_-]+/g,'_').replace(/^[^a-z]+/,'').slice(0,48)||'agent';let candidate=base,n=2;while(this.data().assistantTokens.some(t=>t.clientName===candidate)||['owner','admin','cli','browser','provider','admin-token','browser-token','provider-token'].includes(candidate))candidate=base+'_'+n++;return candidate;}
  private validateAgentAccess(permission:AgentPermission,vaultIds:string[],d:VaultData):void{if(!AGENT_PERMISSIONS.includes(permission))throw new Error('Invalid agent permission');if(!Array.isArray(vaultIds)||new Set(vaultIds).size!==vaultIds.length||vaultIds.some(id=>typeof id!=='string'||!d.vaults.some(v=>v.id===id)))throw new Error('Unknown vault access');}
  private identifyAgent(token:string):TokenRecord|undefined{if(typeof token!=='string'||token.length<40||token.length>256)return;const hash=tokenHash(token);const t=this.current?.assistantTokens.find(t=>t.hash===hash);if(t){this.agentIdentities.set(hash,structuredClone(t));return t;}return this.agentIdentities.get(hash);}
  private authenticate(token:string):TokenRecord{this.data();const t=this.authenticateToken(token);if(!t)throw new Error('Invalid API token');return t;}
  private requirePermission(t:TokenRecord,level:AgentPermission):void{if(AGENT_PERMISSIONS.indexOf(t.permission)<AGENT_PERMISSIONS.indexOf(level))throw new Error('Permission denied');}
  private agentVaultAllowed(t:TokenRecord,vaultId:string,d=this.data()):boolean{const v=d.vaults.find(v=>v.id===vaultId);return !!v&&t.vaultIds.includes(vaultId)&&v.allowAssistant&&(!d.settings.travelMode||v.travelSafe);}
  private allowed(i:Item,t:TokenRecord,loginOnly=true,d=this.data()):boolean{return (!loginOnly||i.type==='login')&&this.agentVaultAllowed(t,i.vaultId,d)&&(!d.settings.agentRequireItemApproval||i.allowAssistant===true)&&!isAssistantForbidden(i)&&!i.deletedAt&&!i.archived;}
  private agentEntry(t:TokenRecord|undefined,action:string,name:string|undefined,outcome:Activity['outcome'],itemId?:string):Activity{return {id:randomUUID(),at:new Date().toISOString(),action,agentId:t?.id??'unknown',agentClientName:t?.clientName??'unknown',agentName:t?.name??'Unknown agent',...(typeof name==='string'&&name?{itemName:name.replace(/[\u0000-\u001f\u007f]/g,'').slice(0,512)}:{}),...(itemId?{itemId}:{}),outcome,detail:t?.id};}
  private async commitDraft(base:VaultData,draft:VaultData,token?:string,permission:AgentPermission='read'):Promise<void>{
    const key=this.requireKey();if(this.current!==base||!this.envelope)throw new Error('Vault changed. Try again');const revision=base.revision;const generation=this.generation;
    const policyFingerprint=()=>{const t=token?this.authenticateToken(token):null;return JSON.stringify({agent:t?{id:t.id,permission:t.permission,vaultIds:t.vaultIds,revokedAt:t.revokedAt}:null,vaults:base.vaults.map(v=>[v.id,v.allowAssistant,v.travelSafe]),travelMode:base.settings.travelMode,itemApproval:base.settings.agentRequireItemApproval});};const policy=token?policyFingerprint():undefined;
    const check=()=>{if(this.current!==base||generation!==this.generation)throw new Error('Vault is locked');if(base.revision!==revision)throw new Error('Vault permissions or content changed. Try again');if(token){this.requirePermission(this.authenticate(token),permission);if(policyFingerprint()!==policy)throw new Error('Agent access changed');}};check();draft.revision=revision+1;const encrypted=seal(draft,key,this.envelope);
    const write=this.writes.then(async()=>{check();await this.storage.write(encrypted);});this.writes=write.catch(()=>{});await write;check();this.envelope=encrypted;this.current=draft;
  }
  private async agentAudit(t:TokenRecord|undefined,action:string,name:string|undefined,outcome:Activity['outcome'],itemId?:string,token?:string,permission:AgentPermission='read'):Promise<void>{
    const entry=this.agentEntry(t,action,name,outcome,itemId);
    if(!this.current){this.pendingAgentActivity.push(entry);return;}
    const base=this.data();const draft=structuredClone(base);draft.activity.push(entry);await this.commitDraft(base,draft,token,permission);
  }
  private async agentAction<T>(token:string,action:string,name:string|undefined,permission:AgentPermission,bucket:'read'|'write'|undefined,fn:(t:TokenRecord)=>Promise<{value:T;item?:Item;audited?:boolean}>):Promise<T>{
    return this.exclusive(async()=>{let t:TokenRecord|undefined=this.identifyAgent(token);try{
      t=this.authenticate(token);this.requirePermission(t,permission);
      if(bucket){const base=this.data();const draft=structuredClone(base);const record=draft.assistantTokens.find(a=>a.id===t!.id)!;const now=Date.now();const key=bucket==='read'?'calls':'writeCalls';const limit=bucket==='read'?10:30;record[key]=record[key].filter(at=>at>now-3600000);if(record[key].length>=limit)throw new Error(bucket==='read'?'Rate limit exceeded: 10 get_login calls per hour per agent':'Rate limit exceeded: 30 writes per hour per agent');record[key].push(now);draft.activity.push(this.agentEntry(t,action+'.requested',name,'success'));await this.commitDraft(base,draft,token,permission);t=this.authenticate(token);}
      const result=await fn(t);if(!result.audited)await this.agentAudit(t,action,result.item?.title??name,'success',result.item?.id,token,permission);
      const currentToken=this.authenticate(token);this.requirePermission(currentToken,permission);if(result.item){const live=this.data().items.find(i=>i.id===result.item!.id);if(!live||((action!=='assistant.delete')&&!this.allowed(live,currentToken,action!=='assistant.search'))||(action==='assistant.delete'&&(!live.deletedAt||isAssistantForbidden(live)||!this.agentVaultAllowed(currentToken,live.vaultId))))throw new Error('Agent access changed');}
      return result.value;
    }catch(error){try{await this.agentAudit(t,action,name,(error as Error).message?.startsWith('Rate limit')?'rate_limited':'denied');}catch{this.pendingAgentActivity.push(this.agentEntry(t,action,name,'denied'));}throw error;}});
  }
  private assistantSummary(i:Item):AssistantLoginSummary{return {name:i.title,website:i.urls[0]||'',vault:this.data().vaults.find(v=>v.id===i.vaultId)!.name,tags:[...i.tags]};}
  private findAssistantLogin(t:TokenRecord,name:string):Item{if(typeof name!=='string'||!name.trim()||name.length>512)throw new Error('Enter a login name');const hits=this.data().items.filter(i=>this.allowed(i,t)&&i.title===name);if(hits.length!==1)throw new Error(hits.length?'Multiple allowed logins share this name. Rename them in JJ Vault.':'Allowed login not found');return hits[0];}
  private validateAssistantFields(input:AssistantLoginFields,adding=false):void{
    if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(k=>!['name','website','username','password','notes','totp_secret','tags'].includes(k)))throw new Error('Invalid login fields');
    for(const key of ['name','website','username','password','notes','totp_secret'] as const)if(input[key]!==undefined&&(typeof input[key]!=='string'||input[key]!.length>(key==='notes'?100000:4096)))throw new Error('Invalid login field');
    if((adding||input.name!==undefined)&&(!input.name?.trim()||input.name.length>512))throw new Error('Enter a login name');
    if(input.website!==undefined&&input.website!==''){try{const u=new URL(input.website);if(!['https:','http:'].includes(u.protocol)||u.username||u.password)throw new Error();}catch{throw new Error('Use a website URL without embedded credentials');}}
    if(input.totp_secret)parseTotp(input.totp_secret);
    if(input.tags!==undefined&&(!Array.isArray(input.tags)||input.tags.length>100||input.tags.some(tag=>typeof tag!=='string'||tag.length>128)))throw new Error('Invalid tags');
  }
  async auditAssistantAttempt(token:string,action:string,name?:string,outcome:'denied'|'rate_limited'='denied'):Promise<void>{
    const allowedActions=['assistant.list','assistant.get','assistant.add','assistant.edit','assistant.delete','assistant.generate','assistant.search'];if(!allowedActions.includes(action))return;
    await this.exclusive(async()=>{const t=this.identifyAgent(token);try{await this.agentAudit(t,action,name,outcome);}catch{this.pendingAgentActivity.push(this.agentEntry(t,action,name,outcome));}});
  }
  async listAssistantLogins(token:string):Promise<AssistantLoginSummary[]>{return this.agentAction(token,'assistant.list',undefined,'read',undefined,async t=>({value:this.data().items.filter(i=>this.allowed(i,t)).map(i=>this.assistantSummary(i))}));}
  async getAssistantLogin(token:string,name:string):Promise<{username:string;password:string;totp?:string}>{return this.agentAction(token,'assistant.get',name,'read','read',async t=>{const i=this.findAssistantLogin(t,name);const code=i.totp?await totp(i.totp):undefined;return {value:{username:i.username||'',password:i.password||'',...(code?{totp:code}:{})},item:i};});}
  async addAssistantLogin(token:string,input:AssistantLoginInput):Promise<AssistantLoginSummary>{return this.agentAction(token,'assistant.add',input?.name,'read_add','write',async t=>{
    if(!input||typeof input!=='object'||typeof input.vault!=='string')throw new Error('Choose a vault');const {vault,...fields}=input;this.validateAssistantFields(fields,true);const d=this.data();const vaults=d.vaults.filter(v=>v.id===vault||v.name===vault);if(vaults.length!==1||!this.agentVaultAllowed(t,vaults[0].id))throw new Error('Agent vault access denied');
    if(d.settings.agentRequireItemApproval)throw new Error('Owner item approval is required before an agent can add a login');
    const item={...newItem('login',input.name.trim(),vaults[0].id),urls:input.website?[input.website]:[],username:input.username,password:input.password||generatePassword({length:32}),notes:input.notes??'',totp:input.totp_secret||undefined,tags:input.tags??[]};if(isAssistantForbidden(item))throw new Error('Bank and X Money items are blocked');
    const draft=structuredClone(d);draft.items.push(item);draft.activity.push(this.agentEntry(t,'assistant.add',item.title,'success',item.id));await this.commitDraft(d,draft,token,'read_add');return {value:this.assistantSummary(item),item,audited:true};
  });}
  async updateAssistantLogin(token:string,name:string,fields:AssistantLoginFields):Promise<AssistantLoginSummary>{return this.agentAction(token,'assistant.edit',name,'read_add_edit','write',async t=>{
    this.validateAssistantFields(fields);if(!Object.keys(fields).length)throw new Error('Provide fields to change');const old=this.findAssistantLogin(t,name);const item=structuredClone(old);const at=new Date().toISOString();if(fields.name!==undefined)item.title=fields.name.trim();if(fields.website!==undefined)item.urls=fields.website?[fields.website]:[];for(const key of ['username','password','notes'] as const)if(fields[key]!==undefined)item[key]=fields[key];if(fields.totp_secret!==undefined)item.totp=fields.totp_secret||undefined;if(fields.tags!==undefined)item.tags=[...fields.tags];if(isAssistantForbidden(item))throw new Error('Bank and X Money items are blocked');if(old.password&&old.password!==item.password)item.passwordHistory.push({password:old.password,changedAt:at});item.updatedAt=at;const d=this.data();const draft=structuredClone(d);draft.items[draft.items.findIndex(i=>i.id===item.id)]=item;draft.activity.push(this.agentEntry(t,'assistant.edit',item.title,'success',item.id));await this.commitDraft(d,draft,token,'read_add_edit');return {value:this.assistantSummary(item),item,audited:true};
  });}
  async deleteAssistantLogin(token:string,name:string):Promise<AssistantDeletion>{return this.agentAction(token,'assistant.delete',name,'full','write',async t=>{const old=this.findAssistantLogin(t,name);const item=structuredClone(old);item.deletedAt=new Date().toISOString();item.restoreUntil=new Date(Date.now()+30*24*60*60*1000).toISOString();item.updatedAt=item.deletedAt;item.allowAssistant=false;const d=this.data();const draft=structuredClone(d);draft.items[draft.items.findIndex(i=>i.id===item.id)]=item;draft.activity.push(this.agentEntry(t,'assistant.delete',item.title,'success',item.id));await this.commitDraft(d,draft,token,'full');return {value:{name:item.title,deleted:true,restoreUntil:item.restoreUntil},item,audited:true};});}
  async generateAssistantPassword(token:string,options:GeneratorOptions={}):Promise<{password:string}>{return this.agentAction(token,'assistant.generate',undefined,'read',undefined,async()=>({value:{password:generatePassword(options)}}));}
  async searchAssistantItems(token:string,query:string):Promise<{name:string;website:string}[]>{return this.agentAction(token,'assistant.search',undefined,'read',undefined,async t=>{if(typeof query!=='string'||query.length>512)throw new Error('Invalid search query');const q=query.toLocaleLowerCase();return {value:this.data().items.filter(i=>this.allowed(i,t,false)&&[i.title,...i.urls,...i.tags].some(value=>value.toLocaleLowerCase().includes(q))).map(i=>({name:i.title,website:i.urls[0]||''}))};});}
  browserList(url:string):{id:string;title:string;username?:string;type:string}[]{const d=this.data();return d.items.filter(i=>this.browserAllowed(i,url)).map(i=>({id:i.id,title:i.title,username:i.username,type:i.type}));}
  private browserAllowed(i:Item,url:string):boolean{const d=this.data();const v=d.vaults.find(v=>v.id===i.vaultId);if(!v?.allowBrowser||i.archived||i.deletedAt||(d.settings.travelMode&&!v.travelSafe)||!['login','creditCard','identity'].includes(i.type))return false;try{const u=new URL(url);if(!['https:','http:'].includes(u.protocol))return false;if(i.type!=='login'&&u.protocol!=='https:')return false;return i.urls.length?i.urls.some(saved=>matchesUrl(saved,url)):i.type!=='login';}catch{return false;}}
  async browserGet(id:string,url:string):Promise<Item>{const generation=this.generation;const i=this.data().items.find(i=>i.id===id);if(!i||!this.browserAllowed(i,url))throw new Error('This item cannot fill this website');await this.record('browser.fill',id);if(generation!==this.generation)throw new Error('Vault is locked');if(!this.browserAllowed(i,url))throw new Error('Browser permission changed');return structuredClone(i);}
  async exportEncrypted():Promise<Envelope>{this.data();await this.save();return structuredClone(this.envelope!);}
  async importEncrypted(envelope:Envelope,password:string,secret:string,beforeReplace?:()=>void):Promise<void>{const generation=this.generation;validateEnvelope(envelope);const key=await deriveKey(password,secret,envelope);let data:VaultData;try{data=open(envelope,key);}catch(error){key.fill(0);throw error;}await this.writes;if(generation!==this.generation){key.fill(0);throw new Error('Vault is locked');}try{beforeReplace?.();await this.storage.write(envelope);}catch(error){key.fill(0);throw error;}if(generation!==this.generation){key.fill(0);throw new Error('Vault is locked');}this.key?.fill(0);this.key=key;this.current=data;this.envelope=envelope;this.initialized=true;this.generation++;this.touch();await this.record('backup.restored');}
  async watchtower(checkBreaches=false){const d=this.data();const items=d.items.filter(i=>!d.settings.travelMode||d.vaults.some(v=>v.id===i.vaultId&&v.travelSafe));return watchtower(items,checkBreaches);}
  async exportForSync():Promise<Envelope>{
    // Capture one local snapshot without replacing live data or awaiting a pending agent write.
    const generation=this.generation;const data=this.data();const key=this.requireKey();const envelope=this.envelope;if(!envelope)throw new Error('No vault');
    const encrypted=seal(this.syncSnapshot(data),key,envelope);if(generation!==this.generation||!this.current)throw new Error('Vault is locked');return encrypted;
  }
  private syncSnapshot(data:VaultData):VaultData{
    const draft=structuredClone(data);if(draft.settings.travelMode){draft.vaults=draft.vaults.filter(v=>v.travelSafe);draft.items=draft.items.filter(i=>draft.vaults.some(v=>v.id===i.vaultId));}draft.assistantTokens=[];draft.activity=[];return draft;
  }
  async mergeEncrypted(envelope:Envelope,limits?:SyncLimits):Promise<void>{
    const generation=this.generation;const incoming=structuredClone(envelope);const bounds=limits===undefined?undefined:{maxCiphertextBytes:limits?.maxCiphertextBytes,maxEnvelopeBytes:limits?.maxEnvelopeBytes};
    return this.exclusive(async()=>{
      // A request queued in a previous unlocked session must not resume after a lock and reopen.
      if(generation!==this.generation)throw new Error('Vault is locked');
      if(bounds&&Object.values(bounds).some(value=>!Number.isSafeInteger(value)||value<=0||value>100_000_000))throw new Error('Invalid sync size limits');
      const base=this.data();const key=this.requireKey();if(!this.envelope||incoming.id!==this.envelope.id)throw new Error('This is a different vault. Restore its encrypted backup to pair this device first.');
      const remote=open(incoming,key);const draft=mergeData(base,remote);
      if(bounds){
        // Match the committed revision and exported data before changing any local state.
        draft.revision=base.revision+1;const exported=seal(this.syncSnapshot(draft),key,this.envelope);
        if(Buffer.from(exported.ciphertext,'base64').byteLength>bounds.maxCiphertextBytes||Buffer.byteLength(JSON.stringify(exported),'utf8')>bounds.maxEnvelopeBytes)throw new Error('Merged vault exceeds the sync service size limit. Remove large attachments or use another sync service before syncing.');
      }
      // mergeData keeps all local agent grants, quotas, activity and device settings.
      draft.activity.push({id:randomUUID(),at:new Date().toISOString(),action:'sync.merged'});await this.commitDraft(base,draft);
    });
  }
}
export function tokenHash(token:string):string{return createHash('sha256').update(token).digest('hex');}
export function mergeData(local:VaultData,remote:VaultData):VaultData{
  const d=structuredClone(local);for(const v of remote.vaults)if(!d.vaults.some(x=>x.id===v.id))d.vaults.push({...v,allowAssistant:false});
  for(const ri of remote.items){const i=d.items.find(x=>x.id===ri.id);if(!i){d.items.push({...structuredClone(ri),allowAssistant:false});continue;}const wasDeleted=!!i.deletedAt;const incomingRestore=!!ri.restoredAt&&ri.restoredAt>(i.restoredAt||'');
    const history=[...i.passwordHistory,...ri.passwordHistory];if(i.password&&ri.password&&i.password!==ri.password)history.push({password:ri.updatedAt>i.updatedAt?i.password:ri.password,changedAt:ri.updatedAt>i.updatedAt?ri.updatedAt:i.updatedAt});
    const uniqueHistory=[...new Map(history.map(h=>[h.password+'\0'+h.changedAt,h])).values()].sort((a,b)=>a.changedAt.localeCompare(b.changedAt));
    const deleted=[i,ri].filter(x=>x.deletedAt).sort((a,b)=>(b.deletedAt||'').localeCompare(a.deletedAt||''))[0];const restored=[i,ri].sort((a,b)=>(b.restoredAt||'').localeCompare(a.restoredAt||''))[0];
    if(deleted&&(!restored.restoredAt||deleted.deletedAt!>=restored.restoredAt)){Object.assign(i,structuredClone(deleted),{allowAssistant:false,passwordHistory:uniqueHistory});continue;}
    const localAllowed=i.allowAssistant;
    if(ri.updatedAt>i.updatedAt)Object.assign(i,structuredClone(ri),{allowAssistant:localAllowed});
    else if(ri.updatedAt===i.updatedAt&&comparable(i)!==comparable(ri)){
      // A stable identifier makes retries idempotent, including differently ordered JSON from Swift.
      const hash=createHash('sha256').update(ri.id+'\0'+comparable(ri)).digest('hex');const conflictId=`${hash.slice(0,8)}-${hash.slice(8,12)}-4${hash.slice(13,16)}-a${hash.slice(17,20)}-${hash.slice(20,32)}`;
      if(!d.items.some(x=>x.id===conflictId))d.items.push({...structuredClone(ri),id:conflictId,title:`${ri.title} (sync conflict)`,allowAssistant:false});
    }
    if(restored.restoredAt&&(!deleted||restored.restoredAt>deleted.deletedAt!)){delete i.deletedAt;i.restoredAt=restored.restoredAt;if(wasDeleted||incomingRestore)i.allowAssistant=false;}
    i.passwordHistory=uniqueHistory;
  }
  for(const item of d.items)if(item.type!=='login'||isAssistantForbidden(item))item.allowAssistant=false;
  d.revision=Math.max(local.revision,remote.revision)+1;return d;
}
function comparable(item:Item):string{const {allowAssistant,passwordHistory,...content}=item;const normalize=(v:any):any=>Array.isArray(v)?v.map(normalize):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).filter(k=>v[k]!==undefined&&k!=='backedUp').sort().map(k=>[k,normalize(v[k])])):v;return JSON.stringify(normalize(content));}
