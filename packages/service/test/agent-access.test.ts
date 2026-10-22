import { test } from 'node:test';
import assert from 'node:assert/strict';
import { VaultEngine, type Envelope, newItem } from '../../core/src/index.ts';
import { startLocalService } from '../src/local-service.ts';
import { randomToken } from '../src/security.ts';

async function fixture() {
  let envelope: Envelope | null = null;
  const engine = new VaultEngine({ read: async () => envelope && structuredClone(envelope), write: async e => { envelope = structuredClone(e); } });
  await engine.initialize('fictional master passphrase 742!');
  const vault = engine.data().vaults[0]; vault.allowAssistant = true;
  const login = await engine.upsertItem({ ...newItem('login', 'Example test', vault.id), username: 'fake@example.invalid', password: 'fictionalTestPassword13!', urls: ['https://example.invalid'], totp: 'JBSWY3DPEHPK3PXP', allowAssistant: true });
  const token = await engine.createToken('Test assistant');
  return { engine, login, token: token.token, envelope: () => structuredClone(envelope!) };
}
async function localFixture() { const f = await fixture(); const admin = randomToken(); const service = await startLocalService(f.engine, { port: 0, adminToken: admin }); return { ...f, admin, service, base: `http://127.0.0.1:${service.port}` }; }
function headers(token: string) { return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }; }
async function request(base: string, path: string, token: string, body: unknown, extra: Record<string, string> = {}) { return fetch(base + path, { method: 'POST', headers: { ...headers(token), ...extra }, body: JSON.stringify(body) }); }
async function tool(f: Awaited<ReturnType<typeof localFixture>>, name: string, args = {}) {
  const r = await request(f.base, '/mcp', f.token, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
  return { response: r, body: await r.json() };
}

test('new MCP tools enforce strict schemas and return metadata without write secrets', async t => {
  const f = await localFixture(); t.after(() => f.service.close());
  const tools = await request(f.base, '/mcp', f.token, { jsonrpc:'2.0',id:2,method:'tools/list',params:{} });
  assert.deepEqual((await tools.json()).result.tools.map((value:{name:string})=>value.name).sort(), ['add_login','delete_login','generate_password','get_login','list_logins','search_items','update_login']);
  const input={vault:f.engine.data().vaults[0].name,name:'MCP added',website:'https://new.invalid',username:'fictional user',password:'fictional input secret',notes:'fictional private note',totp_secret:'JBSWY3DPEHPK3PXP',tags:['work']};
  const added=await tool(f,'add_login',input);assert.equal(added.body.result.isError,undefined);assert.deepEqual(JSON.parse(added.body.result.content[0].text),{name:input.name,website:input.website,vault:input.vault,tags:['work']});assert(!JSON.stringify(added.body).includes(input.password));assert(!JSON.stringify(added.body).includes(input.notes));
  const updated=await tool(f,'update_login',{name:input.name,fields:{password:'fictional replacement',username:'new user'}});assert.equal(updated.body.result.isError,undefined);
  const item=f.engine.data().items.find(i=>i.title===input.name)!;assert.equal(item.password,'fictional replacement');assert.equal(item.passwordHistory[0].password,input.password);
  assert.deepEqual(JSON.parse((await tool(f,'search_items',{query:'MCP added'})).body.result.content[0].text),[{name:input.name,website:input.website}]);
  const generated=JSON.parse((await tool(f,'generate_password',{length:37,options:{symbols:false}})).body.result.content[0].text);assert.match(generated.password,/^[a-zA-Z0-9]{37}$/);
  for(const args of [{...input,permission:'full'},{...input,allowAssistant:true},{...input,clientName:'another'}])assert.equal((await tool(f,'add_login',args)).body.result.isError,true);
  for(const fields of [{vault:'Other'},{allowAssistant:true},{type:'bankAccount'},{passwordHistory:[]}])assert.equal((await tool(f,'update_login',{name:input.name,fields})).body.result.isError,true);
  for(const unsupported of ['create_token','update_agent','unlock','restore_item','purge_item']){const result=await tool(f,unsupported,{});assert(result.body.error||result.body.result.isError);}
  const deleted=JSON.parse((await tool(f,'delete_login',{name:input.name})).body.result.content[0].text);assert.equal(deleted.deleted,true);assert(Math.abs(Date.parse(deleted.restoreUntil)-Date.now()-30*86400000)<5000);assert(f.engine.data().items.find(i=>i.id===item.id)?.deletedAt);
  await f.engine.restoreItem(item.id);assert.equal(f.engine.data().items.find(i=>i.id===item.id)?.deletedAt,undefined);
});

test('MCP permission levels and per vault grants constrain every write and search', async t => {
  const f=await localFixture();t.after(()=>f.service.close());
  const other=await f.engine.addVault('Unapproved vault');other.allowAssistant=true;await f.engine.save();
  await f.engine.upsertItem({...newItem('login','Unapproved secret',other.id),password:'fictional excluded',urls:['https://excluded.invalid']});
  for(const permission of ['read','read_add','read_add_edit','full'] as const){
    const agent=await f.engine.createToken('Agent '+permission,{clientName:'test_'+permission,permission,vaultIds:[f.login.vaultId]});f.token=agent.token;
    const input={vault:f.engine.data().vaults[0].name,name:'permission '+permission,website:'https://permissions.invalid',username:'test'};
    const add=await tool(f,'add_login',input);assert.equal(Boolean(add.body.result.isError),permission==='read');
    const update=await tool(f,'update_login',{name:f.login.title,fields:{notes:'changed by '+permission}});assert.equal(Boolean(update.body.result.isError),permission==='read'||permission==='read_add');
    const victim=await f.engine.upsertItem({...newItem('login','delete '+permission,f.login.vaultId),password:'fake'});
    const deletion=await tool(f,'delete_login',{name:victim.title});assert.equal(Boolean(deletion.body.result.isError),permission!=='full');
    assert.deepEqual(JSON.parse((await tool(f,'search_items',{query:'Unapproved'})).body.result.content[0].text),[]);
    assert.equal((await tool(f,'get_login',{name:'Unapproved secret'})).body.result.isError,true);
    assert.equal((await tool(f,'add_login',{...input,name:'disallowed',vault:other.name})).body.result.isError,true);
  }
});

test('writes notify regardless of read notification preference and audit no secret values', async t=>{
  const f=await fixture();const notifications:unknown[]=[];f.engine.data().settings.notifyAssistant=false;
  const admin=randomToken();const service=await startLocalService(f.engine,{port:0,adminToken:admin,notify:async event=>{notifications.push(event);throw new Error('fictional delivery failure secret');}});t.after(()=>service.close());
  const local={...f,admin,service,base:`http://127.0.0.1:${service.port}`};
  const input={vault:f.engine.data().vaults[0].name,name:'Notification test',website:'https://notification.invalid',username:'test',password:'private fictional write password',notes:'private fictional write notes'};
  assert.equal((await tool(local,'add_login',input)).body.result.isError,undefined);
  assert.equal((await tool(local,'update_login',{name:input.name,fields:{password:'different private fictional password'}})).body.result.isError,undefined);
  assert.equal((await tool(local,'delete_login',{name:input.name})).body.result.isError,undefined);
  assert.deepEqual(notifications.map((event:any)=>event.action),['add','edit','delete']);
  const audit=JSON.stringify(f.engine.data().activity);for(const secret of [input.password,input.notes,'different private fictional password','fictional delivery failure secret']){assert(!audit.includes(secret));assert(!JSON.stringify(notifications).includes(secret));}
  const writes=f.engine.data().activity.filter(entry=>['assistant.add','assistant.edit','assistant.delete'].includes(entry.action));assert.equal(writes.length,3);assert(writes.every(entry=>entry.agentName==='Test assistant'&&entry.agentClientName&&entry.itemName===input.name&&entry.at));
  assert.equal(f.engine.data().activity.filter(entry=>entry.action==='assistant.notification_failed').length,3);
});

test('pending MCP secret responses are withheld on revoke, permission change, vault removal, or lock',async t=>{
  for(const change of ['revoke','permission','vault','lock'] as const){
    const f=await fixture();f.engine.data().settings.notifyAssistant=true;const admin=randomToken();
    const service=await startLocalService(f.engine,{port:0,adminToken:admin,notify:async()=>{const agent=f.engine.data().assistantTokens[0];if(change==='revoke')await f.engine.revokeToken(agent.id);else if(change==='permission')await f.engine.updateAgent(agent.id,{permission:'read'});else if(change==='vault')await f.engine.updateAgent(agent.id,{vaultIds:[]});else f.engine.lock();}});t.after(()=>service.close());
    const response=await tool({...f,admin,service,base:`http://127.0.0.1:${service.port}`},'get_login',{name:f.login.title});assert.equal(response.body.result.isError,true);assert(!JSON.stringify(response.body).includes(f.login.password!));
  }
});

test('MCP quotas are ten secret reads and thirty writes per agent, independent of other agents',async t=>{
  const f=await localFixture();t.after(()=>f.service.close());
  for(let n=0;n<10;n++)assert.equal((await tool(f,'get_login',{name:f.login.title})).body.result.isError,undefined);
  assert.match((await tool(f,'get_login',{name:f.login.title})).body.result.content[0].text,/ten login requests per hour per agent/);
  for(let n=0;n<30;n++)assert.equal((await tool(f,'add_login',{vault:f.login.vaultId,name:'quota '+n,website:'https://quota.invalid',username:'test'})).body.result.isError,undefined);
  assert.match((await tool(f,'add_login',{vault:f.login.vaultId,name:'over quota',website:'https://quota.invalid',username:'test'})).body.result.content[0].text,/thirty writes per hour per agent/);
  const other=await f.engine.createToken('Independent quota');f.token=other.token;
  assert.equal((await tool(f,'get_login',{name:f.login.title})).body.result.isError,undefined);
  assert.equal((await tool(f,'add_login',{vault:f.login.vaultId,name:'second agent quota',website:'https://quota.invalid',username:'test'})).body.result.isError,undefined);
  assert(f.engine.data().activity.some(entry=>entry.outcome==='rate_limited'&&entry.action==='assistant.get'));
  assert(f.engine.data().activity.some(entry=>entry.outcome==='rate_limited'&&entry.action==='assistant.add'));
});

test('MCP bank and X Money guards block reads, edits, deletes, and forbidden additions',async t=>{
  const f=await localFixture();t.after(()=>f.service.close());
  for(const item of [await f.engine.upsertItem({...newItem('bankAccount','Savings account',f.login.vaultId),password:'fictional bank secret'}),await f.engine.upsertItem({...newItem('login','X Money payment',f.login.vaultId),urls:['https://x.money'],password:'fictional money secret'})]){
    for(const [name,args] of [['get_login',{name:item.title}],['update_login',{name:item.title,fields:{notes:'blocked'}}],['delete_login',{name:item.title}]] as const){const result=await tool(f,name,args);assert.equal(result.body.result.isError,true);assert(!JSON.stringify(result.body).includes(item.password!));}
    assert.equal(f.engine.data().items.find(value=>value.id===item.id)?.deletedAt,undefined);
  }
  assert.equal((await tool(f,'add_login',{vault:f.login.vaultId,name:'X Money',website:'https://example.invalid',username:'test'})).body.result.isError,true);
  assert.equal((await tool(f,'update_login',{name:f.login.title,fields:{website:'https://money.x.com'}})).body.result.isError,true);
});

test('a pending login reply is withheld after the owner changes its secret during notification delivery',async t=>{
  const f=await fixture();f.engine.data().settings.notifyAssistant=true;const admin=randomToken();
  const service=await startLocalService(f.engine,{port:0,adminToken:admin,notify:async()=>{const current=f.engine.data().items.find(item=>item.id===f.login.id)!;await f.engine.upsertItem({...current,password:'new fictional owner password'});}});t.after(()=>service.close());
  const response=await tool({...f,admin,service,base:`http://127.0.0.1:${service.port}`},'get_login',{name:f.login.title});assert.equal(response.body.result.isError,true);assert(!JSON.stringify(response.body).includes(f.login.password!));assert(!JSON.stringify(response.body).includes('new fictional owner password'));
});

test('locked and revoked MCP tool attempts are audited without requesting unlock secrets',async t=>{
  const f=await fixture();const key=f.engine.exportSessionKey();const admin=randomToken();const service=await startLocalService(f.engine,{port:0,adminToken:admin});t.after(()=>service.close());
  const local={...f,admin,service,base:`http://127.0.0.1:${service.port}`};
  f.engine.lock();const locked=await tool(local,'get_login',{name:f.login.title});assert.equal(locked.response.status,423);assert.equal(locked.body.error,'Vault is locked');await f.engine.unlockWithKey(key);key.fill(0);
  assert(f.engine.data().activity.some(entry=>entry.action==='assistant.get'&&entry.outcome==='denied'&&entry.itemName===f.login.title&&entry.agentName==='Test assistant'));
  await f.engine.revokeToken(f.engine.data().assistantTokens[0].id);assert.equal((await tool(local,'delete_login',{name:f.login.title})).response.status,401);
  assert(f.engine.data().activity.some(entry=>entry.action==='assistant.delete'&&entry.outcome==='denied'&&entry.itemName===f.login.title&&entry.agentName==='Test assistant'));
});

test('MCP schema rejections are audited using only safe tool and item metadata',async t=>{
  const f=await localFixture();t.after(()=>f.service.close());
  const before=f.engine.data().activity.length;
  const response=await tool(f,'update_login',{name:f.login.title,fields:{permission:'full',password:'fictional rejected private password'}});
  assert.equal(response.body.result.isError,true);
  const entries=f.engine.data().activity.slice(before);assert(entries.some(entry=>entry.action==='assistant.edit'&&entry.itemName===f.login.title&&entry.outcome==='denied'&&entry.agentName==='Test assistant'));
  assert(!JSON.stringify(entries).includes('fictional rejected private password'));assert.equal(f.engine.data().items.find(item=>item.id===f.login.id)?.password,f.login.password);
});

test('a forbidden bank login with a duplicate title does not prevent reading the single allowed login',async t=>{
  const f=await localFixture();t.after(()=>f.service.close());
  await f.engine.upsertItem({...newItem('login',f.login.title,f.login.vaultId),urls:['https://bankofamerica.com'],password:'fictional blocked bank password'});
  const response=await tool(f,'get_login',{name:f.login.title});assert.equal(response.body.result.isError,undefined);assert.equal(JSON.parse(response.body.result.content[0].text).password,f.login.password);assert(!JSON.stringify(response.body).includes('fictional blocked bank password'));
});
