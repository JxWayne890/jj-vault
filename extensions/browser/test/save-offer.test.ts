import test from 'node:test';
import assert from 'node:assert/strict';
import {runInNewContext} from 'node:vm';
import {build} from 'esbuild';
import {chromium,type Page} from '@playwright/test';

const runtimeId='synthetic-extension';
const secret='Synthetic captured password 873625!';
const username='synthetic-owner@example.test';
const bundled=async(name:string)=>(await build({entryPoints:[`extensions/browser/src/${name}.ts`],bundle:true,format:'iife',target:'es2022',write:false})).outputFiles[0].text;
function fixture(code:string){
  let now=100000,url='https://example.test/login',active=true,opens=0;
  let messageHandler:(message:any,sender:any,respond:(reply:any)=>void)=>boolean|void;
  let navigationHandler:(tabId:number,change:{url?:string})=>void;
  const sent:{tabId:number;message:any}[]=[],timers:{fn:()=>void;delay:number}[]=[];
  const action:{openPopup?:(()=>Promise<void>);setBadgeText:(input:any)=>Promise<void>;setBadgeBackgroundColor:(input:any)=>Promise<void>}={setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{},openPopup:async()=>{opens++;}};
  const tabs={get:async(id:number)=>({id,url}),query:async()=>[{id:active?7:8,url}],sendMessage:async(tabId:number,message:any)=>{sent.push({tabId,message:structuredClone(message)});return {ok:true};},onRemoved:{addListener(){}},onUpdated:{addListener(handler:typeof navigationHandler){navigationHandler=handler;}}};
  const chrome={runtime:{id:runtimeId,onMessage:{addListener(handler:typeof messageHandler){messageHandler=handler;}}},action,tabs};
  class FixtureDate extends Date{static now(){return now;}}
  runInNewContext(code,{chrome,URL,Date:FixtureDate,setTimeout:(fn:()=>void,delay:number)=>{timers.push({fn,delay});return timers.length;},console});
  function sender(){return {id:runtimeId,frameId:0,url,tab:{id:7,url}};}
  async function dispatch(message:any,from:any=sender()){
    return new Promise<any>((resolve,reject)=>{let replied=false;const keep=messageHandler(structuredClone(message),from,value=>{replied=true;resolve(JSON.parse(JSON.stringify(value)));});if(!keep&&!replied)resolve(undefined);if(keep)setTimeout(()=>{if(!replied)reject(new Error('Synthetic extension response timed out'));},1000).unref();});
  }
  const candidate=()=>({url,title:'Synthetic login',username,password:secret,capturedAt:now});
  return {dispatch,candidate,sender,sent,timers,action,tabs,opens:()=>opens,clock:(value:number)=>{now=value;},navigate:(value:string)=>{url=value;navigationHandler(7,{url:value});},setUrl:(value:string)=>{url=value;},activate:(value:boolean)=>{active=value;}};
}

test('save offer background exposes metadata only and keeps secrets exclusive to popup review',async()=>{
  const f=fixture(await bundled('background'));
  assert.deepEqual(await f.dispatch({action:'capture',candidate:f.candidate()}),{ok:true,available:true,expiresAt:190000});
  const offer=await f.dispatch({action:'captureOffer'});assert.deepEqual(offer,{ok:true,available:true,expiresAt:190000});
  for(const value of [offer,...f.sent]){const text=JSON.stringify(value);assert.ok(!text.includes(secret));assert.ok(!text.includes(username));assert.ok(!text.includes('Synthetic login'));}
  assert.equal(await f.dispatch({action:'pendingCapture',tabId:7}),undefined,'Content scripts cannot read captured credentials');
  const popup=await f.dispatch({action:'pendingCapture',tabId:7},{id:runtimeId});assert.equal(popup.candidate.password===secret,true);assert.equal(f.opens(),0,'Capturing and metadata queries never open a popup');
  assert.deepEqual(await f.dispatch({action:'reviewCapture'}),{ok:true,available:true,opened:true});assert.equal(f.opens(),1);
  f.action.openPopup=undefined;assert.deepEqual(await f.dispatch({action:'reviewCapture'}),{ok:true,available:true,opened:false});
  f.action.openPopup=async()=>{throw new Error('Synthetic unsupported browser API');};assert.deepEqual(await f.dispatch({action:'reviewCapture'}),{ok:true,available:true,opened:false});
  await f.dispatch({action:'clearCapture',tabId:7},{id:runtimeId});assert.deepEqual(await f.dispatch({action:'captureOffer'}),{ok:true,available:false});assert.ok(f.sent.some(event=>event.message.action==='captureCleared'));
});
test('save offers follow same origin navigation, expire, dismiss, and clear on cross origin changes',async()=>{
  const code=await bundled('background');
  for(const end of ['expiry','dismiss','crossOrigin','http']as const){
    const f=fixture(code);await f.dispatch({action:'capture',candidate:f.candidate()});f.navigate('https://example.test/account');assert.equal((await f.dispatch({action:'captureOffer'})).available,true,'Same origin navigation retains a fresh capture');
    if(end==='expiry')f.clock(190001);if(end==='dismiss')await f.dispatch({action:'dismissCaptureOffer'});if(end==='crossOrigin')f.navigate('https://other.test/');if(end==='http')f.navigate('http://example.test/account');
    assert.equal((await f.dispatch({action:'pendingCapture',tabId:7},{id:runtimeId})).candidate,null);assert.ok(f.sent.some(event=>event.message.action==='captureCleared'));
  }
});
test('review requests reject wrong frames, extensions, changed documents, and inactive tabs',async()=>{
  const f=fixture(await bundled('background'));await f.dispatch({action:'capture',candidate:f.candidate()});
  for(const sender of [{...f.sender(),frameId:1},{...f.sender(),url:'https://other.test/'}])assert.deepEqual(await f.dispatch({action:'reviewCapture'},sender),{ok:false});
  assert.equal(await f.dispatch({action:'reviewCapture'},{...f.sender(),id:'untrusted-extension'}),undefined);f.activate(false);assert.equal((await f.dispatch({action:'reviewCapture'})).available,false);assert.equal(f.opens(),0);
  f.activate(true);f.setUrl('https://other.test/');assert.equal((await f.dispatch({action:'pendingCapture',tabId:7},{id:runtimeId})).candidate,null);assert.equal(f.opens(),0);
});
test('generic browser prompt requires trusted clicks, reveals no fields and restores after navigation',async()=>{
  const content=await bundled('content');
  // Only controlled routed pages and a mocked API are used. No extension is
  // installed and no regular Chrome profile or extension setting is accessed.
  const browser=await chromium.launch({channel:process.env.JJ_VAULT_TEST_BROWSER_CHANNEL || 'chrome',headless:true});const context=await browser.newContext();
  const fixturePage='<html><head><title>Synthetic login</title></head><body><form onsubmit="event.preventDefault()"><input autocomplete="username" id="user"><input type="password" id="password" autocomplete="current-password"><button>Sign in</button></form><iframe src="https://example.test/frame"></iframe></body></html>';
  try{
    await context.route('https://**/*',route=>route.fulfill({contentType:'text/html',body:route.request().url().endsWith('/frame')?'<html><body>Frame fixture</body></html>':fixturePage}));
    let pending:{expiresAt:number}|null=null;let opens=0,captures=0,reviewCalls=0,fallback=false;let page!:Page;
    await context.exposeBinding('__fixtureMessage',async(_source,message:any)=>{
      if(message.action==='capture'){captures++;pending={expiresAt:Date.now()+90000};return {ok:true,available:true,...pending};}
      if(message.action==='captureOffer')return {ok:true,available:!!pending,...pending};
      if(message.action==='reviewCapture'){reviewCalls++;if(!fallback)opens++;return {ok:true,available:!!pending,opened:!fallback};}
      if(message.action==='dismissCaptureOffer'){pending=null;return {ok:true,available:false};}
      throw new Error('Unexpected synthetic API action');
    });
    await context.addInitScript(()=>{
      (window as any).__contentHandler=undefined;
      (window as any).chrome={runtime:{id:'synthetic-extension',onMessage:{addListener(handler:unknown){(window as any).__contentHandler=handler;}},sendMessage(message:unknown){return (window as any).__fixtureMessage(message);}}};
    });
    page=await context.newPage();await page.goto('https://example.test/login');await page.addScriptTag({content});
    const offer=page.locator('[data-jjvault-save-offer]');assert.equal(await offer.count(),0);
    await page.locator('#user').fill(username);await page.locator('#password').fill(secret);await page.locator('form').dispatchEvent('submit');assert.equal(captures,0);assert.equal(await offer.count(),0);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByRole('region',{name:'JJ Vault save offer'}).waitFor();assert.equal(captures,1);assert.equal(opens,0);
    const markup=await offer.evaluate(host=>({outer:host.outerHTML,shadow:host.shadowRoot!.innerHTML}));for(const value of Object.values(markup)){assert.ok(!value.includes(secret));assert.ok(!value.includes(username));assert.ok(!value.includes('Synthetic login'));}
    await page.getByRole('button',{name:'Review in JJ Vault',exact:true}).evaluate(element=>(element as HTMLButtonElement).click());assert.equal(reviewCalls,0,'Synthetic clicks cannot request popup review');
    await page.getByRole('button',{name:'Review in JJ Vault',exact:true}).click();await assertEventually(()=>opens===1);assert.equal(reviewCalls,1);
    fallback=true;await page.getByRole('button',{name:'Review in JJ Vault',exact:true}).click();await page.getByText('Click the JJ Vault icon in the browser toolbar to review, then choose Confirm save.',{exact:true}).waitFor();assert.equal(opens,1);
    await page.goto('https://example.test/account');await page.addScriptTag({content});await page.getByRole('region',{name:'JJ Vault save offer'}).waitFor();
    const frame=page.frames().find(candidate=>candidate.parentFrame());assert.ok(frame);await frame.addScriptTag({content});assert.equal(await frame.locator('[data-jjvault-save-offer]').count(),0,'Frames never display a save offer');
    await page.getByRole('button',{name:'Dismiss',exact:true}).evaluate(element=>(element as HTMLButtonElement).click());assert.equal(await offer.count(),1,'Synthetic dismissal is ignored');
    await page.getByRole('button',{name:'Dismiss',exact:true}).click();await assertEventually(()=>pending===null);assert.equal(await offer.count(),0);
    pending={expiresAt:Date.now()+2000};await page.reload();await page.addScriptTag({content});await page.getByRole('region',{name:'JJ Vault save offer'}).waitFor();await offer.waitFor({state:'detached'});
    pending={expiresAt:Date.now()+90000};await page.reload();await page.addScriptTag({content});await page.getByRole('region',{name:'JJ Vault save offer'}).waitFor();await page.evaluate(()=>{(window as any).__contentHandler({action:'captureCleared'},{id:'synthetic-extension'},()=>{});});assert.equal(await offer.count(),0,'Owner save or discard removes the page prompt');
  }finally{await context.close();await browser.close();}
});
async function assertEventually(check:()=>boolean){const deadline=Date.now()+3000;while(Date.now()<deadline){if(check())return;await new Promise(done=>setTimeout(done,20));}assert.fail('Synthetic browser action did not finish');}
