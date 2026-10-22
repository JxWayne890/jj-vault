interface PhoneViewContext {
  invoke:(action:string,payload?:unknown)=>Promise<any>;
  refresh:()=>Promise<void>;
  toast:(message:string)=>void;
  showModal:(content:string,onClose?:()=>void)=>void;
  closeModal:()=>void;
}
const escape=(value:unknown)=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
export function phoneSettingsCard(status:any={}):string {
  const connected=!!status.paired&&!!status.running;
  const description=connected?'Your iPhone is paired with this Mac. Changes sync while both devices are available on your local network.':status.enabled?'Local sync is enabled. Pair your iPhone to finish connecting it.':'Connect your iPhone to this Mac with a private pairing code.';
  return `<div class="card cardpad" id="phoneSyncCard"><div class="row between"><div class="cardtitle">iPhone connection</div><span class="pill">${connected?'PAIRED':status.enabled?'READY TO PAIR':'NOT CONNECTED'}</span></div><p class="muted">${escape(description)} Your vault stays encrypted in transit and on disk.</p>${status.url?`<p class="muted">Connection address: <code>${escape(status.url)}</code></p>`:''}${status.lastSyncAt?`<p class="muted">Last sync: ${escape(new Date(status.lastSyncAt).toLocaleString())}</p>`:''}${status.lastError?`<p class="error" role="status">${escape(status.lastError)}</p>`:''}<div class="row"><button id="pairPhone" class="primary">Pair iPhone</button><button id="syncPhone" ${status.running?'':'disabled'}>Sync iPhone now</button><button id="disconnectPhone" class="danger" ${status.enabled?'':'disabled'}>Disconnect iPhone</button></div><p class="muted">Open JJ Vault on your iPhone and scan the pairing code. Enter your master password and Secret Key privately on the phone for its first unlock. Face ID can unlock it afterward.</p></div>`;
}
export function bindPhoneSettings(context:PhoneViewContext):void {
  const action=async(button:HTMLButtonElement,fn:()=>Promise<void>)=>{
    button.disabled=true;
    try{await fn();}catch(error){context.toast(error instanceof Error?error.message:'Unable to connect your iPhone');}
    finally{if(button.isConnected)button.disabled=false;}
  };
  const pair=document.getElementById('pairPhone')as HTMLButtonElement|null;
  pair?.addEventListener('click',()=>void action(pair,async()=>{
    const result=await context.invoke('startPhonePairing');
    if(typeof result.qrDataUrl!=='string'||!result.qrDataUrl.startsWith('data:image/png;base64,')||!Number.isFinite(Date.parse(result.expiresAt)))throw new Error('Unable to display the phone pairing code');
    let timer:ReturnType<typeof setInterval>|undefined;
    let stopped=false;
    const cleanup=()=>{if(stopped)return;stopped=true;if(timer)clearInterval(timer);void context.invoke('cancelPhonePairing').catch(()=>{});};
    context.showModal(`<h2>Pair your iPhone</h2><p class="muted">Open JJ Vault on your iPhone, choose Connect to Mac, and scan this code. Keep both devices on the same local network.</p><div class="phone-pair-code"><img id="phonePairQR" src="${escape(result.qrDataUrl)}" alt="JJ Vault iPhone pairing code" width="560" height="560"></div><p class="muted" id="phonePairCountdown" role="status"></p><p class="muted">This code pairs one phone and expires in two minutes. It contains no master password or Secret Key.</p><div class="modalbuttons"><button id="cancel">Cancel</button><button id="phonePairDone" class="primary">Done</button></div>`,cleanup);
    if(!document.getElementById('phonePairQR')){cleanup();return;}
    document.getElementById('phonePairDone')?.addEventListener('click',()=>{context.closeModal();void context.refresh();});
    const tick=()=>{
      if(stopped)return;
      const remaining=Math.max(0,Math.ceil((Date.parse(result.expiresAt)-Date.now())/1000));
      const countdown=document.getElementById('phonePairCountdown');
      if(countdown)countdown.textContent=remaining?`Code expires in ${remaining} seconds.`:'This code expired. Close this window and pair again.';
      if(!remaining){document.getElementById('phonePairQR')?.remove();cleanup();}
    };
    tick();if(!stopped)timer=setInterval(tick,1000);
  }));
  const sync=document.getElementById('syncPhone')as HTMLButtonElement|null;
  sync?.addEventListener('click',()=>void action(sync,async()=>{await context.invoke('syncPhone');await context.refresh();context.toast('Encrypted iPhone sync completed.');}));
  const disconnect=document.getElementById('disconnectPhone')as HTMLButtonElement|null;
  disconnect?.addEventListener('click',()=>void action(disconnect,async()=>{await context.invoke('disablePhoneSync');await context.refresh();context.toast('iPhone disconnected. Pair again to reconnect it.');}));
}
