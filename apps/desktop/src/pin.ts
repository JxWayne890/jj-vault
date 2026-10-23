interface PinViewContext {
  state:()=>any;
  invoke:(action:string,payload?:unknown)=>Promise<any>;
  refresh:()=>Promise<void>;
  toast:(message:string)=>void;
  showModal:(content:string)=>void;
  closeModal:()=>void;
}
function input(id:string,label:string,pin=true):string {
  return `<div class="formfield"><label for="${id}">${label}</label><input id="${id}" type="password" ${pin?'inputmode="numeric" pattern="[0-9]{4,6}" minlength="4" maxlength="6"':''} autocomplete="off" required></div>`;
}
function value(id:string):string{return (document.getElementById(id)as HTMLInputElement|null)?.value||'';}
function clear(form:HTMLFormElement):void{form.querySelectorAll<HTMLInputElement>('input').forEach(input=>input.value='');}
export function pinSettingsRow(state:any):string {
  return `<div class="securityrow"><span><strong>PIN unlock</strong><small>${state.pinEnabled?'Use your chosen 4 to 6 digit PIN to unlock this Mac. Keep your master password and Emergency Kit for recovery.':state.pinAvailable?'Choose a 4 to 6 digit PIN for everyday unlocks on this Mac.':'PIN unlock needs protected device storage. Use your master password to unlock this Mac.'}</small></span>${state.pinEnabled?'<button id="changePin">Change PIN</button><button id="removePin">Remove PIN</button>':`<button id="enablePin" ${state.pinAvailable?'':'disabled'}>Enable PIN</button>`}</div>`;
}
export function showPinDialog(context:PinViewContext,prompt=false,recover=false):void {
  const changing=!!context.state().pinEnabled;
  if(context.state().locked||(!changing&&!context.state().pinAvailable))return;
  if(changing&&!context.state().pinAvailable)recover=true;
  context.showModal(`<h2>${changing?'Change your PIN':'Choose a PIN'}</h2><p class="muted">Choose 4 to 6 digits to unlock JJ Vault on this Mac. Your master password and Secret Key still protect your vault and let you recover access or set up another device.</p><form id="pinform" novalidate>${changing?input(recover?'pinMaster':'currentPin',recover?'Master password':'Current PIN',!recover):''}${changing&&recover&&!context.state().hasRememberedSecretKey?input('pinSecret','Secret Key',false):''}${input('newPin',changing?'New PIN':'PIN')}${input('confirmPin','Confirm PIN')}<div id="pinerror" class="error" role="alert"></div><div class="modalbuttons"><button id="cancel" type="button">${prompt?'Not now':'Cancel'}</button><button id="savePin" class="primary" type="submit">${changing?'Save PIN':'Enable PIN'}</button></div>${changing&&context.state().pinAvailable?`<p><button id="pinRecovery" class="linkbutton" type="button">${recover?'Use current PIN instead':'Forgot your PIN? Use master password'}</button></p>`:''}</form>`);
  document.getElementById('pinRecovery')?.addEventListener('click',()=>showPinDialog(context,prompt,!recover));
  const form=document.getElementById('pinform')as HTMLFormElement|null;
  form?.addEventListener('submit',event=>{event.preventDefault();void(async()=>{
    const submit=document.getElementById('savePin')as HTMLButtonElement;
    const error=document.getElementById('pinerror')!;
    const pin=value('newPin'),confirmPin=value('confirmPin'),currentPin=value('currentPin'),password=value('pinMaster'),secretKey=value('pinSecret');
    clear(form);error.textContent='';submit.disabled=true;
    try{
      if(!/^[0-9]{4,6}$/.test(pin))throw new Error('Choose a PIN with 4 to 6 digits.');
      if(pin!==confirmPin)throw new Error('The PINs do not match.');
      if(changing&&!recover&&!/^[0-9]{4,6}$/.test(currentPin))throw new Error('Enter your current PIN with 4 to 6 digits.');
      if(changing&&recover&&!password)throw new Error('Enter your master password.');
      await context.invoke('setPin',{pin,confirmPin,...(changing?(recover?{password,...(secretKey?{secretKey}:{})}:{currentPin}):{})});
      if(form.isConnected)context.closeModal();
      await context.refresh();context.toast(changing?'PIN updated.':'PIN unlock enabled on this Mac.');
    }catch(reason){if(form.isConnected){error.textContent=reason instanceof Error?reason.message:'Unable to save your PIN';form.querySelector<HTMLInputElement>('input')?.focus();}}
    finally{if(submit.isConnected)submit.disabled=false;}
  })();});
}
function removePinDialog(context:PinViewContext):void {
  context.showModal(`<h2>Remove PIN unlock</h2><p class="muted">Enter your master password to remove the PIN from this Mac. You will use your master password for future unlocks.</p><form id="removePinForm">${input('removePinPassword','Master password',false)}${!context.state().hasRememberedSecretKey?input('pinSecret','Secret Key',false):''}<div id="pinerror" class="error" role="alert"></div><div class="modalbuttons"><button id="cancel" type="button">Cancel</button><button id="confirmRemovePin" class="danger" type="submit">Remove PIN</button></div></form>`);
  const form=document.getElementById('removePinForm')as HTMLFormElement|null;
  form?.addEventListener('submit',event=>{event.preventDefault();void(async()=>{
    const submit=document.getElementById('confirmRemovePin')as HTMLButtonElement;const error=document.getElementById('pinerror')!;
    const password=value('removePinPassword'),secretKey=value('pinSecret');clear(form);submit.disabled=true;
    try{await context.invoke('removePin',{password,...(secretKey?{secretKey}:{})});if(form.isConnected)context.closeModal();await context.refresh();context.toast('PIN unlock removed.');}
    catch(reason){if(form.isConnected)error.textContent=reason instanceof Error?reason.message:'Unable to remove your PIN';}
    finally{if(submit.isConnected)submit.disabled=false;}
  })();});
}
export function bindPinSettings(context:PinViewContext):void {
  document.getElementById('enablePin')?.addEventListener('click',()=>showPinDialog(context));
  document.getElementById('changePin')?.addEventListener('click',()=>showPinDialog(context));
  document.getElementById('removePin')?.addEventListener('click',()=>removePinDialog(context));
}
