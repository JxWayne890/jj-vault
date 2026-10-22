interface AgentViewContext {
  state:any;
  invoke:(action:string,payload?:unknown)=>Promise<any>;
  refresh:()=>Promise<void>;
  toast:(message:string)=>void;
  showModal:(content:string)=>void;
  closeModal:()=>void;
}
const permissions:Record<string,string>={read:'Read',read_add:'Read + add',read_add_edit:'Read + add + edit',full:'Full (includes delete)'};
const escape=(value:unknown)=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const input=(id:string)=>(document.getElementById(id)as HTMLInputElement).value;

export function renderAgents(context:AgentViewContext):void {
  const {state}=context;
  const active=state.tokens.filter((agent:any)=>!agent.revokedAt);
  const vaultLabel=(id:string)=>state.vaults.find((vault:any)=>vault.id===id)?.name||'Hidden vault';
  document.getElementById('workspace')!.innerHTML=`<div class="detail agents-detail">
    <div class="eyebrow">YOUR ASSISTANTS</div>
    <div class="row between"><div><h1>Agents</h1><p class="subtitle">Give each agent its own access, and change it whenever you need.</p></div><button id="addAgent" class="primary">Add agent</button></div>
    <div class="agents-summary"><span><b>${active.length}</b> active agents</span><span>10 login reads per hour per agent</span><span>30 writes per hour per agent</span></div>
    <div class="hint">New agents start with Full access. Choose their vaults before creating them. Bank and X Money items are always blocked. Deletes move items to Recently Deleted, with at least 30 days to restore.</div>
    <div class="card cardpad"><div class="cardtitle">Vault availability</div><p class="muted">These switches can pause access to a vault for every agent. Each agent also has its own vault selection below.</p><div class="agent-vault-list">${state.vaults.map((vault:any)=>`<label class="check"><input type="checkbox" data-agent-vault="${escape(vault.id)}" ${vault.allowAssistant?'checked':''}>Enable agents for ${escape(vault.name)}</label>`).join('')}</div></div>
    <div class="card cardpad"><div class="cardtitle">Write notifications</div><p class="muted">Every add, edit, and delete sends a notification to this Mac.${state.phonePush?.configured&&state.phonePush?.enabled?' iPhone push is configured.':' iPhone push is not configured. Set up the existing iPhone app and Apple push credentials to receive phone alerts.'} No passwords or item contents appear in notifications.</p><button id="refreshNotificationStatus">Refresh status</button></div>
    <div id="agentCards">${state.tokens.length?state.tokens.map((agent:any)=>`<article class="card cardpad agent-card" data-testid="agent-${escape(agent.clientName)}">
      <div class="row between"><div><h2>${escape(agent.name)}</h2><code>${escape(agent.clientName)}</code></div><span class="pill">${agent.revokedAt?'REVOKED':escape(permissions[agent.permission]||'Read')}</span></div>
      <p class="muted">Vaults: ${agent.vaultIds.length?agent.vaultIds.map((id:string)=>escape(vaultLabel(id))+(state.vaults.find((v:any)=>v.id===id)?.allowAssistant===false?' (paused)':'')).join(', '):'None selected'}</p>
      <p class="muted">This hour: ${agent.readCount||0} of 10 login reads. ${agent.writeCount||0} of 30 writes.</p>
      <div class="row"><button data-edit-agent="${escape(agent.id)}" ${agent.revokedAt?'disabled':''}>Edit permissions</button><button class="danger" data-revoke-agent="${escape(agent.id)}" ${agent.revokedAt?'disabled':''}>Revoke</button></div>
    </article>`).join(''):'<div class="card cardpad"><p>No agents yet. Add one to connect it to JJ Vault.</p></div>'}</div>
  </div>`;
  document.getElementById('addAgent')!.addEventListener('click',()=>editAgent(context));
  document.querySelectorAll<HTMLElement>('[data-edit-agent]').forEach(element=>element.addEventListener('click',()=>editAgent(context,state.tokens.find((agent:any)=>agent.id===element.dataset.editAgent))));
  document.querySelectorAll<HTMLButtonElement>('[data-revoke-agent]').forEach(element=>element.addEventListener('click',()=>void action(context,async()=>{
    element.disabled=true;
    await context.invoke('revokeToken',{id:element.dataset.revokeAgent});
    await context.refresh();context.toast('Agent revoked. Its token can no longer access JJ Vault.');
  })));
  document.querySelectorAll<HTMLInputElement>('[data-agent-vault]').forEach(element=>element.addEventListener('change',()=>void action(context,async()=>{
    await context.invoke('updateVault',{id:element.dataset.agentVault,allowAssistant:element.checked});await context.refresh();
  })));
  document.getElementById('refreshNotificationStatus')!.addEventListener('click',()=>void action(context,async()=>{await context.invoke('notificationStatus');await context.refresh();}));
}

async function action(context:AgentViewContext,fn:()=>Promise<void>):Promise<void>{try{await fn();}catch(error){context.toast(error instanceof Error?error.message:'Unable to update agent');await context.refresh();}}

function editAgent(context:AgentViewContext,agent?:any):void {
  const {state}=context;
  const selected=agent?.vaultIds||state.vaults.filter((vault:any)=>vault.allowAssistant).map((vault:any)=>vault.id);
  context.showModal(`<h2>${agent?'Edit agent':'Add agent'}</h2><form id="agentForm">
    <div class="grid2"><div class="formfield"><label for="agentName">Agent name</label><input id="agentName" value="${escape(agent?.name)}" maxlength="128" placeholder="Grillin" required></div>
    <div class="formfield"><label for="agentClientName">Client name</label><input id="agentClientName" value="${escape(agent?.clientName)}" maxlength="64" placeholder="grillin" ${agent?'readonly':''} required><small class="muted">A stable name used by this agent’s commands.</small></div></div>
    <div class="formfield"><label for="agentPermission">Permission</label><select id="agentPermission">${Object.entries(permissions).map(([id,label])=>`<option value="${id}" ${(agent?.permission||'full')===id?'selected':''}>${label}</option>`).join('')}</select></div>
    <fieldset class="agent-vault-picker"><legend>Allowed vaults</legend>${state.vaults.map((vault:any)=>`<label class="check"><input type="checkbox" name="agentVault" value="${escape(vault.id)}" ${selected.includes(vault.id)?'checked':''}>${escape(vault.name)}${vault.allowAssistant?'':' (paused)'}</label>`).join('')}</fieldset>
    <p class="muted">Access covers nonbank items in the selected available vaults. Login writes follow this permission level. Only you can manage agent access. The client name stays the same when you rename the agent.</p>
    <div id="agentFormError" class="error" role="alert"></div><div class="modalbuttons"><button id="cancel" type="button">Cancel</button><button id="saveAgent" class="primary" type="submit">${agent?'Save changes':'Create agent'}</button></div>
  </form>`);
  if(!agent){
    const client=document.getElementById('agentClientName')as HTMLInputElement;
    let manual=false;client.addEventListener('input',()=>{manual=true;});
    document.getElementById('agentName')!.addEventListener('input',()=>{if(!manual)client.value=input('agentName').toLowerCase().replace(/[^a-z0-9_-]+/g,'_').replace(/^[^a-z]+/,'').slice(0,64);});
  }
  document.getElementById('agentForm')!.addEventListener('submit',event=>{
    event.preventDefault();const submit=document.getElementById('saveAgent')as HTMLButtonElement;submit.disabled=true;
    void(async()=>{
      try{
        const hidden=(agent?.vaultIds||[]).filter((id:string)=>!state.vaults.some((vault:any)=>vault.id===id));
        const vaultIds=[...hidden,...Array.from(document.querySelectorAll<HTMLInputElement>('input[name="agentVault"]:checked')).map(element=>element.value)];
        const changes={name:input('agentName'),permission:input('agentPermission'),vaultIds};
        if(agent){await context.invoke('updateAgent',{id:agent.id,changes});context.closeModal();await context.refresh();context.toast('Agent updated. Changes take effect immediately.');}
        else{
          const result=await context.invoke('createAgent',{...changes,clientName:input('agentClientName')});
          context.closeModal();await context.refresh();
          context.showModal(`<h2>Agent ready on this Mac</h2><p>The token is saved privately for <strong>${escape(result.clientName)}</strong>. This agent can use its own client name with the JJ Vault helper.</p><p class="hint secretkey" data-testid="agent-helper-command">${escape(result.helperCommand)}</p><p class="muted">For a direct MCP connection, you can copy its API token now. The token is never shown in this window.</p><div class="modalbuttons"><button id="copyAgentToken">Copy API token</button><button id="cancel" class="primary">Done</button></div>`);
          document.getElementById('copyAgentToken')!.addEventListener('click',()=>void action(context,async()=>{await context.invoke('copyToken',{token:result.token});context.toast('Token copied. Clipboard clears in 90 seconds.');}));
        }
      }catch(error){const field=document.getElementById('agentFormError');if(field)field.textContent=error instanceof Error?error.message:'Unable to save agent';else context.toast('Unable to save agent');}
      finally{submit.disabled=false;}
    })();
  });
}
