import { extensionAPI, type BrowserItem, type LoginCandidate } from './types.ts';
import { safePageUrl, sameDocument } from './matching.ts';
import { cleanError } from './errors.ts';

const api = extensionAPI();
declare const JJVAULT_NATIVE_HOST: string;
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
let tabId: number | undefined;
let activeUrl = '';
let items: BrowserItem[] = [];
let candidate: LoginCandidate | null = null;
let busy = false;

function status(message: string, kind: 'error' | 'success' | 'neutral' = 'neutral') {
  $('status').textContent = message;
  $('status').dataset.kind = kind;
}

async function native(action: string, rest: Record<string, unknown> = {}) {
  const reply = await api.runtime.sendNativeMessage(JJVAULT_NATIVE_HOST, { action, url: activeUrl, ...rest });
  if (!reply?.ok) throw new Error(reply?.error || 'JJ Vault did not respond.');
  return reply.result;
}

async function checkPage() {
  if (tabId === undefined) throw new Error('Open a website first.');
  const tab = await api.tabs.get(tabId);
  if (!tab.url || !sameDocument(activeUrl, tab.url)) throw new Error('The page changed. Reopen JJ Vault to continue.');
}

const labels: Record<string, string> = { login: 'Login', password: 'Password', identity: 'Identity', creditCard: 'Card' };
const symbols: Record<string, string> = { login: '↗', password: '✳', identity: '◎', creditCard: '▰' };

function render() {
  const query = $<HTMLInputElement>('search').value.toLowerCase();
  const type = $<HTMLSelectElement>('typeFilter').value;
  const matches = items.filter(item => (!type || item.type === type) && `${item.title} ${item.username ?? ''}`.toLowerCase().includes(query));
  const list = $('items'); list.replaceChildren();
  $('count').textContent = `${matches.length} ${matches.length === 1 ? 'item' : 'items'}`;
  if (!matches.length) {
    const empty = document.createElement('div'); empty.className = 'empty';
    empty.textContent = query ? 'No items match your search.' : 'No matching items. Check browser access in JJ Vault.';
    list.append(empty); return;
  }
  for (const item of matches) {
    const button = document.createElement('button'); button.className = 'item'; button.type = 'button';
    button.setAttribute('aria-label', `Fill ${item.title}, ${labels[item.type] ?? item.type}`);
    const icon = document.createElement('span'); icon.className = 'itemIcon'; icon.textContent = symbols[item.type] ?? '◇';
    const info = document.createElement('span'); info.className = 'itemInfo';
    const title = document.createElement('strong'); title.textContent = item.title;
    const detail = document.createElement('span'); detail.textContent = item.username || labels[item.type] || item.type;
    info.append(title, detail);
    const fill = document.createElement('span'); fill.className = 'fillLabel'; fill.textContent = 'Fill';
    button.append(icon, info, fill);
    button.addEventListener('click', () => void fillItem(item.id));
    list.append(button);
  }
}

async function fillItem(id: string) {
  if (busy) return; busy = true;
  let secret: BrowserItem | undefined;
  try {
    await checkPage(); status('Requesting this item from JJ Vault…');
    secret = await native('get', { id });
    await checkPage();
    const reply = await api.tabs.sendMessage(tabId!, { action: 'fill', expectedUrl: activeUrl, item: secret }, { frameId: 0 });
    if (!reply?.ok) throw new Error(reply?.error || 'Reload this page, then try filling again.');
    status(reply.filled ? `Filled ${reply.filled} ${reply.filled === 1 ? 'field' : 'fields'}. You can review and submit.` : 'No compatible visible fields were found.', reply.filled ? 'success' : 'neutral');
  } catch (error) { status(cleanError(error), 'error'); }
  finally {
    if (secret) { secret.password = ''; secret.username = ''; secret.totp = ''; secret.fields?.forEach(field => { field.value = ''; }); }
    secret = undefined; busy = false;
  }
}

function showCandidate() {
  $('capture').hidden = !candidate;
  if (!candidate) return;
  $<HTMLInputElement>('saveTitle').value = candidate.title || new URL(candidate.url).hostname;
  $('saveUser').textContent = candidate.username || 'No username';
  const select = $<HTMLSelectElement>('saveTarget'); select.replaceChildren();
  const create = document.createElement('option'); create.value = ''; create.textContent = 'Save as a new login'; select.append(create);
  for (const item of items.filter(item => item.type === 'login')) {
    const option = document.createElement('option'); option.value = item.id; option.textContent = `Update ${item.title}${item.username ? ` (${item.username})` : ''}`; select.append(option);
  }
}

async function saveCandidate(event: SubmitEvent) {
  event.preventDefault();
  if (!candidate || busy) return; busy = true;
  try {
    await checkPage();
    if (Date.now() - candidate.capturedAt > 90_000) throw new Error('The save offer expired. Submit the login again to capture it.');
    const title = $<HTMLInputElement>('saveTitle').value.trim();
    if (!title) throw new Error('Give this login a name.');
    const id = $<HTMLSelectElement>('saveTarget').value;
    // A password only change form supplies no username. Keep the selected login's reviewed identity.
    const username = candidate.username || (id ? items.find(item => item.id === id && item.type === 'login')?.username : '') || '';
    await native('save', { item: { ...(id ? { id } : {}), type: 'login', title, username, password: candidate.password, urls: [candidate.url] } });
    await clearCandidate();
    status(id ? 'Password updated in JJ Vault.' : 'Login saved in JJ Vault.', 'success');
    items = await native('list'); render();
  } catch (error) { status(cleanError(error), 'error'); }
  finally { busy = false; }
}

async function clearCandidate() {
  if (candidate) { candidate.password = ''; candidate.username = ''; }
  candidate = null; $('capture').hidden = true;
  if (tabId !== undefined) await api.runtime.sendMessage({ action: 'clearCapture', tabId });
}

async function load() {
  try {
    $('connection').textContent = 'Connecting';
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id === undefined || !safePageUrl(tab.url)) throw new Error('Open an HTTPS website to use autofill.');
    tabId = tab.id; activeUrl = tab.url;
    $('website').textContent = new URL(activeUrl).hostname;
    items = await native('list');
    if (!Array.isArray(items)) throw new Error('The vault returned an invalid response.');
    await checkPage();
    $('connection').textContent = 'Connected'; $('connection').dataset.connected = 'true';
    status('Select an item to fill this website.'); render();
    const pending = await api.runtime.sendMessage({ action: 'pendingCapture', tabId });
    candidate = pending?.candidate ?? null; showCandidate();
  } catch (error) {
    $('connection').textContent = 'Unavailable'; $('connection').dataset.connected = 'false';
    status(cleanError(error), 'error');
    $('items').replaceChildren();
  }
}

$('search').addEventListener('input', render);
$('typeFilter').addEventListener('change', render);
$('refresh').addEventListener('click', () => void load());
$('saveForm').addEventListener('submit', event => void saveCandidate(event as SubmitEvent));
$('dismiss').addEventListener('click', () => void clearCandidate());
$('extensionId').textContent = api.runtime.id;
window.addEventListener('unload', () => { if (candidate) { candidate.password = ''; candidate.username = ''; } items = []; });
void load();
