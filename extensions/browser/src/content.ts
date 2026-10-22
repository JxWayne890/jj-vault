import { extensionAPI, type BrowserItem } from './types.ts';
import { fieldValue, type FieldDescriptor } from './fields.ts';
import { matchesUrl, safePageUrl, sameDocument } from './matching.ts';

const api = extensionAPI();
const topFrame = window.top === window.self;
const MAX_CAPTURE_AGE = 90_000;

function visible(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): boolean {
  if (element.disabled || ('readOnly' in element && element.readOnly) || element.getAttribute('aria-hidden') === 'true') return false;
  if (element instanceof HTMLInputElement && ['hidden', 'submit', 'button', 'checkbox', 'radio', 'file'].includes(element.type)) return false;
  const style = getComputedStyle(element);
  return element.getClientRects().length > 0 && style.visibility !== 'hidden' && style.display !== 'none' && Number(style.opacity) !== 0;
}

function descriptor(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): FieldDescriptor {
  return { autocomplete: element.autocomplete, type: element instanceof HTMLInputElement ? element.type : element.tagName.toLowerCase(), name: element.name, id: element.id, label: Array.from(element.labels ?? []).map(label => label.textContent ?? '').join(' ') };
}

function safeForm(form: HTMLFormElement | null): boolean {
  if (!form) return true;
  try { return new URL(form.action || location.href, location.href).origin === location.origin; } catch { return false; }
}

function insert(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string): boolean {
  if (element instanceof HTMLSelectElement) {
    const option = Array.from(element.options).find(option => option.value.toLowerCase() === value.toLowerCase() || option.text.toLowerCase() === value.toLowerCase() || (/^\d+$/.test(value) && Number(option.value) === Number(value)));
    if (!option) return false;
    element.value = option.value;
  } else {
    const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    if (!setter) return false;
    setter.call(element, value);
  }
  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}

export function fillItem(item: BrowserItem, expectedUrl: string): { filled: number } {
  if (!topFrame || !sameDocument(expectedUrl, location.href)) throw new Error('The page changed. Open JJ Vault again.');
  if (!item || !['login', 'password', 'identity', 'creditCard'].includes(item.type)) throw new Error('This item cannot be filled.');
  if ((item.type === 'login' || item.type === 'password') && !item.urls?.some(url => matchesUrl(url, location.href))) throw new Error('This login does not match this website.');
  if (item.urls?.length && !item.urls.some(url => matchesUrl(url, location.href))) throw new Error('This item does not match this website.');
  const controls = Array.from(document.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>('input,select,textarea')).filter(visible).filter(element => safeForm(element.form));
  const matches = controls.map(element => ({ element, value: fieldValue(item, descriptor(element)) })).filter(match => match.value !== undefined);
  const focused = matches.find(match => match.element === document.activeElement);
  const password = matches.find(match => match.element instanceof HTMLInputElement && match.element.type === 'password');
  const form = (focused ?? password ?? matches[0])?.element.form;
  if (form === undefined) return { filled: 0 };
  let filled = 0;
  for (const match of matches) {
    if (match.element.form !== form || !visible(match.element) || !safeForm(match.element.form) || !sameDocument(expectedUrl, location.href)) continue;
    if (insert(match.element, match.value!)) filled++;
  }
  return { filled };
}

let offer: HTMLElement | undefined;
let offerTimer: ReturnType<typeof setTimeout> | undefined;
function hideOffer() { if (offerTimer) clearTimeout(offerTimer); offerTimer = undefined; offer?.remove(); offer = undefined; }
function showOffer(expiresAt: unknown) {
  if (!topFrame || !safePageUrl(location.href) || typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + MAX_CAPTURE_AGE + 1000) return;
  hideOffer();
  const host = document.createElement('div'); host.dataset.jjvaultSaveOffer = '';
  host.style.cssText = 'all:initial;position:fixed;right:20px;bottom:20px;z-index:2147483647;width:min(350px,calc(100vw - 40px));';
  const shadow = host.attachShadow({ mode: 'open' });
  // This page visible surface contains static instructions only. Captured fields stay in extension memory.
  shadow.innerHTML = `<style>:host{color-scheme:light}section{box-sizing:border-box;background:#fff;color:#19251b;font:14px/1.45 system-ui,sans-serif;border:1px solid #d4dfd0;border-radius:14px;padding:18px;box-shadow:0 8px 36px #0003}strong{display:block;font-size:16px}p{margin:8px 0 14px}button{font:inherit;border:1px solid #bacbb4;border-radius:8px;padding:8px 11px;cursor:pointer;background:#e0f3cd;color:#19251b}button+button{margin-left:8px;background:#fff}button:focus-visible{outline:3px solid #416a2a;outline-offset:2px}[role=status]{margin:10px 0 0;font-size:13px}</style><section role="region" aria-label="JJ Vault save offer"><strong>Save or update this login?</strong><p>Review it in JJ Vault. Nothing is saved until you confirm.</p><button type="button" id="review">Review in JJ Vault</button><button type="button" id="dismiss">Dismiss</button><p role="status" hidden></p></section>`;
  const review = shadow.querySelector<HTMLButtonElement>('#review')!;
  review.addEventListener('click', event => {
    if (!event.isTrusted) return;
    review.disabled = true;
    void api.runtime.sendMessage({ action: 'reviewCapture' }).then(reply => {
      if (offer !== host) return;
      if (!reply?.available) { hideOffer(); return; }
      if (!reply.opened) { const status = shadow.querySelector<HTMLElement>('[role=status]')!; status.hidden = false; status.textContent = 'Click the JJ Vault icon in the browser toolbar to review, then choose Confirm save.'; }
    }).catch(() => {
      if (offer !== host) return;
      const status = shadow.querySelector<HTMLElement>('[role=status]')!; status.hidden = false; status.textContent = 'Click the JJ Vault icon in the browser toolbar to review, then choose Confirm save.';
    }).finally(() => { if (offer === host) review.disabled = false; });
  });
  shadow.querySelector<HTMLButtonElement>('#dismiss')!.addEventListener('click', event => { if (!event.isTrusted) return; hideOffer(); void api.runtime.sendMessage({ action: 'dismissCaptureOffer' }).catch(() => {}); });
  offer = host; (document.body ?? document.documentElement).append(host);
  offerTimer = setTimeout(() => { if (offer === host) hideOffer(); }, Math.max(0, expiresAt - Date.now()));
}

if (topFrame) {
  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== api.runtime.id) return;
    if (message?.action === 'captureCleared') { hideOffer(); respond({ ok: true }); return; }
    if (message?.action !== 'fill' || typeof message.expectedUrl !== 'string') return;
    try { respond({ ok: true, ...fillItem(message.item, message.expectedUrl) }); }
    catch (error) { respond({ ok: false, error: error instanceof Error ? error.message : 'Autofill failed.' }); }
  });

  document.addEventListener('submit', event => {
    if (!event.isTrusted || !safePageUrl(location.href) || !(event.target instanceof HTMLFormElement) || !safeForm(event.target)) return;
    const fields = Array.from(event.target.querySelectorAll<HTMLInputElement>('input')).filter(visible);
    const passwords = fields.filter(field => field.type === 'password' && field.value);
    const fresh = passwords.filter(field => field.autocomplete === 'new-password');
    const passwordField = fresh[0] ?? passwords[0];
    if (!passwordField || passwordField.value.length > 4096 || (fresh.length > 1 && fresh.some(field => field.value !== passwordField.value))) return;
    const userField = fields.find(field => field.autocomplete === 'username') ?? fields.find(field => field.type === 'email') ?? fields.find(field => /^(user(name)?|login|email)$/i.test(field.name || field.id));
    const candidate = { url: location.href, title: document.title.slice(0, 512) || location.hostname, username: (userField?.value ?? '').slice(0, 4096), password: passwordField.value, capturedAt: Date.now() };
    void api.runtime.sendMessage({ action: 'capture', candidate }).then(reply => { if (reply?.ok && reply.available) showOffer(reply.expiresAt); }).catch(() => {}).finally(() => { candidate.password = ''; candidate.username = ''; });
  }, { capture: true });
  if (safePageUrl(location.href)) void api.runtime.sendMessage({ action: 'captureOffer' }).then(reply => { if (reply?.available) showOffer(reply.expiresAt); }).catch(() => {});
  window.addEventListener('pagehide', hideOffer);
}
