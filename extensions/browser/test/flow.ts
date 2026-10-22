/** Real browser fixture tests. All credential values here are deliberately synthetic. */
import { chromium, type Page } from '@playwright/test';
import { readFile, mkdir } from 'node:fs/promises';
import assert from 'node:assert/strict';
import path from 'node:path';

const browser = await chromium.launch({ channel: process.env.JJ_VAULT_TEST_BROWSER_CHANNEL || 'chrome', headless: true });
const context = await browser.newContext();
const content = await readFile(path.resolve('dist/extensions/chrome/content.js'), 'utf8');
const popupHTML = await readFile(path.resolve('dist/extensions/chrome/popup.html'), 'utf8');
const fixture = `<!doctype html><html><head><title>Example login</title></head><body>
<form id="login" onsubmit="event.preventDefault()"><label>Username <input id="user" autocomplete="username"></label><label>Password <input id="password" type="password" autocomplete="current-password"></label><input id="hidden" type="password" style="display:none"><input id="otp" autocomplete="one-time-code"><button>Sign in</button></form>
<form id="foreign" action="https://evil.test/post"><input id="foreignPassword" type="password"></form>
<form id="signup"><input id="new" type="password" autocomplete="new-password"></form>
<form id="card"><input id="cardNumber" autocomplete="cc-number"><select id="cardMonth" autocomplete="cc-exp-month"><option value="">Month</option><option value="2">February</option></select><input id="cardYear" autocomplete="cc-exp-year"><input id="cvc" autocomplete="cc-csc"></form>
<form id="identity"><input id="first" autocomplete="given-name"><input id="city" autocomplete="address-level2"></form>
<iframe src="https://example.test/frame"></iframe></body></html>`;

async function installMock(page: Page) {
  await page.addInitScript(() => {
    (window as any).__captures = [];
    (window as any).chrome = { runtime: { id: 'fixture-extension', onMessage: { addListener(handler: unknown) { (window as any).__fillHandler = handler; } }, sendMessage(message: unknown) { (window as any).__captures.push(message); return Promise.resolve({ ok: true }); } } };
  });
}

try {
  await context.route('https://example.test/**', route => route.fulfill({ contentType: 'text/html', body: new URL(route.request().url()).pathname === '/frame' ? '<form><input type="password"></form>' : fixture }));
  const page = await context.newPage(); await installMock(page);
  await page.goto('https://example.test/login'); await page.addScriptTag({ content });
  const fill = async (item: unknown, expectedUrl = page.url()) => page.evaluate(({ item, expectedUrl }) => {
    let result: unknown;
    (window as any).__fillHandler({ action: 'fill', expectedUrl, item }, { id: 'fixture-extension' }, (value: unknown) => { result = value; });
    return result as { ok: boolean; filled?: number };
  }, { item, expectedUrl });
  const login = { id: 'fixture', title: 'Example', type: 'login', username: 'synthetic@example.test', password: 'fixture only password', urls: ['https://example.test/'], totp: '123456' };
  assert.deepEqual(await fill(login), { ok: true, filled: 3 });
  assert.equal(await page.locator('#user').inputValue(), login.username);
  assert.equal(await page.locator('#password').inputValue(), login.password);
  assert.equal(await page.locator('#otp').inputValue(), '123456');
  for (const id of ['hidden', 'foreignPassword', 'new']) assert.equal(await page.locator(`#${id}`).inputValue(), '');
  assert.equal((await fill({ ...login, urls: ['https://other.test'] })).ok, false);
  assert.equal((await fill(login, 'https://example.test/old')).ok, false);
  const frame = page.frames().find(frame => frame.parentFrame()); assert.ok(frame);
  await frame.addScriptTag({ content });
  assert.equal(await frame.evaluate(() => Boolean((window as any).__fillHandler)), false);
  await page.locator('#login').dispatchEvent('submit');
  assert.equal(await page.evaluate(() => (window as any).__captures.filter((message: any) => message.action === 'capture').length), 0, 'Synthetic submit cannot capture credentials');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  assert.equal(await page.evaluate(() => (window as any).__captures.filter((message: any) => message.action === 'capture').length), 1, 'Trusted submit offers a save');
  const card = { id: 'card', type: 'creditCard', title: 'Fixture card', fields: [{ label: 'Card number', value: '4242424242424242' }, { label: 'Expiration', value: '02/2030' }, { label: 'CVV', value: '000' }] };
  assert.deepEqual(await fill(card), { ok: true, filled: 4 });
  assert.equal(await page.locator('#cardNumber').inputValue(), '4242424242424242');
  assert.equal(await page.locator('#cardMonth').inputValue(), '2');
  assert.equal(await page.locator('#cardYear').inputValue(), '2030');
  assert.deepEqual(await fill({ id: 'identity', type: 'identity', title: 'Fixture', fields: [{ label: 'First name', value: 'Example' }, { label: 'City', value: 'Austin' }] }), { ok: true, filled: 2 });
  assert.equal(await page.locator('#first').inputValue(), 'Example');
  process.stdout.write('PASS real Chrome: visible login + TOTP, cards, identity, hidden and foreign forms, navigation rejection, frame rejection, trusted capture\n');

  // Render the real popup against a controlled native bridge. Never touch a user browser profile.
  const popup = await context.newPage();
  await popup.setViewportSize({ width: 390, height: 760 });
  popup.on('pageerror', error => process.stderr.write(`Popup error: ${error.message}\n`));
  await context.route('https://popup.test/**', async route => {
    const file = new URL(route.request().url()).pathname.slice(1) || 'popup.html';
    if (file === 'popup.html') return route.fulfill({ contentType: 'text/html', body: popupHTML });
    if (!/^(popup\.(js|css)|icon\.svg)$/.test(file)) return route.abort();
    return route.fulfill({ contentType: file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'application/javascript', body: await readFile(path.resolve(`dist/extensions/chrome/${file}`)) });
  });
  const mockBridge = () => {
    const item = { id: 'example', title: 'Example account', type: 'login', username: 'synthetic@example.test' };
    (window as any).__nativeCalls = []; (window as any).__fillCalls = []; (window as any).__changed = false;
    (window as any).chrome = {
      runtime: { id: 'fixture-extension', sendNativeMessage(_host: string, message: any) { (window as any).__nativeCalls.push(message); return Promise.resolve({ ok: true, result: message.action === 'list' ? [item] : message.action === 'get' ? { ...item, password: 'synthetic secret', urls: ['https://example.test'] } : { id: 'saved' } }); }, sendMessage(message: any) { return Promise.resolve(message.action === 'pendingCapture' ? { candidate: { url: 'https://example.test/login', title: 'Captured example', username: (window as any).__passwordOnly ? '' : 'synthetic@example.test', password: 'synthetic captured', capturedAt: Date.now() } } : { ok: true }); } },
      tabs: { query: async () => [{ id: 7, url: 'https://example.test/login' }], get: async () => ({ id: 7, url: (window as any).__changed ? 'https://evil.test' : 'https://example.test/login' }), sendMessage: async (_tab: number, message: any, options: unknown) => { (window as any).__fillCalls.push({ message, options }); return { ok: true, filled: 2 }; } },
    };
  };
  await popup.addInitScript({ content: `window.__name = value => value; (${mockBridge.toString()})();` });
  await popup.goto('https://popup.test/popup.html');
  await popup.getByRole('button', { name: 'Fill Example account, Login' }).waitFor({ timeout: 10_000 }).catch(async error => { process.stderr.write((await popup.locator('body').innerText()) + '\n'); throw error; });
  await popup.getByRole('button', { name: 'Confirm save' }).waitFor();
  await mkdir('output/playwright', { recursive: true });
  await popup.screenshot({ path: 'output/playwright/browser-popup.png', fullPage: true });
  assert.equal(await popup.evaluate(() => (window as any).__nativeCalls.filter((call: any) => call.action === 'save').length), 0, 'Save is never automatic');
  await popup.getByRole('button', { name: 'Fill Example account, Login' }).click();
  await popup.getByText('Filled 2 fields. You can review and submit.').waitFor();
  assert.equal(await popup.evaluate(() => (window as any).__fillCalls[0].options.frameId), 0);
  await popup.getByRole('button', { name: 'Confirm save' }).click();
  await popup.getByText('Login saved in JJ Vault.').waitFor();
  assert.equal(await popup.evaluate(() => (window as any).__nativeCalls.filter((call: any) => call.action === 'save').length), 1);
  // Password change forms often omit the username. Updating the selected login
  // must retain its existing identity from the reviewed item metadata.
  await popup.evaluate(() => { (window as any).__passwordOnly = true; });
  await popup.locator('#refresh').click();
  await popup.getByRole('button', { name: 'Confirm save' }).waitFor();
  await popup.locator('#saveTarget').selectOption('example');
  await popup.getByRole('button', { name: 'Confirm save' }).click();
  await popup.getByText('Password updated in JJ Vault.').waitFor();
  const passwordOnlyUpdate = await popup.evaluate(() => (window as any).__nativeCalls.filter((call: any) => call.action === 'save').at(-1).item);
  assert.equal(passwordOnlyUpdate.id, 'example');
  assert.equal(passwordOnlyUpdate.username, 'synthetic@example.test', 'Password only updates retain the selected login username');
  await popup.evaluate(() => { (window as any).__changed = true; });
  await popup.getByRole('button', { name: 'Fill Example account, Login' }).click();
  await popup.getByText('The page changed. Reopen JJ Vault to continue.').waitFor();
  assert.equal(await popup.evaluate(() => (window as any).__nativeCalls.filter((call: any) => call.action === 'get').length), 1);
  await popup.screenshot({ path: 'output/playwright/browser-navigation-rejected.png' });
  process.stdout.write('PASS real Chrome popup: explicit fill, top frame target, explicit save only, password only updates preserve username, navigation cancels native get\n');
} finally { await context.close(); await browser.close(); }
