/**
 * Local visual fixture for Chrome Web Store screenshots.
 * Serves the actual built popup with synthetic data and no native connection.
 * Run with tsx, then use the Playwright CLI against the printed loopback URL.
 * Capture to output/playwright before copying selected images to release/chrome-web-store.
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDirectExecution } from '../packages/service/src/entrypoint.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const popupDirectory = path.join(root, 'dist/extensions/chrome');

const mockChrome = `
// Synthetic demo bridge. This fixture never reads a real vault or browser profile.
const demoItems = [
  { id: 'demo-work', title: 'Example workspace', type: 'login', username: 'alex@example.test' },
  { id: 'demo-personal', title: 'Personal example', type: 'login', username: 'hello@example.test' },
  { id: 'demo-card', title: 'Demo card', type: 'creditCard' }
];
window.chrome = {
  runtime: {
    id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    sendNativeMessage: async (_host, message) => ({ ok: true, result:
      message.action === 'list' ? structuredClone(demoItems) :
      message.action === 'get' ? { ...demoItems.find(item => item.id === message.id),
        password: 'synthetic demo password', urls: ['https://example.test/'] } : { id: 'demo-saved' } }),
    sendMessage: async () => ({ candidate: null, ok: true })
  },
  tabs: {
    query: async () => [{ id: 1, url: 'https://example.test/signin' }],
    get: async () => ({ id: 1, url: 'https://example.test/signin' }),
    sendMessage: async () => ({ ok: true, filled: 2 })
  }
};
`;

const demoPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>JJ Vault Chrome demo</title>
<style>
*{box-sizing:border-box}html,body{margin:0;width:1280px;height:800px;overflow:hidden}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#e9eee9;background:#111914}
.canvas{width:1280px;height:800px;position:relative;background:radial-gradient(ellipse at 82% 44%,#293d2b 0,transparent 51%),#111914}
.brand{position:absolute;left:72px;top:57px;display:flex;align-items:center;gap:13px;font-size:25px;font-weight:650;letter-spacing:-.6px}.brand img{width:44px;height:44px}
.demo{position:absolute;right:72px;top:68px;color:#c5d9bb;background:#26382a;border:1px solid #3c5240;border-radius:30px;padding:8px 14px;font-size:13px}
.copy{position:absolute;left:72px;top:188px;width:560px}.eyebrow{font-size:13px;letter-spacing:2.7px;color:#b8d994;font-weight:550;margin-bottom:24px}
h1{font-size:62px;line-height:1.05;font-weight:610;letter-spacing:-2.7px;margin:0 0 25px}.copy p{font-size:21px;color:#adbdaf;line-height:1.55;margin:0;max-width:480px}
.points{margin-top:32px;display:grid;gap:14px;color:#d1dfca;font-size:17px}.points span:before{content:'✓';color:#c8ed9f;margin-right:13px}
.requirement{display:inline-block;margin-top:35px;border:1px solid #4d6545;background:#23331f;color:#d4edbe;border-radius:9px;font-size:15px;padding:13px 17px}
.popup{position:absolute;left:774px;top:130px;width:392px;background:#171d1a;border-radius:13px;box-shadow:0 28px 60px #0007;overflow:hidden;border:1px solid #455543}
iframe{display:block;width:390px;height:552px;border:0}.popupLabel{position:absolute;left:774px;top:109px;width:392px;text-align:center;color:#9ead9e;font-size:13px}
.footer{position:absolute;left:72px;right:72px;bottom:24px;display:flex;justify-content:space-between;border-top:1px solid #334336;padding-top:20px;color:#9dad9e;font-size:13px}
</style></head><body><div class="canvas">
<div class="brand"><img src="/icon.svg" alt="">JJ Vault</div><div class="demo">Demo preview · Sample data</div>
<div class="copy"><div class="eyebrow">JJ VAULT FOR CHROME</div><h1>Your vault.<br>Within reach.</h1>
<p>Choose a saved item and fill it on the website you are visiting.</p>
<div class="points"><span>Logins and authenticator codes</span><span>Cards and addresses</span><span>You choose what gets filled</span></div>
<div class="requirement">Requires the JJ Vault Mac app</div></div>
<div class="popup"><iframe src="/popup.html" title="Actual JJ Vault popup with synthetic demo data" onload="this.style.height=this.contentDocument.body.scrollHeight+'px'"></iframe></div>
<div class="popupLabel">Actual extension popup with demo data</div>
<div class="footer"><span>Private vault on your Mac</span><span>Keep JJ Vault running and unlocked to use autofill</span></div>
</div></body></html>`;

export async function startChromeStoreFixture() {
  const popupHtml = (await readFile(path.join(popupDirectory, 'popup.html'), 'utf8'))
    .replace('<script src="popup.js">', '<script src="/mock-chrome.js"></script><script src="popup.js">');
  const iconSvg = await readFile(path.join(popupDirectory, 'icon.svg'), 'utf8');
  const paddedIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128"><g transform="translate(16 16) scale(.75)">${iconSvg.replace(/^<svg[^>]*>/, '').replace(/<\/svg>\s*$/, '')}</g></svg>`;
  const server = createServer(async (request, response) => {
    try {
      const route = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
      if (route === '/favicon.ico') { response.statusCode = 204; response.end(); return; }
      if (route === '/') { response.setHeader('Content-Type', 'text/html'); response.end(demoPage); return; }
      if (route === '/popup.html') { response.setHeader('Content-Type', 'text/html'); response.end(popupHtml); return; }
      if (route === '/mock-chrome.js') { response.setHeader('Content-Type', 'application/javascript'); response.end(mockChrome); return; }
      if (route === '/store-icon.html') {
        response.setHeader('Content-Type', 'text/html');
        response.end(`<!doctype html><html><head><title>JJ Vault store icon</title><style>html,body{margin:0;background:transparent}svg{display:block}</style></head><body>${paddedIcon}</body></html>`);
        return;
      }
      const file = route.slice(1);
      if (!['popup.js', 'popup.css', 'icon.svg'].includes(file)) { response.statusCode = 404; response.end(); return; }
      response.setHeader('Content-Type', file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'application/javascript');
      response.end(await readFile(path.join(popupDirectory, file)));
    } catch { response.statusCode = 500; response.end('Demo fixture unavailable. Build the Chrome extension first.'); }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Demo server did not acquire a loopback port.');
  return { server, url: `http://127.0.0.1:${address.port}` };
}

if (isDirectExecution(import.meta.url)) {
  if (process.argv.length > 2) throw new Error('This local visual fixture does not accept arguments.');
  const fixture = await startChromeStoreFixture();
  process.stdout.write(`Chrome store demo fixture: ${fixture.url}\nStore icon: ${fixture.url}/store-icon.html\nSynthetic demo only. No real vault or browser profile is used.\n`);
  const cli = '"$HOME/.codex/skills/playwright/scripts/playwright_cli.sh" --session jj-vault-store-assets';
  process.stdout.write(`\nReproduce the screenshot with the Playwright CLI:\nmkdir -p output/playwright\n${cli} open ${fixture.url} --headed\n${cli} resize 1280 800\n${cli} snapshot\n${cli} screenshot --filename output/playwright/chrome-store-popup-1280x800.png\n${cli} close\n\nThe store icon uses /store-icon.html at 128 by 128 with an omitBackground screenshot.\n`);
}
