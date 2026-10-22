import { build } from 'esbuild';
import { mkdir, copyFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const root = path.dirname(fileURLToPath(import.meta.url));

function crc32(bytes: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngIcon(size: number) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let row = 0; row < size; row++) for (let column = 0; column < size; column++) {
    const x = (column + .5) * 128 / size, y = (row + .5) * 128 / size;
    const rounded = (cx: number, cy: number, w: number, h: number, r: number) => Math.hypot(Math.max(Math.abs(x - cx) - w / 2 + r, 0), Math.max(Math.abs(y - cy) - h / 2 + r, 0)) <= r;
    const base = rounded(64, 64, 124, 124, 30);
    const shackle = y <= 43 && y >= 8 && Math.abs(Math.hypot(x - 64, y - 29) - 18) < 5 && (y < 29 || Math.abs(x - 64) > 12);
    const body = rounded(64, 67, 66, 64, 11);
    const hole = Math.hypot(x - 64, y - 64) < 9 || (Math.abs(x - 64) < 4 && y >= 64 && y < 85);
    const dark = (body || shackle) && !hole;
    const color = dark ? [36, 60, 34] : [200, 237, 159];
    const index = row * (size * 4 + 1) + 1 + column * 4;
    raw.set([...color, base ? 255 : 0], index);
  }
  const header = Buffer.alloc(13); header.writeUInt32BE(size, 0); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6;
  const chunk = (name: string, data: Buffer) => {
    const payload = Buffer.concat([Buffer.from(name), data]);
    const length = Buffer.alloc(4); length.writeUInt32BE(data.length);
    const checksum = Buffer.alloc(4); checksum.writeUInt32BE(crc32(payload));
    return Buffer.concat([length, payload, checksum]);
  };
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

export async function buildExtensions(destination = path.resolve(root, '../../dist/extensions')) {
  for (const browser of ['chrome', 'firefox', 'safari']) {
    const outdir = path.join(destination, browser); await mkdir(outdir, { recursive: true });
    await build({ entryPoints: ['background', 'content', 'popup'].map(name => path.join(root, `src/${name}.ts`)), outdir, bundle: true, format: 'iife', target: 'es2022', sourcemap: true, legalComments: 'none', define: { JJVAULT_NATIVE_HOST: JSON.stringify(browser === 'safari' ? 'com.john.jjvault.safari' : 'com.john.jjvault') } });
    await Promise.all(['popup.html', 'popup.css'].map(file => copyFile(path.join(root, file), path.join(outdir, file))));
    await copyFile(path.join(root, 'assets/icon.svg'), path.join(outdir, 'icon.svg'));
    for (const size of [16, 32, 48, 128]) await writeFile(path.join(outdir, `icon${size}.png`), pngIcon(size));
    const manifest: Record<string, unknown> = {
      manifest_version: 3, name: 'JJ Vault', version: '0.1.0', description: 'Fill your logins, one time codes, cards, and addresses from your local JJ Vault.',
      permissions: ['activeTab', 'tabs', 'nativeMessaging'], host_permissions: ['https://*/*'],
      action: { default_title: 'JJ Vault', default_popup: 'popup.html', default_icon: { '16': 'icon16.png', '32': 'icon32.png' } },
      icons: { '16': 'icon16.png', '32': 'icon32.png', '48': 'icon48.png', '128': 'icon128.png' },
      background: browser === 'chrome' ? { service_worker: 'background.js' } : { scripts: ['background.js'], persistent: false },
      content_scripts: [{ matches: ['https://*/*'], js: ['content.js'], run_at: 'document_idle', all_frames: false }],
      commands: { _execute_action: { suggested_key: { default: 'Ctrl+Shift+L', mac: 'Command+Shift+L' } } },
      content_security_policy: { extension_pages: "script-src 'self'; object-src 'none'; connect-src 'none'" },
    };
    if (browser === 'chrome') manifest.minimum_chrome_version = '120';
    if (browser === 'firefox') manifest.browser_specific_settings = { gecko: { id: 'jjvault@john.local', strict_min_version: '140.0', data_collection_permissions: { required: ['authenticationInfo', 'personallyIdentifyingInfo', 'financialAndPaymentInfo', 'browsingActivity'] } } };
    await writeFile(path.join(outdir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await buildExtensions();
