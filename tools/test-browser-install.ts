import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { installBrowserHost } from './install-browser-host.ts';
import { installBrowserHost as installServiceHost } from '../packages/service/src/browser-install.ts';

const run = promisify(execFile);
const first = 'a'.repeat(32);
const second = 'b'.repeat(32);
const third = 'c'.repeat(32);
const support = 'Library/Application Support/JJ Vault';
const chromeFolder = 'Library/Application Support/Google/Chrome/NativeMessagingHosts';
const firefoxFolder = 'Library/Application Support/Mozilla/NativeMessagingHosts';
async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'jj-browser-install-'));
  const homeDirectory = path.join(directory, 'home with quote\'s');
  const sourceHostFile = path.join(directory, 'cloud checkout', 'dist', 'native-host.cjs');
  await mkdir(homeDirectory, { mode: 0o700 }); await mkdir(path.dirname(sourceHostFile), { recursive: true });
  await writeFile(sourceHostFile, 'process.stdout.write(JSON.stringify(process.argv.slice(2)));\n', { mode: 0o644 });
  return { directory, homeDirectory, sourceHostFile, options: { homeDirectory, sourceHostFile }, config: path.join(homeDirectory, support, 'browser-host.json'), cleanup: () => rm(directory, { recursive: true, force: true }) };
}
test('browser installer deploys an independent private host and quotes its stable launcher', async () => {
  const f = await fixture();
  try {
    const result = await installBrowserHost(['--chrome', first], f.options);
    assert.equal(result.hostFile, path.join(f.homeDirectory, support, 'native-host.cjs'));
    assert.equal(result.chromeCount, 1); assert.equal(result.firefoxCount, 0);
    const launcher = await readFile(result.executable, 'utf8');
    assert.ok(!launcher.includes('cloud checkout')); assert.ok(launcher.includes('native-host.cjs'));
    assert.equal((await lstat(result.executable)).mode & 0o777, 0o700);
    assert.equal((await lstat(result.hostFile)).mode & 0o777, 0o600);
    assert.equal((await lstat(f.config)).mode & 0o777, 0o600);
    assert.equal((await lstat(path.dirname(f.config))).mode & 0o777, 0o700);
    const manifestFile = path.join(f.homeDirectory, chromeFolder, 'com.john.jjvault.json');
    const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
    assert.deepEqual(manifest.allowed_origins, [`chrome-extension://${first}/`]); assert.equal(manifest.path, result.executable);
    assert.equal((await lstat(manifestFile)).mode & 0o777, 0o600);
    await rm(path.dirname(path.dirname(f.sourceHostFile)), { recursive: true });
    const execution = await run(result.executable, [`chrome-extension://${first}/`, 'a quoted argument']);
    assert.deepEqual(JSON.parse(execution.stdout), [`chrome-extension://${first}/`, 'a quoted argument']);
  } finally { await f.cleanup(); }
});
test('pairing and removal preserve other Chrome IDs, Firefox, Safari, and unrelated manifests', async () => {
  const f = await fixture();
  try {
    await installBrowserHost(['--chrome', first, '--chrome', second, '--firefox'], f.options);
    const config = JSON.parse(await readFile(f.config, 'utf8'));
    config.safariExtensionIds = ['com.john.jjvault.safari']; config.ownerSetting = 'keep';
    await writeFile(f.config, JSON.stringify(config), { mode: 0o600 });
    const unrelated = path.join(f.homeDirectory, chromeFolder, 'org.other.bridge.json');
    await writeFile(unrelated, 'leave this untouched', { mode: 0o600 });
    let result = await installBrowserHost(['--chrome', third, '--remove-chrome', first], f.options);
    assert.equal(result.chromeCount, 2); assert.equal(result.firefoxCount, 1);
    let updated = JSON.parse(await readFile(f.config, 'utf8'));
    assert.deepEqual(updated.chromeExtensionIds, [second, third]); assert.deepEqual(updated.firefoxExtensionIds, ['jjvault@john.local']);
    assert.deepEqual(updated.safariExtensionIds, config.safariExtensionIds); assert.equal(updated.ownerSetting, 'keep');
    result = await installBrowserHost(['--remove-chrome', second, '--remove-chrome', third], f.options);
    assert.equal(result.chromeCount, 0); assert.equal(result.firefoxCount, 1);
    await assert.rejects(lstat(path.join(f.homeDirectory, chromeFolder, 'com.john.jjvault.json')), { code: 'ENOENT' });
    assert.equal(await readFile(unrelated, 'utf8'), 'leave this untouched');
    const firefox = JSON.parse(await readFile(path.join(f.homeDirectory, firefoxFolder, 'com.john.jjvault.json'), 'utf8'));
    assert.deepEqual(firefox.allowed_extensions, ['jjvault@john.local']);
    await installBrowserHost(['--remove-firefox'], f.options);
    updated = JSON.parse(await readFile(f.config, 'utf8')); assert.deepEqual(updated.safariExtensionIds, config.safariExtensionIds);
    await assert.rejects(lstat(path.join(f.homeDirectory, firefoxFolder, 'com.john.jjvault.json')), { code: 'ENOENT' });
  } finally { await f.cleanup(); }
});
test('malformed IDs and unsupported arguments fail before making configuration', async () => {
  const f = await fixture();
  try {
    for (const args of [['--chrome', '../secret'], ['--chrome', 'q'.repeat(32)], ['--chrome'], ['--home', '/tmp']]) await assert.rejects(installBrowserHost(args, f.options));
    await assert.rejects(lstat(f.config), { code: 'ENOENT' });
  } finally { await f.cleanup(); }
});
test('pairing refuses symbolic or nonprivate configuration without reading its target', async () => {
  const f = await fixture();
  try {
    await mkdir(path.dirname(f.config), { recursive: true, mode: 0o700 });
    const target = path.join(f.directory, 'target'); await writeFile(target, 'unchanged', { mode: 0o600 });
    await symlink(target, f.config);
    await assert.rejects(installBrowserHost(['--chrome', first], f.options), /regular owner controlled/);
    assert.equal(await readFile(target, 'utf8'), 'unchanged'); await rm(f.config);
    await writeFile(f.config, '{}', { mode: 0o644 }); await chmod(f.config, 0o644);
    await assert.rejects(installBrowserHost(['--chrome', first], f.options), /safe permissions/);
  } finally { await f.cleanup(); }
});
test('pairing refuses symbolic support folders and symbolic built hosts', async () => {
  const f = await fixture();
  try {
    const elsewhere = path.join(f.directory, 'elsewhere'); await mkdir(elsewhere);
    await symlink(elsewhere, path.join(f.homeDirectory, 'Library'));
    await assert.rejects(installBrowserHost(['--chrome', first], f.options), /real owner controlled/);
    await rm(path.join(f.homeDirectory, 'Library'));
    const linked = path.join(f.directory, 'linked-host.cjs'); await symlink(f.sourceHostFile, linked);
    await assert.rejects(installBrowserHost(['--chrome', first], { ...f.options, sourceHostFile: linked }), /regular owner controlled/);
  } finally { await f.cleanup(); }
});
test('Node selection uses an executable preferred runtime and falls back when missing', async () => {
  const f = await fixture();
  try {
    let result = await installBrowserHost(['--chrome', first], { ...f.options, preferredNode: process.execPath });
    assert.equal(result.nodePath, process.execPath);
    result = await installBrowserHost(['--chrome', first], { ...f.options, preferredNode: path.join(f.directory, 'missing-node') });
    assert.equal(result.nodePath, process.execPath);
  } finally { await f.cleanup(); }
});

test('desktop installer uses an explicit runtime, data directory, and service port', async () => {
  const f = await fixture();
  try {
    const dataDirectory = path.join(f.homeDirectory, 'custom local vault');
    const result = await installServiceHost({ operations: [{ action: 'chrome', id: first }], sourceHostFile: f.sourceHostFile, runtimePath: process.execPath, homeDirectory: f.homeDirectory, dataDirectory, port: 24680 });
    assert.equal(result.nodePath, process.execPath);
    assert.equal(result.configFile, path.join(dataDirectory, 'browser-host.json'));
    assert.equal(result.hostFile, path.join(dataDirectory, 'native-host.cjs'));
    const config = JSON.parse(await readFile(result.configFile, 'utf8'));
    assert.equal(config.port, 24680);
    assert.equal(config.browserTokenFile, path.join(dataDirectory, 'browser-token'));
    const launcher = await readFile(result.executable, 'utf8');
    assert.ok(launcher.includes("exec /usr/bin/env 'JJ_VAULT_BROWSER_CONFIG="));
    await assert.rejects(lstat(f.config), { code: 'ENOENT' });
    const execution = await run(result.executable, [`chrome-extension://${first}/`]);
    assert.deepEqual(JSON.parse(execution.stdout), [`chrome-extension://${first}/`]);
  } finally { await f.cleanup(); }
});
test('installer rejects unsafe token files and invalid service ports before writing a bridge', async () => {
  const f = await fixture();
  try {
    await mkdir(path.dirname(f.config), { recursive: true, mode: 0o700 });
    const tokenFile = path.join(path.dirname(f.config), 'browser-token');
    const target = path.join(f.directory, 'target-token');
    await writeFile(target, 'x'.repeat(64), { mode: 0o600 });
    await symlink(target, tokenFile);
    await assert.rejects(installBrowserHost(['--chrome', first], f.options), /regular owner controlled/);
    await rm(tokenFile);
    await writeFile(tokenFile, 'x'.repeat(64), { mode: 0o644 }); await chmod(tokenFile, 0o644);
    await assert.rejects(installBrowserHost(['--chrome', first], f.options), /safe permissions/);
    await chmod(tokenFile, 0o600); await writeFile(tokenFile, 'short');
    await assert.rejects(installBrowserHost(['--chrome', first], f.options), /at least 43/);
    await writeFile(tokenFile, 'x'.repeat(64));
    for (const port of [0, -1, 65536, 1.5]) await assert.rejects(installBrowserHost(['--chrome', first], { ...f.options, port }), /Invalid browser host port/);
    await assert.rejects(lstat(f.config), { code: 'ENOENT' });
    await assert.rejects(lstat(path.join(path.dirname(f.config), 'jjvault-browser-host')), { code: 'ENOENT' });
  } finally { await f.cleanup(); }
});
test('service module validates operations and custom folder ownership rules', async () => {
  const f = await fixture();
  try {
    const options = { operations: [{ action: 'chrome' as const, id: first }], sourceHostFile: f.sourceHostFile, runtimePath: process.execPath, homeDirectory: f.homeDirectory };
    await assert.rejects(installServiceHost({ ...options, operations: [{ action: 'chrome', id: 'invalid' }] }), /invalid extension IDs/);
    const folder = path.join(f.directory, 'outside home'); await mkdir(folder, { mode: 0o700 });
    const link = path.join(f.directory, 'unsafe alias'); await symlink(folder, link);
    await assert.rejects(installServiceHost({ ...options, dataDirectory: path.join(link, 'vault') }), /real owner controlled/);
    await assert.rejects(installServiceHost({ ...options, runtimePath: f.sourceHostFile }), /EACCES/);
  } finally { await f.cleanup(); }
});
async function sendNativeMessage(executable: string, caller: string, message: unknown) {
  const payload = Buffer.from(JSON.stringify(message));
  const header = Buffer.alloc(4); header.writeUInt32LE(payload.length);
  return new Promise<Buffer>((resolve, reject) => {
    const child = spawn(executable, [caller], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env } });
    const chunks: Buffer[] = [];
    let stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('Native host fixture timed out')); }, 15000);
    child.stdout.on('data', chunk => chunks.push(Buffer.from(chunk)));
    child.stderr.on('data', chunk => { stderr += chunk.toString(); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`Native host fixture exited with code ${code}: ${stderr}`));
      else resolve(Buffer.concat(chunks));
    });
    child.stdin.end(Buffer.concat([header, payload]));
  });
}
test('packaged desktop runtime launches the real native host against an isolated synthetic service', async () => {
  const f = await fixture();
  const token = 'fixture-browser-token-'.repeat(4);
  let requestCount = 0;
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    assert.equal(request.url, '/browser');
    assert.equal(request.headers.authorization, `Bearer ${token}`);
    assert.deepEqual(JSON.parse(Buffer.concat(chunks).toString('utf8')), { action: 'list', url: 'https://example.test/login' });
    requestCount++;
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ ok: true, logins: [{ id: 'fixture-login', title: 'Fixture login' }] }));
  });
  try {
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const dataDirectory = path.join(f.homeDirectory, 'packaged desktop fixture');
    await mkdir(dataDirectory, { mode: 0o700 });
    const browserTokenFile = path.join(dataDirectory, 'browser-token');
    await writeFile(browserTokenFile, token, { mode: 0o600 });
    const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    await build({ stdin: { contents: 'import { runNativeHost } from "./packages/service/src/native-host.ts"; runNativeHost().catch(()=>process.exitCode=1);', resolveDir: sourceRoot, sourcefile: 'native-fixture-entry.ts' }, outfile: f.sourceHostFile, bundle: true, platform: 'node', target: 'node22', format: 'cjs', logLevel: 'silent' });
    const electronRuntime = createRequire(import.meta.url)('electron') as string;
    assert.ok(!electronRuntime.startsWith('/Applications/'));
    const result = await installServiceHost({ operations: [{ action: 'chrome', id: first }], sourceHostFile: f.sourceHostFile, runtimePath: electronRuntime, runAsNode: true, homeDirectory: f.homeDirectory, dataDirectory, port: address.port, browserTokenFile });
    const launcher = await readFile(result.executable, 'utf8');
    assert.ok(launcher.includes("exec /usr/bin/env 'ELECTRON_RUN_AS_NODE=1'"));
    await rm(path.dirname(path.dirname(f.sourceHostFile)), { recursive: true });
    const output = await sendNativeMessage(result.executable, `chrome-extension://${first}/`, { action: 'list', url: 'https://example.test/login' });
    assert.equal(output.readUInt32LE(0), output.length - 4);
    assert.deepEqual(JSON.parse(output.subarray(4).toString('utf8')), { ok: true, logins: [{ id: 'fixture-login', title: 'Fixture login' }] });
    assert.equal(requestCount, 1);
    await assert.rejects(sendNativeMessage(result.executable, `chrome-extension://${second}/`, { action: 'list' }), /exited with code 1/);
    assert.equal(requestCount, 1);
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
    await f.cleanup();
  }
});

test('desktop installer reads its bundled native host from an isolated Electron asar app', async () => {
  const f = await fixture();
  try {
    const staging = path.join(f.directory, 'packaged source');
    const appFile = path.join(f.directory, 'fixture.asar');
    await mkdir(staging, { mode: 0o700 });
    await writeFile(path.join(staging, 'package.json'), JSON.stringify({ name: 'jj-vault-installer-fixture', version: '1.0.0', main: 'main.cjs' }));
    await copyFile(f.sourceHostFile, path.join(staging, 'native-host.cjs'));
    const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const fixturePaths = { homeDirectory: f.homeDirectory, userData: path.join(f.directory, 'isolated electron data') };
    const contents = `
      import { app } from 'electron';
      import path from 'node:path';
      import { installBrowserHost } from './packages/service/src/browser-install.ts';
      const fixture = ${JSON.stringify(fixturePaths)};
      app.setPath('userData', fixture.userData);
      app.whenReady().then(async () => {
        const result = await installBrowserHost({ operations: [{ action: 'chrome', id: ${JSON.stringify(first)} }], sourceHostFile: path.join(__dirname, 'native-host.cjs'), runtimePath: process.execPath, runAsNode: true, homeDirectory: fixture.homeDirectory });
        process.stdout.write(JSON.stringify(result) + '\\n');
        app.exit(0);
      }).catch(error => { process.stderr.write(String(error)); app.exit(1); });
    `;
    await build({ stdin: { contents, resolveDir: sourceRoot, sourcefile: 'desktop-install-fixture.ts' }, outfile: path.join(staging, 'main.cjs'), bundle: true, platform: 'node', target: 'node22', format: 'cjs', external: ['electron'], logLevel: 'silent' });
    const asar = createRequire(import.meta.url)('@electron/asar') as { createPackage(source: string, destination: string): Promise<void> };
    await asar.createPackage(staging, appFile);
    const electronRuntime = createRequire(import.meta.url)('electron') as string;
    const environment = { ...process.env };
    delete environment.ELECTRON_RUN_AS_NODE;
    const execution = await run(electronRuntime, [appFile], { env: environment, timeout: 20000 });
    const result = JSON.parse(execution.stdout.trim()) as { executable: string; hostFile: string };
    assert.equal(await readFile(result.hostFile, 'utf8'), await readFile(f.sourceHostFile, 'utf8'));
    await rm(staging, { recursive: true }); await rm(appFile);
    const hostExecution = await run(result.executable, [`chrome-extension://${first}/`]);
    assert.deepEqual(JSON.parse(hostExecution.stdout), [`chrome-extension://${first}/`]);
  } finally { await f.cleanup(); }
});
