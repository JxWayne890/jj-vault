import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, copyFile, link, lstat, mkdir, mkdtemp, open, readFile, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { checkBrowserConnection, runCli } from './check-browser-connection.mjs';

const firstId = 'a'.repeat(32);
const secondId = 'b'.repeat(32);
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'jj-chrome-check-'));
  const homeDirectory = path.join(directory, "home with quote's");
  const support = path.join(homeDirectory, 'Library', 'Application Support');
  const extension = path.join(support, 'JJ Vault Browser', 'chrome');
  const app = path.join(support, 'JJ Vault');
  const nativeDirectory = path.join(support, 'Google', 'Chrome', 'NativeMessagingHosts');
  for (const folder of [extension, app, nativeDirectory]) await mkdir(folder, { mode: 0o700, recursive: true });
  const paths = {
    extensionManifest: path.join(extension, 'manifest.json'),
    backgroundBundle: path.join(extension, 'background.js'),
    contentBundle: path.join(extension, 'content.js'),
    popupBundle: path.join(extension, 'popup.js'),
    nativeManifest: path.join(nativeDirectory, 'com.john.jjvault.json'),
    pairingConfig: path.join(app, 'browser-host.json'),
    launcher: path.join(app, 'jjvault-browser-host'),
    nativeHost: path.join(app, 'native-host.cjs'),
    runtime: path.join(directory, "fake node's runtime"),
  };
  const manifest = { manifest_version: 3, name: 'JJ Vault', version: '0.1.0', permissions: ['activeTab', 'tabs', 'nativeMessaging'], background: { service_worker: 'background.js' }, action: { default_popup: 'popup.html' }, content_scripts: [{ matches: ['https://*/*'], js: ['content.js'] }] };
  const config = { port: 17373, browserTokenFile: path.join(app, 'browser-token'), chromeExtensionIds: [firstId] };
  const native = { name: 'com.john.jjvault', type: 'stdio', path: paths.launcher, allowed_origins: [`chrome-extension://${firstId}/`] };
  const writeJson = (filename, value) => writeFile(filename, JSON.stringify(value), { mode: 0o600 });
  await writeJson(paths.extensionManifest, manifest);
  await writeJson(paths.pairingConfig, config);
  await writeJson(paths.nativeManifest, native);
  for (const key of ['backgroundBundle', 'contentBundle', 'popupBundle', 'nativeHost']) await writeFile(paths[key], 'SYNTHETIC_DO_NOT_EXECUTE_OR_READ', { mode: 0o600 });
  await writeFile(paths.runtime, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  const launcher = runtime => `#!/bin/sh\nexec ${quote(runtime)} ${quote(paths.nativeHost)} "$@"\n`;
  const envLauncher = (runAsNode = false, environment = []) => `#!/bin/sh\nexec /usr/bin/env ${[...(runAsNode ? ['ELECTRON_RUN_AS_NODE=1'] : []), `JJ_VAULT_BROWSER_CONFIG=${paths.pairingConfig}`, ...environment, paths.runtime, paths.nativeHost].map(quote).join(' ')} "$@"\n`;
  await writeFile(paths.launcher, launcher(paths.runtime), { mode: 0o700 });
  return { directory, homeDirectory, extension, paths, manifest, config, native, writeJson, launcher, envLauncher, check: extra => checkBrowserConnection({ homeDirectory, ...extra }), cleanup: () => rm(directory, { force: true, recursive: true }) };
}
const status = (result, name) => result.checks.find(check => check.name === name)?.status;

test('complete fixture reports configured metadata while preserving live verification as false', async () => {
  const f = await fixture();
  try {
    const before = await lstat(f.paths.launcher);
    const result = await f.check();
    assert.equal(result.status, 'configured');
    assert.equal(result.failureCount, 0);
    assert.equal(result.checkedFileCount, 8);
    assert.equal(result.presentFileCount, 8);
    assert.equal(result.liveAutofillVerified, false);
    assert.deepEqual(result.metadata, { extensionVersion: '0.1.0', extensionPermissionCount: 3, contentScriptCount: 1, pairedChromeCount: 1, bridgePort: 17373, allowedChromeOriginCount: 1, runtimeAvailable: true });
    const after = await lstat(f.paths.launcher);
    assert.equal(after.mtimeMs, before.mtimeMs);
    assert.equal(after.mode, before.mode);
  } finally { await f.cleanup(); }
});

test('missing bridge files return incomplete and a failing CLI result', async () => {
  const f = await fixture();
  try {
    for (const key of ['nativeManifest', 'pairingConfig', 'launcher', 'nativeHost']) await rm(f.paths[key]);
    const result = await f.check();
    assert.equal(result.status, 'incomplete');
    assert.equal(result.presentFileCount, 4);
    for (const key of ['nativeManifest', 'pairingConfig', 'launcher', 'nativeHost']) assert.equal(status(result, key), 'missing');
    let output = '';
    assert.equal(await runCli(['--json'], { homeDirectory: f.homeDirectory }, { write: value => { output += value; } }), 1);
    assert.equal(JSON.parse(output).liveAutofillVerified, false);
  } finally { await f.cleanup(); }
});

test('only public metadata appears in output and secret files are never opened', async () => {
  const f = await fixture();
  try {
    f.config.extraPrivateField = 'PRIVATE_CONFIG_CANARY';
    await f.writeJson(f.paths.pairingConfig, f.config);
    f.manifest.description = 'PRIVATE_DESCRIPTION_CANARY';
    await f.writeJson(f.paths.extensionManifest, f.manifest);
    // These directories make accidental attempts to read a token or vault fail.
    await mkdir(f.config.browserTokenFile, { mode: 0o000 });
    await mkdir(path.join(path.dirname(f.paths.pairingConfig), 'vault.json'), { mode: 0o000 });
    let output = '';
    assert.equal(await runCli(['--json'], { homeDirectory: f.homeDirectory }, { write: value => { output += value; } }), 0);
    for (const forbidden of ['PRIVATE_', 'SYNTHETIC_', 'browserTokenFile', f.homeDirectory, firstId]) assert.equal(output.includes(forbidden), false);
  } finally { await f.cleanup(); }
});

test('symbolic files, hard links, and symbolic support directories are rejected', async () => {
  const f = await fixture();
  try {
    await rm(f.paths.pairingConfig);
    await symlink(f.paths.nativeHost, f.paths.pairingConfig);
    assert.equal(status(await f.check(), 'pairingConfig'), 'unsafe');
    await rm(f.paths.pairingConfig);
    await link(f.paths.nativeHost, f.paths.pairingConfig);
    assert.equal(status(await f.check(), 'pairingConfig'), 'unsafe');
    await rm(f.paths.pairingConfig);
    const library = path.join(f.homeDirectory, 'Library');
    const moved = path.join(f.directory, 'elsewhere');
    const { rename } = await import('node:fs/promises');
    await rename(library, moved);
    await symlink(moved, library);
    assert.equal(status(await f.check(), 'extensionManifest'), 'unsafe');
  } finally { await f.cleanup(); }
});

test('unsafe modes, wrong owners, and nonexecutable launchers are rejected', async () => {
  const f = await fixture();
  try {
    await chmod(f.paths.pairingConfig, 0o644);
    assert.equal(status(await f.check(), 'pairingConfig'), 'unsafe');
    await chmod(f.paths.pairingConfig, 0o600);
    await chmod(f.paths.launcher, 0o600);
    assert.equal(status(await f.check(), 'launcher'), 'unsafe');
    if (process.getuid) assert.equal(status(await f.check({ expectedUid: process.getuid() + 1 }), 'extensionManifest'), 'unsafe');
    await chmod(path.dirname(f.paths.nativeHost), 0o777);
    assert.equal(status(await f.check(), 'nativeHost'), 'unsafe');
  } finally { await f.cleanup(); }
});

test('malformed and oversized public JSON fails without exposing its contents', async () => {
  const f = await fixture();
  try {
    for (const contents of ['{PRIVATE_MALFORMED', '[]', 'null', ' '.repeat(65_537)]) {
      await writeFile(f.paths.extensionManifest, contents);
      const result = await f.check();
      assert.ok(['invalid', 'oversized'].includes(status(result, 'extensionContract')));
      assert.equal(JSON.stringify(result).includes('PRIVATE_MALFORMED'), false);
    }
  } finally { await f.cleanup(); }
});

test('Darwin refuses dataless metadata before opening or parsing its contents', { skip: process.platform !== 'darwin', timeout: 5_000 }, async () => {
  const f = await fixture();
  try {
    await rm(f.paths.extensionManifest);
    const handle = await open(f.paths.extensionManifest, 'wx', 0o600);
    try { await handle.truncate(1_024); } finally { await handle.close(); }
    const sparse = await lstat(f.paths.extensionManifest);
    assert.equal(sparse.blocks, 0, 'Fixture must have no allocated data blocks');
    let output = '';
    assert.equal(await runCli(['--json'], { homeDirectory: f.homeDirectory }, { write: value => { output += value; } }), 1);
    // Reading the zero filled sparse file would instead produce invalid JSON.
    assert.equal(status(JSON.parse(output), 'extensionContract'), 'offloaded');
  } finally { await f.cleanup(); }
});

test('Chrome ID validation rejects invalid, empty, and duplicate pairing IDs', async () => {
  const f = await fixture();
  try {
    for (const ids of [[], ['q'.repeat(32)], [firstId, firstId], ['../secret'], 'not an array']) {
      await f.writeJson(f.paths.pairingConfig, { ...f.config, chromeExtensionIds: ids });
      assert.equal(status(await f.check(), 'pairingContract'), 'invalid');
    }
    await f.writeJson(f.paths.pairingConfig, { ...f.config, browserTokenFile: '/outside/browser-token' });
    assert.equal(status(await f.check(), 'pairingContract'), 'invalid');
    await f.writeJson(f.paths.pairingConfig, { ...f.config, port: 65536 });
    assert.equal(status(await f.check(), 'pairingContract'), 'invalid');
  } finally { await f.cleanup(); }
});

test('native manifest requires exact IDs, origin syntax, host name, and launcher path', async () => {
  const f = await fixture();
  try {
    for (const patch of [
      { allowed_origins: ['chrome-extension://*/'] },
      { allowed_origins: [`chrome-extension://${firstId}/extra`] },
      { allowed_origins: [`chrome-extension://${secondId}/`] },
      { allowed_origins: [`chrome-extension://${firstId}/`, `chrome-extension://${firstId}/`] },
      { name: 'other.host' }, { type: 'other' }, { path: '/outside/host' },
    ]) {
      await f.writeJson(f.paths.nativeManifest, { ...f.native, ...patch });
      assert.equal(status(await f.check(), 'nativeManifestContract'), 'invalid');
    }
    await f.writeJson(f.paths.pairingConfig, { ...f.config, chromeExtensionIds: [firstId, secondId] });
    await f.writeJson(f.paths.nativeManifest, { ...f.native, allowed_origins: [`chrome-extension://${secondId}/`, `chrome-extension://${firstId}/`] });
    assert.equal(status(await f.check(), 'nativeManifestContract'), 'ok');
  } finally { await f.cleanup(); }
});

test('extension contract validates expected public entry points and native permission', async () => {
  const f = await fixture();
  try {
    for (const patch of [{ manifest_version: 2 }, { version: 'PRIVATE_VERSION_CANARY' }, { permissions: ['tabs'] }, { background: { service_worker: '../background.js' } }, { action: { default_popup: '/other/popup.html' } }, { content_scripts: [] }]) {
      await f.writeJson(f.paths.extensionManifest, { ...f.manifest, ...patch });
      assert.equal(status(await f.check(), 'extensionContract'), 'invalid');
    }
  } finally { await f.cleanup(); }
});

test('launcher parsing accepts installer quoting and refuses alternate scripts or targets', async () => {
  const f = await fixture();
  try {
    assert.equal(status(await f.check(), 'launcherContract'), 'ok');
    for (const contents of [
      '#!/bin/sh\necho PRIVATE_CANARY\n',
      f.launcher(f.paths.runtime) + 'echo extra\n',
      `#!/bin/sh\nexec ${quote(f.paths.runtime)} '/outside/native-host.cjs' "$@"\n`,
      f.launcher(path.join(f.directory, 'missing runtime')),
      f.launcher('relative-node'),
    ]) {
      await writeFile(f.paths.launcher, contents);
      assert.notEqual(status(await f.check(), 'launcherContract'), 'ok');
    }
    assert.equal((await readFile(f.paths.runtime, 'utf8')).includes('exit 99'), true);
  } finally { await f.cleanup(); }
});

test('Node and Electron env launchers require the exact config and permitted environment', async () => {
  const f = await fixture();
  try {
    for (const runAsNode of [false, true]) {
      await writeFile(f.paths.launcher, f.envLauncher(runAsNode));
      assert.equal((await f.check()).status, 'configured');
    }
    const configWord = quote(`JJ_VAULT_BROWSER_CONFIG=${f.paths.pairingConfig}`);
    for (const contents of [
      f.envLauncher().replace(configWord, quote('JJ_VAULT_BROWSER_CONFIG=/outside/browser-host.json')),
      f.envLauncher(true).replace(quote('ELECTRON_RUN_AS_NODE=1'), quote('ELECTRON_RUN_AS_NODE=0')),
      f.envLauncher(false, ['NODE_OPTIONS=--require /outside/other.cjs']),
      f.envLauncher(false, ['JJ_VAULT_BROWSER_CONFIG=/outside/browser-host.json']),
      f.envLauncher(true).replace(`${quote('ELECTRON_RUN_AS_NODE=1')} ${configWord}`, `${configWord} ${quote('ELECTRON_RUN_AS_NODE=1')}`),
      f.envLauncher().replace('/usr/bin/env', '/bin/env'),
    ]) {
      await writeFile(f.paths.launcher, contents);
      assert.equal(status(await f.check(), 'launcherContract'), 'invalid');
    }
  } finally { await f.cleanup(); }
});

test('explicit source extension directory accepts safe public build files within the home', async () => {
  const f = await fixture();
  try {
    const extensionDirectory = path.join(f.homeDirectory, 'source checkout', 'dist', 'extensions', 'chrome');
    await mkdir(path.dirname(extensionDirectory), { recursive: true, mode: 0o755 });
    await rename(f.extension, extensionDirectory);
    for (const filename of ['manifest.json', 'background.js', 'content.js', 'popup.js']) await chmod(path.join(extensionDirectory, filename), 0o644);
    let output = '';
    assert.equal(await runCli(['--extension-directory', extensionDirectory, '--json'], { homeDirectory: f.homeDirectory }, { write: value => { output += value; } }), 0);
    assert.equal(JSON.parse(output).status, 'configured');
    assert.equal(output.includes(extensionDirectory), false);
    await chmod(path.join(extensionDirectory, 'background.js'), 0o666);
    assert.equal(status(await f.check({ extensionDirectory }), 'backgroundBundle'), 'unsafe');
  } finally { await f.cleanup(); }
});

test('explicit extension directories cannot escape the home or follow symbolic directories', async () => {
  const f = await fixture();
  try {
    const linkDirectory = path.join(f.homeDirectory, 'linked extension');
    await symlink(f.extension, linkDirectory);
    assert.equal(status(await f.check({ extensionDirectory: linkDirectory }), 'extensionManifest'), 'unsafe');
    let output = '';
    assert.equal(await runCli(['--extension-directory', f.directory], { homeDirectory: f.homeDirectory }, { write: value => { output += value; } }), 2);
    assert.ok(output.includes('within your home'));
  } finally { await f.cleanup(); }
});

test('runtime checks allow a safe symlink and reject writable or nonexecutable targets', async () => {
  const f = await fixture();
  try {
    const runtimeLink = path.join(f.directory, 'node');
    await symlink(f.paths.runtime, runtimeLink);
    await writeFile(f.paths.launcher, f.launcher(runtimeLink));
    assert.equal(status(await f.check(), 'launcherContract'), 'ok');
    await chmod(f.paths.runtime, 0o777);
    assert.equal(status(await f.check(), 'launcherContract'), 'unsafe');
    await chmod(f.paths.runtime, 0o600);
    assert.equal(status(await f.check(), 'launcherContract'), 'unsafe');
  } finally { await f.cleanup(); }
});

test('CLI help and invalid arguments do not inspect the real home', async () => {
  let output = '';
  const sink = { write: value => { output += value; } };
  assert.equal(await runCli(['--help'], { homeDirectory: '/path/that/must/not/be/read' }, sink), 0);
  assert.equal(await runCli(['--home', '/tmp'], {}, sink), 2);
  for (const args of [['--extension-directory'], ['--extension-directory', '--json'], ['--extension-directory', '/tmp\nother'], ['--extension-directory', '/tmp', '--extension-directory', '/tmp']]) {
    assert.equal(await runCli(args, { homeDirectory: '/path/that/must/not/be/read' }, sink), 2);
  }
  assert.ok(output.includes('Home and owner fixture paths are not accepted'));
});

test('diagnostic launches through a symbolic parent and does not run when imported', { timeout: 10_000 }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'jj-check-entrypoint-'));
  try {
    const realDirectory = path.join(directory, "owner's real folder");
    const aliasDirectory = path.join(directory, "owner's linked folder");
    await mkdir(realDirectory);
    await symlink(realDirectory, aliasDirectory);
    const filename = 'check-browser-connection.mjs';
    await copyFile(fileURLToPath(new URL('./check-browser-connection.mjs', import.meta.url)), path.join(realDirectory, filename));
    const alias = path.join(aliasDirectory, filename);
    assert.notEqual(path.resolve(alias), await realpath(alias));
    const execute = promisify(execFile);
    const direct = await execute(process.execPath, [alias, '--help'], { timeout: 5_000 });
    assert.match(direct.stdout, /Read only JJ Vault Chrome setup check/);
    assert.equal(direct.stderr, '');
    const wrapper = path.join(directory, filename);
    await writeFile(wrapper, `await import(${JSON.stringify(pathToFileURL(alias).href)}); process.stdout.write('imported only\\n');\n`);
    const imported = await execute(process.execPath, [wrapper, '--help'], { timeout: 5_000 });
    assert.equal(imported.stdout, 'imported only\n');
    assert.equal(imported.stderr, '');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
