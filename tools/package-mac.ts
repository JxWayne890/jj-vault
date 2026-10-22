import { spawn, execFileSync } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, rm, writeFile, readdir, open, rename, lstat, symlink } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { _electron as electron } from '@playwright/test';
import { resolvePackageOptions } from './package-options.ts';

// Reject invalid options before inspecting inputs, generating files, or replacing an app.
const { stageOnly, signingIdentity, entitlements, signingStatus } = resolvePackageOptions(
  process.argv.slice(2), process.env,
  () => execFileSync('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning'], { encoding: 'utf8' }),
);
const root = process.cwd();
const finalAppPath = path.join(root, 'release', 'mac-arm64', 'JJ Vault.app');
const installedAppPath = path.join(homedir(), 'Applications', 'JJ Vault.app');
function run(command: string, args: string[], env = process.env): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, env, stdio: ['ignore', 'inherit', 'inherit'] });
    child.once('error', reject); child.once('exit', code => code === 0 ? resolve() : reject(new Error(`${path.basename(command)} exited with ${code}`)));
  });
}
async function writeGeneratedFile(file: string, contents: string | Uint8Array): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}-${Date.now()}`;
  try { await writeFile(temporary, contents, { flag: 'wx' }); await rename(temporary, file); }
  finally { await rm(temporary, { force: true }); }
}
if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('This packaging target requires an Apple silicon Mac.');
await access('dist/desktop/main.cjs'); await access('apple/build/JJBiometric');
const stagingBase = path.join(homedir(), '.cache', 'jj-vault-build'); await mkdir(stagingBase, { recursive: true });
const stagingDirectory = await mkdtemp(path.join(stagingBase, 'package-'));
let appPath = path.join(stagingDirectory, 'mac-arm64', 'JJ Vault.app');
await run('/usr/bin/swift', ['assets/render-icon.swift', path.join(root, 'assets', 'icon.png')]);
const iconset = await mkdtemp(path.join(tmpdir(), 'jjvault-icon-'));
const iconDirectory = path.join(iconset, 'JJVault.iconset'); await mkdir(iconDirectory);
try {
  for (const size of [16, 32, 128, 256, 512]) {
    await run('/usr/bin/sips', ['-z', String(size), String(size), 'assets/icon.png', '--out', path.join(iconDirectory, `icon_${size}x${size}.png`)]);
    await run('/usr/bin/sips', ['-z', String(size * 2), String(size * 2), 'assets/icon.png', '--out', path.join(iconDirectory, `icon_${size}x${size}@2x.png`)]);
  }
  const nativeIcon = path.join(iconset, 'icon.icns');
  await run('/usr/bin/iconutil', ['-c', 'icns', iconDirectory, '-o', nativeIcon]);
  await rename(nativeIcon, path.join(root, 'assets', 'icon.icns'));
} finally { await rm(iconset, { recursive: true, force: true }); }
const configuration = {
  appId: 'com.john.jjvault', productName: 'JJ Vault', asar: true, npmRebuild: false,
  electronDist: path.join(root, 'node_modules', 'electron', 'dist'),
  directories: { output: stagingDirectory },
  extraMetadata: { main: 'dist/desktop/main.cjs' },
  files: ['dist/**/*', 'package.json', '!node_modules/**/*'],
  extraResources: [{ from: 'apple/build/JJBiometric', to: 'JJBiometric' }],
  mac: { category: 'public.app-category.utilities', icon: 'assets/icon.icns', identity: null, hardenedRuntime: true, notarize: false, extendInfo: { NSLocalNetworkUsageDescription: 'Allow your iPhone to connect to JJ Vault on this Mac for encrypted local network sync.' } },
};
const configurationPath = path.join(stagingDirectory, 'local-package-config.json'); await writeFile(configurationPath, JSON.stringify(configuration, null, 2));
await run(process.execPath, ['node_modules/electron-builder/out/cli/cli.js', '--mac', 'dir', '--arm64', '--publish', 'never', '--config', configurationPath], { ...process.env, CSC_IDENTITY_AUTO_DISCOVERY: 'false' });
// Clear build output metadata, then sign nested code in Apple's required order.
// Resource packs stay covered by the framework resource seal and are not signed individually.
await run('/usr/bin/xattr', ['-cr', appPath]);
const macho: string[] = []; const frameworks: string[] = []; const nestedApps: string[] = [];
async function visit(directory: string): Promise<void> {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) { if (entry.name.endsWith('.framework')) frameworks.push(file); if (entry.name.endsWith('.app')) nestedApps.push(file); await visit(file); }
    else if (entry.isFile() && !entry.name.endsWith('.pak')) {
      const handle = await open(file, 'r'); const bytes = Buffer.alloc(4);
      try { const { bytesRead } = await handle.read(bytes, 0, 4, 0); if (bytesRead === 4 && [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].includes(bytes.readUInt32BE())) macho.push(file); } finally { await handle.close(); }
    }
  }
}
await visit(appPath);
const deepest = (a: string, b: string) => b.split(path.sep).length - a.split(path.sep).length;
async function sign(file: string, withEntitlements = false) { await run('/usr/bin/codesign', ['--force', '--sign', signingIdentity, '--timestamp=none', '--options', 'runtime', ...(path.basename(file) === 'JJBiometric' ? ['--identifier', 'com.john.jjvault.biometric'] : []), ...(withEntitlements ? ['--entitlements', path.join(root, entitlements)] : []), file]); }
for (const file of macho.sort(deepest)) await sign(file);
for (const file of frameworks.sort(deepest)) await sign(file);
for (const file of nestedApps.sort(deepest)) await sign(file, true);
await sign(appPath, true);
await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', appPath]);
if (!stageOnly) {
  await mkdir(path.dirname(installedAppPath), { recursive: true });
  try { await lstat(installedAppPath); await rename(installedAppPath, path.join(path.dirname(installedAppPath), `JJ Vault.previous.${Date.now()}.app`)); } catch (error: any) { if (error.code !== 'ENOENT') throw error; }
  await rename(appPath, installedAppPath); appPath = installedAppPath;
  await run('/usr/bin/xattr', ['-cr', appPath]);
  await mkdir(path.dirname(finalAppPath), { recursive: true }); await rm(finalAppPath, { recursive: true, force: true }); await symlink(installedAppPath, finalAppPath, 'dir');
  await rm(stagingDirectory, { recursive: true, force: true });
  await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', appPath]);
}
const dataDirectory = await mkdtemp(path.join(tmpdir(), 'jjvault-packaged-smoke-'));
const errors: string[] = [];
const running = await electron.launch({ executablePath: path.join(appPath, 'Contents', 'MacOS', 'JJ Vault'), args: ['--use-mock-keychain'], env: { ...process.env, JJ_VAULT_DATA_DIR: dataDirectory, JJ_VAULT_PORT: '0', JJ_VAULT_REMEMBER_SECRET: '0' }, timeout: 45000 });
try {
  const page = await running.firstWindow(); page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('heading', { name: 'Make yourself at home' }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Create JJ Vault', exact: true }).count(), 1);
  const state = await page.evaluate(() => (window as any).vault.invoke('state'));
  assert.equal(state.initialized, false); assert.equal(state.locked, true); assert(state.servicePort > 0);
  assert.equal(state.hasRememberedSecretKey, false);
  await assert.rejects(readFile(path.join(dataDirectory, 'vault.json')));
  assert.deepEqual(errors, []);
  await writeGeneratedFile(stageOnly ? 'output/qa/mac-packaged-staged.png' : 'output/qa/mac-packaged-ready.png', await page.screenshot());
} finally { await running.close(); await rm(dataDirectory, { recursive: true, force: true }); }
await run('/usr/bin/xattr', ['-cr', appPath]);
await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', appPath]);
await run('/usr/bin/codesign', ['--verify', '--strict', path.join(appPath, 'Contents', 'Resources', 'JJBiometric')]);
if (stageOnly) {
  const result = { stagedAppPath: appPath, signingStatus, notarized: false, startupVerified: true, userVaultCreated: false, rememberedSecretStorageEnabledDuringSmoke: false, createdAt: new Date().toISOString() };
  await writeGeneratedFile('release/STAGED-PACKAGE-STATUS.json', JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result));
} else {
  await writeGeneratedFile('release/PACKAGE-STATUS.txt', `JJ Vault local Apple silicon build\n${signingStatus} Not notarized.\nInstalled at ${installedAppPath}. Release path is a symlink to the stable local app.\nPackaged startup verified with an isolated temporary directory. No user vault was created.\nThe complete editable source remains in the project directory.\n`);
  console.log(`Packaged and verified: ${appPath}`);
}
