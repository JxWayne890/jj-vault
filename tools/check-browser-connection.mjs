#!/usr/bin/env node
import { constants, realpathSync } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HOST = 'com.john.jjvault';
const ID = /^[a-p]{32}$/;
const MAX_JSON = 65_536;
const MAX_LAUNCHER = 16_384;
const SHELL_WORD = "'(?:[^']|'\\\\'')*'";
const LEGACY_LAUNCHER = new RegExp(`^#!/bin/sh\\nexec (${SHELL_WORD}) (${SHELL_WORD}) "\\$@"\\n$`);
const ENV_LAUNCHER = new RegExp(`^#!/bin/sh\\nexec /usr/bin/env (?:(${SHELL_WORD}) )?(${SHELL_WORD}) (${SHELL_WORD}) (${SHELL_WORD}) "\\$@"\\n$`);
const problem = code => Object.assign(new Error(code), { diagnosticCode: code });
const owned = (info, uid) => uid === undefined || info.uid === uid;

function requireFile(info, uid, privateMode, executable = false) {
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || !owned(info, uid)
    || (info.mode & (privateMode ? 0o077 : 0o022)) || (executable && !(info.mode & 0o100))) {
    throw problem('unsafe');
  }
}

// Walk only the exact expected support path. Never enumerate user files.
async function inspectFile(filename, home, uid, privateMode = true, executable = false) {
  const relative = path.relative(home, filename);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw problem('invalid');
  let current = home;
  for (const component of [null, ...relative.split(path.sep).slice(0, -1)]) {
    if (component !== null) current = path.join(current, component);
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink() || !owned(info, uid) || (info.mode & 0o022)) throw problem('unsafe');
  }
  const info = await lstat(filename);
  requireFile(info, uid, privateMode, executable);
  return info;
}

// Refuse links, oversized files, and replacements before parsing public metadata.
async function readBounded(filename, info, maximum, uid, privateMode) {
  // A nonempty dataless iCloud file can block on open even with a tiny read.
  // Sparse metadata is conservatively unavailable too. Never hydrate it here.
  if (process.platform === 'darwin' && info.size > 0 && info.blocks === 0) throw problem('offloaded');
  if (info.size > maximum) throw problem('oversized');
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    requireFile(before, uid, privateMode);
    if (before.dev !== info.dev || before.ino !== info.ino || before.size > maximum) throw problem('unsafe');
    const buffer = Buffer.alloc(maximum + 1);
    let size = 0;
    while (size <= maximum) {
      const { bytesRead } = await handle.read(buffer, size, maximum + 1 - size, null);
      if (!bytesRead) break;
      size += bytesRead;
    }
    const after = await handle.stat();
    if (size > maximum || after.size > maximum) throw problem('oversized');
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw problem('unsafe');
    return buffer.subarray(0, size).toString('utf8');
  } finally { await handle.close(); }
}

function jsonObject(value) {
  let result;
  try { result = JSON.parse(value); } catch { throw problem('invalid'); }
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw problem('invalid');
  return result;
}

function chromeIds(values) {
  if (!Array.isArray(values) || values.length === 0 || values.some(value => typeof value !== 'string' || !ID.test(value))
    || new Set(values).size !== values.length) throw problem('invalid');
  return values;
}

function decodeShellWord(value) { return value.slice(1, -1).replaceAll("'\\''", "'"); }

function launcherRuntime(contents, app) {
  const legacy = LEGACY_LAUNCHER.exec(contents);
  if (legacy) {
    if (decodeShellWord(legacy[2]) !== path.join(app, 'native-host.cjs')) throw problem('invalid');
    return decodeShellWord(legacy[1]);
  }
  const environment = ENV_LAUNCHER.exec(contents);
  if (!environment || (environment[1] && decodeShellWord(environment[1]) !== 'ELECTRON_RUN_AS_NODE=1')
    || decodeShellWord(environment[2]) !== `JJ_VAULT_BROWSER_CONFIG=${path.join(app, 'browser-host.json')}`
    || decodeShellWord(environment[4]) !== path.join(app, 'native-host.cjs')) throw problem('invalid');
  return decodeShellWord(environment[3]);
}

async function inspectRuntime(filename, uid) {
  if (!path.isAbsolute(filename) || filename.includes('\0') || filename.includes('\n')) throw problem('invalid');
  // Homebrew commonly uses a symlink for Node. Check its resolved binary and
  // every containing directory without opening or running the executable.
  const resolved = await realpath(filename);
  for (const candidate of new Set([filename, resolved])) {
    const components = candidate.split(path.sep).filter(Boolean);
    let current = path.parse(candidate).root;
    for (const component of components) {
      current = path.join(current, component);
      const info = await lstat(current);
      const protectedTemporaryDirectory = info.isDirectory() && info.uid === 0 && (info.mode & 0o1000);
      if ((uid !== undefined && info.uid !== uid && info.uid !== 0)
        || (!info.isSymbolicLink() && (info.mode & 0o022) && !protectedTemporaryDirectory)) throw problem('unsafe');
      if (current === candidate && !info.isSymbolicLink() && (!info.isFile() || !(info.mode & 0o111))) throw problem('unsafe');
    }
  }
  const info = await lstat(resolved);
  if (!info.isFile() || info.isSymbolicLink() || !(info.mode & 0o111)) throw problem('unsafe');
}

/** Read only. Home and owner fixture overrides are never command line flags. */
export async function checkBrowserConnection(options = {}) {
  const home = path.resolve(options.homeDirectory ?? os.homedir());
  const uid = options.expectedUid ?? (process.getuid ? process.getuid() : undefined);
  const support = path.join(home, 'Library', 'Application Support');
  const extension = path.resolve(options.extensionDirectory ?? path.join(support, 'JJ Vault Browser', 'chrome'));
  const app = path.join(support, 'JJ Vault');
  const files = [
    ['extensionManifest', path.join(extension, 'manifest.json')],
    ['backgroundBundle', path.join(extension, 'background.js')],
    ['contentBundle', path.join(extension, 'content.js')],
    ['popupBundle', path.join(extension, 'popup.js')],
    ['nativeManifest', path.join(support, 'Google', 'Chrome', 'NativeMessagingHosts', `${HOST}.json`)],
    ['pairingConfig', path.join(app, 'browser-host.json')],
    ['launcher', path.join(app, 'jjvault-browser-host')],
    ['nativeHost', path.join(app, 'native-host.cjs')],
  ];
  const checks = [];
  const metadata = {};
  const inspected = new Map();
  const record = (name, status) => checks.push({ name, status });
  async function check(name, operation) {
    try { await operation(); record(name, 'ok'); }
    catch (error) { record(name, error?.code === 'ENOENT' ? 'missing' : error?.diagnosticCode ?? 'unreadable'); }
  }
  for (const [name, filename] of files) {
    await check(name, async () => {
      const privateMode = !['extensionManifest', 'backgroundBundle', 'contentBundle', 'popupBundle'].includes(name);
      const info = await inspectFile(filename, home, uid, privateMode, name === 'launcher');
      if (info.size === 0) throw problem('invalid');
      inspected.set(name, { filename, info, privateMode });
    });
  }
  async function read(name, maximum = MAX_JSON) {
    const file = inspected.get(name);
    if (!file) throw problem('dependency');
    return readBounded(file.filename, file.info, maximum, uid, file.privateMode);
  }
  await check('extensionContract', async () => {
    const manifest = jsonObject(await read('extensionManifest'));
    if (manifest.manifest_version !== 3 || manifest.name !== 'JJ Vault' || !/^\d+\.\d+\.\d+(?:\.\d+)?$/.test(manifest.version)
      || manifest.background?.service_worker !== 'background.js' || manifest.action?.default_popup !== 'popup.html'
      || !Array.isArray(manifest.permissions) || !manifest.permissions.includes('nativeMessaging')
      || manifest.permissions.some(value => typeof value !== 'string' || !/^[A-Za-z]+$/.test(value))
      || !Array.isArray(manifest.content_scripts) || !manifest.content_scripts.some(script => Array.isArray(script.js) && script.js.includes('content.js'))) throw problem('invalid');
    metadata.extensionVersion = manifest.version;
    metadata.extensionPermissionCount = manifest.permissions.length;
    metadata.contentScriptCount = manifest.content_scripts.length;
  });
  let pairedIds;
  await check('pairingContract', async () => {
    const config = jsonObject(await read('pairingConfig'));
    pairedIds = chromeIds(config.chromeExtensionIds);
    if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535
      || config.browserTokenFile !== path.join(app, 'browser-token')) throw problem('invalid');
    metadata.pairedChromeCount = pairedIds.length;
    metadata.bridgePort = config.port;
  });
  await check('nativeManifestContract', async () => {
    const manifest = jsonObject(await read('nativeManifest'));
    if (manifest.name !== HOST || manifest.type !== 'stdio' || manifest.path !== path.join(app, 'jjvault-browser-host')
      || !Array.isArray(manifest.allowed_origins) || manifest.allowed_origins.length === 0) throw problem('invalid');
    const ids = manifest.allowed_origins.map(origin => {
      if (typeof origin !== 'string' || !/^chrome-extension:\/\/[a-p]{32}\/$/.test(origin)) throw problem('invalid');
      return origin.slice('chrome-extension://'.length, -1);
    });
    chromeIds(ids);
    if (!pairedIds) throw problem('dependency');
    if (ids.length !== pairedIds.length || ids.some(id => !pairedIds.includes(id))) throw problem('invalid');
    metadata.allowedChromeOriginCount = ids.length;
  });
  await check('launcherContract', async () => {
    const runtime = launcherRuntime(await read('launcher', MAX_LAUNCHER), app);
    await inspectRuntime(runtime, uid);
    metadata.runtimeAvailable = true;
  });
  const failureCount = checks.filter(check => check.status !== 'ok').length;
  return {
    status: failureCount === 0 ? 'configured' : 'incomplete',
    liveAutofillVerified: false,
    checkedFileCount: files.length,
    presentFileCount: inspected.size,
    failureCount,
    metadata,
    checks,
  };
}

export async function runCli(args, options = {}, output = process.stdout) {
  if (args.includes('--help')) {
    output.write('Read only JJ Vault Chrome setup check. No tokens, vaults, or saved logins are opened.\nUsage: node tools/check-browser-connection.mjs [--json] [--extension-directory DIRECTORY]\nThe extension directory must be within your home and contain real owner controlled files.\nConfigured means installation metadata passes. A live Chrome fill is a separate check.\n');
    return 0;
  }
  let extensionDirectory = options.extensionDirectory;
  let suppliedExtension = false;
  let json = false;
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--json') json = true;
    else if (args[index] === '--extension-directory' && !suppliedExtension) {
      const value = args[++index];
      if (!value || value.startsWith('--') || /[\0\r\n]/.test(value)) {
        output.write('Choose an extension directory. Use --help.\n');
        return 2;
      }
      extensionDirectory = path.resolve(value);
      suppliedExtension = true;
    } else {
      output.write('Unknown argument. Use --help. Home and owner fixture paths are not accepted as command line arguments.\n');
      return 2;
    }
  }
  if (extensionDirectory) {
    const relative = path.relative(path.resolve(options.homeDirectory ?? os.homedir()), path.resolve(extensionDirectory));
    if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      output.write('The extension directory must be within your home folder.\n');
      return 2;
    }
  }
  const result = await checkBrowserConnection({ ...options, extensionDirectory });
  if (json) output.write(`${JSON.stringify(result, null, 2)}\n`);
  else {
    output.write(`JJ Vault Chrome setup: ${result.status}. ${result.presentFileCount}/${result.checkedFileCount} files passed safety checks.\n`);
    if (result.metadata.extensionVersion) output.write(`Extension version ${result.metadata.extensionVersion}.\n`);
    if (result.metadata.pairedChromeCount) output.write(`Paired Chrome extensions: ${result.metadata.pairedChromeCount}.\n`);
    for (const check of result.checks.filter(check => check.status !== 'ok')) output.write(`${check.name}: ${check.status}.\n`);
    output.write('Live Chrome autofill remains unverified by this read only check.\n');
  }
  return result.failureCount ? 1 : 0;
}

function isDirectExecution() {
  if (!process.argv[1]) return false;
  try { return realpathSync(path.resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url)); }
  catch { return false; }
}

if (isDirectExecution()) {
  runCli(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(() => {
    process.stderr.write('Chrome setup check could not complete. No secrets are included in diagnostic output.\n');
    process.exitCode = 1;
  });
}
