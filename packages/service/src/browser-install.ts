import { constants } from 'node:fs';
import { access, chmod, lstat, mkdir, open, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { requireStrongToken } from './security.ts';

const HOST = 'com.john.jjvault';
const CHROME_ID = /^[a-p]{32}$/;
export type BrowserInstallOperation = { action: 'chrome' | 'removeChrome' | 'firefox' | 'removeFirefox'; id: string };
export interface BrowserInstallOptions {
  operations: BrowserInstallOperation[];
  /** An explicit bundle and runtime work in both a source checkout and a packaged app. */
  sourceHostFile: string;
  runtimePath: string;
  /** Electron's executable can act as Node without requiring a separate Node installation. */
  runAsNode?: boolean;
  homeDirectory?: string;
  dataDirectory?: string;
  port?: number;
  browserTokenFile?: string;
}
export interface BrowserInstallResult {
  chromeCount: number;
  firefoxCount: number;
  executable: string;
  hostFile: string;
  nodePath: string;
  configFile: string;
}

function quote(value: string) { return `'${value.replaceAll("'", "'\\''")}'`; }
function absolutePath(value: string, label: string) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || /[\0\r\n]/.test(value)) throw new Error(`${label} must be an absolute local path.`);
  return path.resolve(value);
}
async function optionalInfo(filename: string) {
  try { return await lstat(filename); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
}
function requireOwnerFile(info: NonNullable<Awaited<ReturnType<typeof optionalInfo>>>, label: string, privateMode = true) {
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (process.getuid && info.uid !== process.getuid()) || (info.mode & (privateMode ? 0o077 : 0o022))) throw new Error(`${label} must be a regular owner controlled file with safe permissions.`);
}
function requireOwnerDirectory(info: NonNullable<Awaited<ReturnType<typeof optionalInfo>>>) {
  if (!info.isDirectory() || info.isSymbolicLink() || (process.getuid && info.uid !== process.getuid()) || (info.mode & 0o022)) throw new Error('Browser support folders must be real owner controlled directories.');
}
async function safeDirectory(base: string, relative: string) {
  let current = base;
  requireOwnerDirectory(await lstat(base));
  for (const component of relative.split(path.sep).filter(Boolean)) {
    if (component === '..' || component === '.') throw new Error('Invalid browser support folder.');
    current = path.join(current, component);
    await mkdir(current, { mode: 0o700 }).catch(error => { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; });
    requireOwnerDirectory(await lstat(current));
  }
  return current;
}
async function safeDataDirectory(home: string, directory: string) {
  const relative = path.relative(home, directory);
  if (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)) return safeDirectory(home, relative);
  // A custom location can be outside the home folder. Its ancestors must
  // remain controlled by this user or the operating system.
  let current = path.parse(directory).root;
  for (const component of directory.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    await mkdir(current, { mode: 0o700 }).catch(error => { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; });
    let info = await lstat(current);
    if (info.isSymbolicLink()) {
      // macOS uses protected root owned aliases such as /var and /tmp.
      if (info.uid !== 0 || current === directory) throw new Error('Browser support folders must be real owner controlled directories.');
      info = await lstat(await realpath(current));
    }
    const protectedTemporary = info.uid === 0 && Boolean(info.mode & 0o1000);
    if (!info.isDirectory() || (process.getuid && info.uid !== process.getuid() && info.uid !== 0) || ((info.mode & 0o022) && !protectedTemporary)) throw new Error('Browser support folders must be real owner controlled directories.');
  }
  requireOwnerDirectory(await lstat(directory));
  return directory;
}
async function readChecked(filename: string, info: NonNullable<Awaited<ReturnType<typeof optionalInfo>>>, label: string, privateMode = true, maxBytes?: number) {
  requireOwnerFile(info, label, privateMode);
  if (maxBytes !== undefined && info.size > maxBytes) throw new Error(`${label} is too large.`);
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const current = await handle.stat();
    requireOwnerFile(current, label, privateMode);
    if (current.dev !== info.dev || current.ino !== info.ino || (maxBytes !== undefined && current.size > maxBytes)) throw new Error(`${label} changed during installation.`);
    const data = await handle.readFile();
    if (maxBytes !== undefined && data.length > maxBytes) throw new Error(`${label} is too large.`);
    return data;
  } finally { await handle.close(); }
}
async function readHostContents(filename: string, info: NonNullable<Awaited<ReturnType<typeof optionalInfo>>>) {
  const archive = process.versions.electron ? /^(.+?\.asar)[\\/]/.exec(filename)?.[1] : undefined;
  if (!archive) return readChecked(filename, info, 'Built browser host', false);
  // Electron exposes virtual file stats inside asar, but open/fstat refers to
  // its extracted copy. Verify the owner and identity of the containing archive.
  requireOwnerFile(info, 'Built browser host', false);
  const originalFS = createRequire(process.execPath)('original-fs') as typeof import('node:fs');
  const before = await originalFS.promises.lstat(archive);
  requireOwnerFile(before, 'Bundled browser host archive', false);
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    requireOwnerFile(await handle.stat(), 'Built browser host', false);
    const data = await handle.readFile();
    const after = await originalFS.promises.lstat(archive);
    requireOwnerFile(after, 'Bundled browser host archive', false);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || data.length !== info.size) throw new Error('Built browser host changed during installation.');
    return data;
  } finally { await handle.close(); }
}
async function secureWrite(filename: string, contents: string | Buffer, mode = 0o600) {
  const temporary = `${filename}.${randomUUID()}.tmp`;
  try {
    const info = await optionalInfo(filename);
    if (info) requireOwnerFile(info, 'Existing browser setup file');
    await writeFile(temporary, contents, { mode, flag: 'wx' });
    await chmod(temporary, mode);
    await rename(temporary, filename);
  } finally { await rm(temporary, { force: true }); }
}
async function removeOwnFile(filename: string) {
  const info = await optionalInfo(filename);
  if (info) { requireOwnerFile(info, 'Existing browser manifest'); await rm(filename); }
}
function ids(value: unknown, kind: 'chrome' | 'firefox' | 'safari'): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some(id => typeof id !== 'string' || (kind === 'chrome' ? !CHROME_ID.test(id) : !/^[A-Za-z0-9@._{}-]{3,200}$/.test(id)))) throw new Error('Browser pairing config contains invalid extension IDs.');
  return value;
}
function validateOperations(operations: BrowserInstallOperation[]) {
  if (!Array.isArray(operations) || !operations.length) throw new Error('Choose a browser to pair or remove.');
  for (const operation of operations) {
    if (!operation || !['chrome', 'removeChrome', 'firefox', 'removeFirefox'].includes(operation.action)) throw new Error('Unknown browser setup operation.');
    ids([operation.id], operation.action === 'chrome' || operation.action === 'removeChrome' ? 'chrome' : 'firefox');
  }
}

/** Install only native messaging metadata and a private copy of the built bridge. */
export async function installBrowserHost(options: BrowserInstallOptions): Promise<BrowserInstallResult> {
  if (process.platform !== 'darwin') throw new Error('This installer currently supports macOS.');
  validateOperations(options.operations);
  const home = absolutePath(options.homeDirectory ?? os.homedir(), 'Home folder');
  const sourceHostFile = absolutePath(options.sourceHostFile, 'Built browser host');
  const nodePath = absolutePath(options.runtimePath, 'Browser host runtime');
  const sourceInfo = await optionalInfo(sourceHostFile);
  if (!sourceInfo) throw new Error('Build JJ Vault first with npm run build.');
  const hostContents = await readHostContents(sourceHostFile, sourceInfo);
  const runtimeInfo = await lstat(await realpath(nodePath));
  if (!runtimeInfo.isFile() || (runtimeInfo.mode & 0o022) || (process.getuid && runtimeInfo.uid !== process.getuid() && runtimeInfo.uid !== 0)) throw new Error('Browser host runtime must be a trusted executable.');
  await access(nodePath, constants.X_OK);
  const appDirectory = await safeDataDirectory(home, absolutePath(options.dataDirectory ?? path.join(home, 'Library', 'Application Support', 'JJ Vault'), 'Browser data folder'));
  await chmod(appDirectory, 0o700);
  const configFile = path.join(appDirectory, 'browser-host.json');
  const fileInfo = await optionalInfo(configFile);
  const old = fileInfo ? JSON.parse((await readChecked(configFile, fileInfo, 'Browser pairing config', true, 65536)).toString('utf8')) : {};
  if (!old || typeof old !== 'object' || Array.isArray(old)) throw new Error('Browser pairing config must be an object.');
  const chrome = new Set(ids(old.chromeExtensionIds, 'chrome'));
  const firefox = new Set(ids(old.firefoxExtensionIds, 'firefox'));
  const safari = ids(old.safariExtensionIds, 'safari');
  for (const operation of options.operations) {
    if (operation.action === 'chrome') chrome.add(operation.id);
    else if (operation.action === 'removeChrome') chrome.delete(operation.id);
    else if (operation.action === 'firefox') firefox.add(operation.id);
    else firefox.delete(operation.id);
  }
  const port = options.port ?? old.port ?? 17373;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('Invalid browser host port.');
  const browserTokenFile = absolutePath(options.browserTokenFile ?? old.browserTokenFile ?? path.join(appDirectory, 'browser-token'), 'Browser token file');
  const tokenInfo = await optionalInfo(browserTokenFile);
  if (tokenInfo) requireStrongToken((await readChecked(browserTokenFile, tokenInfo, 'Browser token file', true, 4096)).toString('utf8').trim(), 'Browser token');
  const hostFile = path.join(appDirectory, 'native-host.cjs');
  const executable = path.join(appDirectory, 'jjvault-browser-host');
  const destinations = [
    { relative: 'Library/Application Support/Google/Chrome/NativeMessagingHosts', ids: chrome, property: 'allowed_origins', values: [...chrome].map(id => `chrome-extension://${id}/`) },
    { relative: 'Library/Application Support/Mozilla/NativeMessagingHosts', ids: firefox, property: 'allowed_extensions', values: [...firefox] },
  ];
  const manifests = [];
  for (const destination of destinations) {
    const folder = await safeDirectory(home, destination.relative);
    const filename = path.join(folder, `${HOST}.json`);
    const existing = await optionalInfo(filename);
    if (existing) requireOwnerFile(existing, 'Existing browser manifest');
    manifests.push({ ...destination, filename });
  }
  // Keep the host outside the source checkout and direct it to this app's config.
  const environment = `${options.runAsNode ? `${quote('ELECTRON_RUN_AS_NODE=1')} ` : ''}${quote(`JJ_VAULT_BROWSER_CONFIG=${configFile}`)}`;
  await secureWrite(hostFile, hostContents);
  await secureWrite(executable, `#!/bin/sh\nexec /usr/bin/env ${environment} ${quote(nodePath)} ${quote(hostFile)} "$@"\n`, 0o700);
  const config = { ...old, port, browserTokenFile, chromeExtensionIds: [...chrome], firefoxExtensionIds: [...firefox], safariExtensionIds: safari };
  await secureWrite(configFile, JSON.stringify(config, null, 2) + '\n');
  for (const destination of manifests) {
    if (destination.ids.size === 0) { await removeOwnFile(destination.filename); continue; }
    await secureWrite(destination.filename, JSON.stringify({ name: HOST, description: 'Local JJ Vault browser bridge', path: executable, type: 'stdio', [destination.property]: destination.values }, null, 2) + '\n');
  }
  return { chromeCount: chrome.size, firefoxCount: firefox.size, executable, hostFile, nodePath, configFile };
}
