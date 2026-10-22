#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { access, copyFile, lstat, mkdir, readFile, readdir, readlink, rename, symlink, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import path from 'node:path';

// Keep generated dependency files outside iCloud managed Documents directories.
// This tool changes no dependency versions and preserves an existing dependency tree.
const project = process.cwd();
const online = process.argv.includes('--online');
const lock = await readFile(path.join(project, 'package-lock.json'));
const digest = createHash('sha256').update(lock).digest('hex');
const cacheRoot = path.join(homedir(), '.cache', 'jj-vault-build');
const destination = path.join(cacheRoot, `dependencies-${digest.slice(0, 16)}`);
const modules = path.join(project, 'node_modules');
async function exists(file) { try { await access(file); return true; } catch { return false; } }
async function run(command, args, cwd) {
  await new Promise((resolve, reject) => { const child = spawn(command, args, { cwd, stdio: ['ignore', 'inherit', 'inherit'], env: process.env }); child.once('error', reject); child.once('exit', code => code === 0 ? resolve() : reject(new Error(`${command} exited with ${code}`))); });
}
try {
  if ((await lstat(modules)).isSymbolicLink()) {
    const current = path.resolve(project, await readlink(modules));
    const currentLock = await readFile(path.join(current, '..', 'package-lock.json'));
    if (createHash('sha256').update(currentLock).digest('hex') === digest && await exists(path.join(current, 'electron', 'path.txt'))) {
      console.log(`Local dependencies already match the lockfile: ${current}`); process.exit(0);
    }
  }
} catch (error) { if (error.code && error.code !== 'ENOENT') throw error; }
await mkdir(destination, { recursive: true, mode: 0o700 });
await copyFile(path.join(project, 'package.json'), path.join(destination, 'package.json'));
await writeFile(path.join(destination, 'package-lock.json'), lock);
if (!await exists(path.join(destination, '.ready'))) {
  await run('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund', ...(online ? [] : ['--offline'])], destination);
  const electron = path.join(destination, 'node_modules', 'electron');
  const { version } = JSON.parse(await readFile(path.join(electron, 'package.json'), 'utf8'));
  const archiveName = `electron-v${version}-darwin-${process.arch}.zip`;
  const electronCache = path.join(homedir(), 'Library', 'Caches', 'electron');
  let archive;
  if (await exists(electronCache)) for (const directory of await readdir(electronCache, { withFileTypes: true })) {
    if (directory.isDirectory() && await exists(path.join(electronCache, directory.name, archiveName))) { archive = path.join(electronCache, directory.name, archiveName); break; }
  }
  if (archive && process.platform === 'darwin') {
    const checksums = JSON.parse(await readFile(path.join(electron, 'checksums.json'), 'utf8'));
    const hash = createHash('sha256'); for await (const chunk of createReadStream(archive)) hash.update(chunk);
    if (hash.digest('hex') !== checksums[archiveName]) throw new Error('Cached Electron archive checksum does not match the installed package');
    await run('/usr/bin/ditto', ['-x', '-k', archive, path.join(electron, 'dist')], destination);
    await writeFile(path.join(electron, 'path.txt'), 'Electron.app/Contents/MacOS/Electron');
  } else if (online) await run(process.execPath, ['install.js'], electron);
  else throw new Error('Electron archive is not cached. Run again with --online to download the exact locked version.');
  await writeFile(path.join(destination, '.ready'), digest + '\n');
}
let existingModules = false; try { await lstat(modules); existingModules = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
if (existingModules) await rename(modules, path.join(project, `node_modules.previous.${Date.now()}`));
await symlink(path.join(destination, 'node_modules'), modules, 'dir');
console.log(`Prepared exact lockfile dependencies outside iCloud: ${destination}`);
