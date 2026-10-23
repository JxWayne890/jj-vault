import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { strToU8, zipSync, type Zippable } from 'fflate';
import { isDirectExecution } from '../packages/service/src/entrypoint.ts';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const folderName = 'JJ-Vault-Chrome';
const runtimeFiles = [
  'manifest.json', 'background.js', 'content.js', 'popup.js', 'popup.html', 'popup.css',
  'icon.svg', 'icon16.png', 'icon32.png', 'icon48.png', 'icon128.png',
] as const;
const maximumFileBytes = 4 * 1024 * 1024;

export interface ChromePackageOptions {
  sourceDirectory?: string;
  outputDirectory?: string;
}

export interface ChromePackageResult {
  zipPath: string;
  checksumPath: string;
  sha256: string;
  version: string;
  entries: string[];
}

const installationInstructions = `JJ Vault Chrome extension

This extension requires the JJ Vault Mac app. Install the Mac app, create or
unlock your own vault, and enable Browser autofill for the vaults you want to use.
The extension does not contain a vault or anyone else's saved information.

1. Unzip this download. Move the JJ-Vault-Chrome folder to a permanent location
   on your Mac before loading it. Keep that folder after installation.
2. Open Chrome and enter chrome://extensions in the address bar.
3. Turn on Developer mode in the upper right, then choose Load unpacked.
4. Select the JJ-Vault-Chrome folder that contains manifest.json.
5. Find JJ Vault in Chrome's extension list and copy its full Extension ID.
   Each installation can have a different ID. Use the ID shown on your computer.
6. Open JJ Vault on your Mac. Choose Settings, find Browser connection, paste
   that ID into Extension ID, and choose Pair extension. Confirm the pairing.
7. Restart Chrome. Click the Extensions puzzle icon beside the address bar and
   pin JJ Vault. Open it on a normal HTTPS website, then refresh the popup.
8. Keep the Mac app running and your vault unlocked while using autofill.
   A locked vault refuses browser access. You choose each item that gets filled.

If the popup says Unavailable, confirm that the Mac app is running, that you
paired this computer's actual Extension ID, and that browser access is enabled.
Unlock the vault if the popup says Locked. Chrome's internal pages do not allow
normal extension filling. Test on an ordinary HTTPS sign in page instead.

For updates, replace files in the same permanent folder, then choose Reload
for JJ Vault at chrome://extensions. Moving the folder can change its ID and
require pairing again. Do not delete the folder while the extension is installed.

This beta uses Chrome's Load unpacked installation. It is not yet distributed
through the Chrome Web Store. Do not try to load the ZIP file itself.

Setup guide: https://github.com/JxWayne890/jj-vault/blob/main/docs/CHROME-SETUP.md
`;

/** Inspect every existing path component before reading files or creating output. */
async function inspectDirectory(directory: string): Promise<void> {
  const parent = path.dirname(directory);
  if (parent !== directory) await inspectDirectory(parent);
  const info = await lstat(directory);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('Chrome package directories must be real directories, without symbolic links.');
}

async function makeOutputDirectory(directory: string): Promise<void> {
  try { await inspectDirectory(directory); }
  catch (error: any) {
    if (error.code !== 'ENOENT') throw error;
    const parent = path.dirname(directory);
    await makeOutputDirectory(parent);
    try { await mkdir(directory); } catch (failure: any) { if (failure.code !== 'EEXIST') throw failure; }
    await inspectDirectory(directory);
  }
}

async function readRuntimeFile(file: string): Promise<Uint8Array> {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > maximumFileBytes) throw new Error('A Chrome runtime file is not a regular file or exceeds the package size limit.');
    return await handle.readFile();
  } finally { await handle.close(); }
}

async function writeArtifact(file: string, contents: string | Uint8Array): Promise<void> {
  const temporary = `${file}.tmp-${randomUUID()}`;
  try {
    await writeFile(temporary, contents, { flag: 'wx', mode: 0o644 });
    await rename(temporary, file);
  } finally { await rm(temporary, { force: true }); }
}

/** Package only known public runtime files. Unexpected files are never opened. */
export async function packageChromeExtension(options: ChromePackageOptions = {}): Promise<ChromePackageResult> {
  const sourceDirectory = path.resolve(options.sourceDirectory ?? path.join(projectRoot, 'dist/extensions/chrome'));
  const outputDirectory = path.resolve(options.outputDirectory ?? path.join(projectRoot, 'release'));
  await inspectDirectory(sourceDirectory);
  // Validate the entire allowlist before reading even its first file.
  for (const name of runtimeFiles) {
    const info = await lstat(path.join(sourceDirectory, name));
    if (info.isSymbolicLink() || !info.isFile() || info.size > maximumFileBytes) {
      throw new Error(`Chrome runtime file ${name} must be a regular file without symbolic links, within the package size limit.`);
    }
  }
  const archive: Zippable = {};
  let version = '';
  for (const name of runtimeFiles) {
    const bytes = await readRuntimeFile(path.join(sourceDirectory, name));
    if (name === 'manifest.json') {
      const manifest = JSON.parse(Buffer.from(bytes).toString('utf8'));
      if (manifest.manifest_version !== 3 || manifest.name !== 'JJ Vault' ||
          typeof manifest.version !== 'string' || !/^\d+(?:\.\d+){1,3}$/.test(manifest.version)) {
        throw new Error('Build the JJ Vault Chrome extension before packaging it. Its manifest is invalid.');
      }
      version = manifest.version;
    }
    archive[`${folderName}/${name}`] = bytes;
  }
  archive[`${folderName}/INSTALL.txt`] = strToU8(installationInstructions);
  // A fixed timestamp makes the same built inputs produce the same archive.
  const zip = zipSync(archive, { level: 9, mtime: new Date(2000, 0, 1) });
  const sha256 = createHash('sha256').update(zip).digest('hex');
  const zipName = `${folderName}-${version}.zip`;
  const zipPath = path.join(outputDirectory, zipName);
  const checksumPath = `${zipPath}.sha256`;
  await makeOutputDirectory(outputDirectory);
  await writeArtifact(zipPath, zip);
  await writeArtifact(checksumPath, `${sha256}  ${zipName}\n`);
  return { zipPath, checksumPath, sha256, version, entries: Object.keys(archive) };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write('Package the already built JJ Vault Chrome extension.\n\nUsage: npm run package:chrome\n\nBuild the extension first with npm run build:extensions.\n');
    return;
  }
  if (args.length) throw new Error('Chrome packaging does not accept command line options.');
  const result = await packageChromeExtension();
  process.stdout.write(`Chrome extension archive: ${result.zipPath}\nSHA256: ${result.sha256}\nChecksum file: ${result.checksumPath}\n`);
}

if (isDirectExecution(import.meta.url)) main().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.message : 'Chrome extension packaging failed'}\n`);
  process.exitCode = 1;
});
