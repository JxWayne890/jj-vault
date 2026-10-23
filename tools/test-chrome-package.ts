import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, unlink, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { unzipSync, strFromU8 } from 'fflate';
import { packageChromeExtension } from './package-chrome.ts';

const files = [
  'manifest.json', 'background.js', 'content.js', 'popup.js', 'popup.html', 'popup.css',
  'icon.svg', 'icon16.png', 'icon32.png', 'icon48.png', 'icon128.png',
];

async function fixture() {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'jjvault-chrome-package-'));
  const sourceDirectory = path.join(directory, 'source');
  const outputDirectory = path.join(directory, 'release');
  await mkdir(sourceDirectory);
  for (const name of files) await writeFile(path.join(sourceDirectory, name), name === 'manifest.json'
    ? JSON.stringify({ manifest_version: 3, name: 'JJ Vault', version: '0.1.0' }) : `fixture:${name}`);
  return { directory, sourceDirectory, outputDirectory };
}

test('Chrome ZIP contains exactly the runtime allowlist and installation guide, with a valid checksum', async () => {
  const f = await fixture();
  try {
    // If the packager opens unexpected files, this dangling private link fails.
    await symlink(path.join(f.directory, 'does-not-exist'), path.join(f.sourceDirectory, 'browser-token'));
    await writeFile(path.join(f.sourceDirectory, 'vault.json'), 'PRIVATE_FIXTURE_MUST_NOT_SHIP');
    await writeFile(path.join(f.sourceDirectory, 'background.js.map'), 'PRIVATE_SOURCEMAP_MUST_NOT_SHIP');
    await mkdir(path.join(f.sourceDirectory, 'private'));
    await writeFile(path.join(f.sourceDirectory, 'private', 'credentials.json'), 'PRIVATE_NESTED_MUST_NOT_SHIP');
    const result = await packageChromeExtension(f);
    const bytes = await readFile(result.zipPath);
    const entries = unzipSync(bytes);
    assert.deepEqual(Object.keys(entries).sort(), [...files, 'INSTALL.txt'].map(name => `JJ-Vault-Chrome/${name}`).sort());
    for (const name of files) assert.deepEqual(Buffer.from(entries[`JJ-Vault-Chrome/${name}`]), await readFile(path.join(f.sourceDirectory, name)));
    const instructions = strFromU8(entries['JJ-Vault-Chrome/INSTALL.txt']);
    assert.match(instructions, /requires the JJ Vault Mac app/);
    assert.match(instructions, /chrome:\/\/extensions/);
    assert.match(instructions, /Developer mode[\s\S]*Load unpacked/);
    assert.match(instructions, /Select the JJ-Vault-Chrome folder that contains manifest.json/);
    assert.match(instructions, /Each installation can have a different ID/);
    assert.match(instructions, /Pair extension/);
    assert.match(instructions, /Keep the Mac app running and your vault unlocked/);
    assert.match(instructions, /pin JJ Vault/);
    const digest = createHash('sha256').update(bytes).digest('hex');
    assert.equal(result.sha256, digest);
    assert.equal(await readFile(result.checksumPath, 'utf8'), `${digest}  JJ-Vault-Chrome-0.1.0.zip\n`);
    assert.equal(result.version, '0.1.0');
    assert.equal(path.basename(result.zipPath), 'JJ-Vault-Chrome-0.1.0.zip');
    assert.deepEqual(await readdir(f.outputDirectory), ['JJ-Vault-Chrome-0.1.0.zip', 'JJ-Vault-Chrome-0.1.0.zip.sha256']);
    const repeated = await packageChromeExtension(f);
    assert.equal(repeated.sha256, digest);
  } finally { await rm(f.directory, { recursive: true, force: true }); }
});

test('a required runtime symlink is refused before any runtime content is read or output is created', async () => {
  const f = await fixture();
  try {
    // Malformed manifest would fail first if it were read before all metadata.
    await writeFile(path.join(f.sourceDirectory, 'manifest.json'), 'NOT_JSON');
    await unlink(path.join(f.sourceDirectory, 'icon128.png'));
    await symlink(path.join(f.directory, 'private-secret-not-to-read'), path.join(f.sourceDirectory, 'icon128.png'));
    await assert.rejects(packageChromeExtension(f), /icon128.png must be a regular file without symbolic links/);
    await assert.rejects(readFile(path.join(f.outputDirectory, 'JJ-Vault-Chrome-0.1.0.zip')), { code: 'ENOENT' });
  } finally { await rm(f.directory, { recursive: true, force: true }); }
});

test('source and output directory symlinks are refused without writing into their targets', async () => {
  const f = await fixture();
  try {
    const sourceLink = path.join(f.directory, 'source-link');
    await symlink(f.sourceDirectory, sourceLink, 'dir');
    await assert.rejects(packageChromeExtension({ sourceDirectory: sourceLink, outputDirectory: f.outputDirectory }), /without symbolic links/);
    const target = path.join(f.directory, 'unrelated');
    await mkdir(target);
    await symlink(target, f.outputDirectory, 'dir');
    await assert.rejects(packageChromeExtension(f), /without symbolic links/);
    assert.deepEqual(await readdir(target), []);
  } finally { await rm(f.directory, { recursive: true, force: true }); }
});

test('missing runtime files and unsafe manifest versions fail before producing an archive', async () => {
  const f = await fixture();
  try {
    await unlink(path.join(f.sourceDirectory, 'popup.js'));
    await assert.rejects(packageChromeExtension(f), { code: 'ENOENT' });
    await writeFile(path.join(f.sourceDirectory, 'popup.js'), 'fixture');
    for (const version of ['../../private', '0.1.0-beta', '']) {
      await writeFile(path.join(f.sourceDirectory, 'manifest.json'), JSON.stringify({ manifest_version: 3, name: 'JJ Vault', version }));
      await assert.rejects(packageChromeExtension(f), /manifest is invalid/);
    }
    await assert.rejects(readdir(f.outputDirectory), { code: 'ENOENT' });
  } finally { await rm(f.directory, { recursive: true, force: true }); }
});
