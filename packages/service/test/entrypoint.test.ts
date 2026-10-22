import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { lstat, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { build } from 'esbuild';
import { isDirectExecution } from '../src/entrypoint.ts';

const execute = promisify(execFile);
const sourceDirectory = fileURLToPath(new URL('../src/', import.meta.url));
async function run(filename: string, args: string[], environment: NodeJS.ProcessEnv) {
  try {
    const result = await execute(process.execPath, [filename, ...args], { env: environment, timeout: 10_000, maxBuffer: 128 * 1024 });
    return { code: 0, ...result };
  } catch (error: any) {
    if (typeof error.code !== 'number') throw error;
    return { code: error.code, stdout: String(error.stdout), stderr: String(error.stderr) };
  }
}

test('bundled service commands run through aliased parent paths and stay quiet when imported', { timeout: 60_000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'jj-entrypoint-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const realDirectory = join(directory, "owner's real folder");
  const aliasDirectory = join(directory, "owner's linked folder");
  const wrapperDirectory = join(directory, 'import wrappers');
  await mkdir(realDirectory); await mkdir(wrapperDirectory);
  await symlink(realDirectory, aliasDirectory);
  const blockedDirectory = join(directory, 'not a directory');
  await writeFile(blockedDirectory, 'SYNTHETIC NOT A TOKEN', { mode: 0o600 });
  const environment = {
    ...process.env,
    JJ_VAULT_DIR: join(directory, 'uninitialized owner directory'),
    JJ_VAULT_AGENT_DIR: join(directory, 'uninitialized agent directory'),
    JJ_VAULT_BROWSER_CONFIG: join(directory, 'missing browser config.json'),
    JJ_VAULT_RELAY_DIR: blockedDirectory,
  };
  const commands = [
    { name: 'agent-client', args: ['--help'], code: 0, stdout: /Usage: jjvault-agent/, stderr: /^$/ },
    { name: 'cli', args: ['--help'], code: 0, stdout: /jjvault status/, stderr: /^$/ },
    { name: 'native-host', args: [], code: 1, stdout: /^$/, stderr: /^JJ Vault native host rejected the connection\./ },
    { name: 'sync-server', args: [], code: 1, stdout: /^$/, stderr: /^Relay failed to start\./ },
  ];
  for (const command of commands) {
    const filename = `${command.name}.mjs`;
    await build({
      entryPoints: [join(sourceDirectory, `${command.name}.ts`)],
      outfile: join(realDirectory, filename), bundle: true, platform: 'node', target: 'node22', format: 'esm', logLevel: 'silent',
      banner: { js: 'import {createRequire} from "node:module"; const require=createRequire(import.meta.url);' },
    });
    const alias = join(aliasDirectory, filename);
    assert.notEqual(resolve(alias), await realpath(alias), 'Fixture must reproduce canonical module and argv path differences');
    const result = await run(alias, command.args, environment);
    assert.equal(result.code, command.code, command.name);
    assert.match(result.stdout, command.stdout, command.name);
    assert.match(result.stderr, command.stderr, command.name);
    // Match the CLI basename while importing a different real file. The guard
    // must compare canonical identities rather than only the executable name.
    const wrapper = join(wrapperDirectory, filename);
    await writeFile(wrapper, `await import(${JSON.stringify(pathToFileURL(alias).href)}); process.stdout.write('imported only\\n');\n`);
    const imported = await run(wrapper, command.args, environment);
    assert.equal(imported.code, 0, command.name);
    assert.equal(imported.stdout, 'imported only\n', command.name);
    assert.equal(imported.stderr, '', command.name);
  }
});

test('entrypoint identity rejects missing paths and imports with another entry file', () => {
  assert.equal(isDirectExecution(undefined), false);
  assert.equal(isDirectExecution(import.meta.url, '/nonexistent-synthetic-entrypoint.ts'), false);
  assert.equal(isDirectExecution('data:text/javascript,export{}', process.argv[1]), false);
  assert.equal(isDirectExecution(import.meta.url, fileURLToPath(new URL('../src/entrypoint.ts', import.meta.url))), false);
});

test('browser installer rejects an unknown argument through an aliased parent without creating setup files', { timeout: 15_000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'jj-installer-entrypoint-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const realDirectory = join(directory, "owner's real folder");
  const aliasDirectory = join(directory, "owner's linked folder");
  await mkdir(realDirectory);
  await symlink(realDirectory, aliasDirectory);
  const filename = 'install-browser-host.mjs';
  await build({
    entryPoints: [fileURLToPath(new URL('../../../tools/install-browser-host.ts', import.meta.url))],
    outfile: join(realDirectory, filename), bundle: true, platform: 'node', target: 'node22', format: 'esm', logLevel: 'silent',
  });
  const home = join(directory, 'uninitialized home');
  const alias = join(aliasDirectory, filename);
  assert.notEqual(resolve(alias), await realpath(alias));
  const result = await run(alias, ['--unknown'], { ...process.env, HOME: home });
  assert.equal(result.code, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /Unknown browser setup argument/);
  await assert.rejects(lstat(home), { code: 'ENOENT' });
});
