import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolvePackageOptions } from './package-options.ts';

const fingerprint = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01';
const identityName = 'Developer ID Application: Example Company (EXAMPLE123)';
const identities = `  1) ${fingerprint} "${identityName}"\n     1 valid identities found\n`;

test('default packaging stages with ad hoc signing without inspecting the Keychain', () => {
  const options = resolvePackageOptions([], {}, () => { throw new Error('Unexpected identity inspection'); });
  assert.equal(options.install, false);
  assert.equal(options.stageOnly, true);
  assert.equal(options.signingIdentity, '-');
  assert.equal(options.entitlements, 'assets/entitlements.mac.adhoc.plist');
});

test('only the explicit install option selects app replacement', () => {
  assert.equal(resolvePackageOptions(['--install'], {}).install, true);
  assert.equal(resolvePackageOptions(['--install'], {}).stageOnly, false);
  assert.equal(resolvePackageOptions([], { JJ_VAULT_STAGE_ONLY: '0' }).install, false);
});

test('the legacy staging flag retains staging and conflicts with installation before inspection', () => {
  assert.equal(resolvePackageOptions([], { JJ_VAULT_STAGE_ONLY: '1' }).stageOnly, true);
  assert.throws(() => resolvePackageOptions(['--install'], {
    JJ_VAULT_STAGE_ONLY: '1', JJ_VAULT_SIGN_IDENTITY: identityName,
  }, () => { throw new Error('Unexpected identity inspection'); }), /conflicts/);
});

test('unknown and duplicate arguments fail before identity inspection', () => {
  for (const args of [['--unknown'], ['--install', '--unknown'], ['--install', '--install']]) {
    assert.throws(() => resolvePackageOptions(args, { JJ_VAULT_SIGN_IDENTITY: identityName },
      () => { throw new Error('Unexpected identity inspection'); }), /Unknown packaging option|may only be provided once/);
  }
});

test('empty or ad hoc identity configuration is rejected before inspection', () => {
  for (const configuredIdentity of ['', '   ', '-']) {
    assert.throws(() => resolvePackageOptions([], { JJ_VAULT_SIGN_IDENTITY: configuredIdentity },
      () => { throw new Error('Unexpected identity inspection'); }), /Omit it for ad hoc signing/);
  }
});

test('a configured installed identity name resolves to its unambiguous fingerprint', () => {
  let inspections = 0;
  const options = resolvePackageOptions([], { JJ_VAULT_SIGN_IDENTITY: identityName }, () => {
    inspections += 1;
    return identities;
  });
  assert.equal(inspections, 1);
  assert.equal(options.signingIdentity, fingerprint);
  assert.equal(options.entitlements, 'assets/entitlements.mac.plist');
  assert.equal(options.stageOnly, true);
  assert.match(options.signingStatus, /Example Company/);
});

test('an explicit installed fingerprint is accepted without selecting a different identity', () => {
  assert.equal(resolvePackageOptions([], { JJ_VAULT_SIGN_IDENTITY: fingerprint.toLowerCase() },
    () => identities).signingIdentity, fingerprint);
});

test('a missing or partially matched identity fails instead of silently using ad hoc signing', () => {
  for (const requestedIdentity of ['Missing identity', 'Example Company', fingerprint.slice(0, 20)]) {
    assert.throws(() => resolvePackageOptions([], { JJ_VAULT_SIGN_IDENTITY: requestedIdentity },
      () => identities), /Requested signing identity is unavailable/);
  }
});

test('identity lookup failure remains a failure', () => {
  const failure = new Error('Keychain lookup failed');
  assert.throws(() => resolvePackageOptions([], { JJ_VAULT_SIGN_IDENTITY: identityName },
    () => { throw failure; }), error => error === failure);
  assert.throws(() => resolvePackageOptions([], { JJ_VAULT_SIGN_IDENTITY: identityName }), /Cannot inspect/);
});

test('invalid identity lines do not satisfy an explicitly requested signer', () => {
  assert.throws(() => resolvePackageOptions([], { JJ_VAULT_SIGN_IDENTITY: identityName },
    () => `  1) ${fingerprint} "${identityName}" (certificate expired)`), /unavailable/);
});

// Trap mutations in a child process so a regression cannot touch an installed app,
// staging cache, generated icon, or release path while exercising the real entry point.
const writeGuard = `
  import fs from 'node:fs';
  import promises from 'node:fs/promises';
  import { syncBuiltinESMExports } from 'node:module';
  const writes = ['appendFile', 'chmod', 'chown', 'copyFile', 'cp', 'link', 'lchown', 'lchmod',
    'lutimes', 'mkdir', 'mkdtemp', 'rename', 'rm', 'rmdir', 'symlink', 'truncate', 'unlink',
    'utimes', 'writeFile'];
  for (const name of writes) {
    const reject = () => { throw new Error('PACKAGE_TEST_FILESYSTEM_WRITE:' + name); };
    if (typeof promises[name] === 'function') promises[name] = reject;
    if (typeof fs[name] === 'function') fs[name] = reject;
    if (typeof fs[name + 'Sync'] === 'function') fs[name + 'Sync'] = reject;
  }
  syncBuiltinESMExports();
`;

test('the real packaging entry point rejects invalid options and missing inputs before filesystem mutations', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'jjvault-package-options-'));
  const script = fileURLToPath(new URL('./package-mac.ts', import.meta.url));
  const loader = fileURLToPath(new URL('../node_modules/tsx/dist/loader.mjs', import.meta.url));
  const environment: NodeJS.ProcessEnv = { ...process.env, TSX_DISABLE_CACHE: '1' };
  delete environment.JJ_VAULT_SIGN_IDENTITY;
  delete environment.JJ_VAULT_STAGE_ONLY;
  const missingInput = process.platform === 'darwin' && process.arch === 'arm64'
    ? /dist\/desktop\/main\.cjs/
    : /requires an Apple silicon Mac/;
  const cases = [
    { args: [], env: {}, expected: missingInput },
    { args: [], env: { JJ_VAULT_STAGE_ONLY: '1' }, expected: missingInput },
    { args: ['--unknown'], env: { JJ_VAULT_SIGN_IDENTITY: identityName }, expected: /Unknown packaging option/ },
    { args: ['--install', '--unknown'], env: {}, expected: /Unknown packaging option/ },
    { args: ['--install'], env: { JJ_VAULT_STAGE_ONLY: '1' }, expected: /conflicts/ },
    { args: ['--install', '--install'], env: {}, expected: /may only be provided once/ },
    { args: [], env: { JJ_VAULT_SIGN_IDENTITY: '' }, expected: /Omit it for ad hoc signing/ },
  ];
  try {
    const guardCheck = spawnSync(process.execPath, [
      '--import', `data:text/javascript,${encodeURIComponent(writeGuard)}`, '--input-type=module',
      '--eval', 'import { writeFile } from "node:fs/promises"; await writeFile("unexpected", "test");',
    ], { cwd: directory, env: environment, encoding: 'utf8', timeout: 30000 });
    assert.equal(guardCheck.error, undefined);
    assert.equal(guardCheck.status, 1, guardCheck.stderr);
    assert.match(guardCheck.stderr, /PACKAGE_TEST_FILESYSTEM_WRITE:writeFile/);
    assert.deepEqual(await readdir(directory), []);
    for (const scenario of cases) {
      const result = spawnSync(process.execPath, [
        '--import', loader, '--import', `data:text/javascript,${encodeURIComponent(writeGuard)}`,
        script, ...scenario.args,
      ], { cwd: directory, env: { ...environment, ...scenario.env }, encoding: 'utf8', timeout: 30000 });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, scenario.expected);
      assert.doesNotMatch(result.stderr, /PACKAGE_TEST_FILESYSTEM_WRITE/);
      assert.deepEqual(await readdir(directory), []);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
