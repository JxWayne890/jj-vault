// This creates a disposable local PostgreSQL cluster on a private Unix socket.
// It never reads database credentials or connects to an existing database.
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { envelope, share } from './fixtures.mjs';

function run(command, args, input = '') {
  return new Promise((resolve, reject) => {
    const process = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = ''; let err = '';
    process.stdout.on('data', value => { out += value; });
    process.stderr.on('data', value => { err += value; });
    process.on('error', reject);
    process.on('close', code => code === 0 ? resolve(out.trim()) : reject(new Error(`${command} exited ${code}: ${err.trim()}`)));
    process.stdin.end(input);
  });
}

const directory = await mkdtemp(join(tmpdir(), 'jj-relay-postgres-'));
const data = join(directory, 'data');
let started = false;
const sql = text => run('psql', ['-X', '-h', directory, '-p', '5432', '-U', 'relay_test_admin', '-d', 'postgres', '--set', 'ON_ERROR_STOP=1', '-A', '-t', '-q'], text);
const quote = value => `'${JSON.stringify(value).replaceAll("'", "''")}'::jsonb`;
const asService = text => sql('set role service_role;\n' + text);
let checks = 0;
function check(description) { checks += 1; console.log(`PASS ${description}`); }
try {
  await run('initdb', ['-D', data, '--no-locale', '--encoding=UTF8', '--auth=trust', '-U', 'relay_test_admin']);
  await run('pg_ctl', ['-D', data, '-l', join(directory, 'postgres.log'), '-o', `-k ${directory} -h '' -p 5432`, '-w', 'start']);
  started = true;
  await sql('create role anon; create role authenticated; create role service_role bypassrls; grant usage on schema public to anon, authenticated, service_role;');
  const migration = await readFile(new URL('../supabase/migrations/202610210001_private_relay.sql', import.meta.url), 'utf8');
  await sql(migration); check('migration applies to fresh PostgreSQL 17');

  for (const role of ['anon', 'authenticated']) {
    for (const name of ['jj_relay_status()', 'jj_relay_read()', "jj_relay_write(0,'{}'::jsonb)", "jj_relay_share_read('synthetic')", "jj_relay_share_create('synthetic','{}'::jsonb)", "jj_relay_share_delete('synthetic')"])
      await assert.rejects(sql(`set role ${role}; select public.${name};`), /permission denied/);
    for (const table of ['vault', 'shares']) await assert.rejects(sql(`set role ${role}; select * from jj_relay.${table};`), /permission denied/);
  }
  for (const table of ['vault', 'shares']) await assert.rejects(asService(`select * from jj_relay.${table};`), /permission denied/);
  const rls = await sql("select bool_and(relrowsecurity) from pg_class where oid in ('jj_relay.vault'::regclass,'jj_relay.shares'::regclass);");
  assert.equal(rls, 't'); check('anon and authenticated cannot call any relay RPC or access tables, service uses RPC only, RLS enabled');

  assert.deepEqual(JSON.parse(await asService('select public.jj_relay_read();')), { revision: 0, envelope: null });
  const value = envelope();
  assert.equal(await sql(`select jj_relay.valid_envelope(${quote(value)});`), 't');
  for (const key of Object.keys(value)) {
    const candidate = { ...value, [key]: null };
    assert.equal(await sql(`select jj_relay.valid_envelope(${quote(candidate)});`), 'f', `null envelope ${key}`);
    await assert.rejects(asService(`select public.jj_relay_write(0,${quote(candidate)});`), /Invalid relay request/);
  }
  for (const key of Object.keys(value.kdf)) {
    const candidate = { ...value, kdf: { ...value.kdf, [key]: null } };
    assert.equal(await sql(`select jj_relay.valid_envelope(${quote(candidate)});`), 'f', `null KDF ${key}`);
  }
  const invalid = [null, [], {}, { ...value, extra: 'plaintext' }, { ...value, kdf: { ...value.kdf, extra: 'plaintext' } },
    { ...value, kdf: { ...value.kdf, memoryKiB: 1 } }, { ...value, kdf: { ...value.kdf, memoryKiB: 65536.5 } },
    { ...value, kdf: { ...value.kdf, iterations: '3' } }, { ...value, ciphertext: 'AA==' },
    { ...value, iv: value.iv + '=' }, { ...value, ciphertext: Buffer.alloc(2097153).toString('base64') }];
  for (const candidate of invalid) assert.equal(await sql(`select jj_relay.valid_envelope(${quote(candidate)});`), 'f');
  check('database rejects every null envelope and KDF field, extra fields, invalid KDF, base64 and oversized ciphertext');

  const contenders = Array.from({ length: 12 }, (_, index) => envelope('synthetic-vault-' + index));
  const results = await Promise.all(contenders.map(candidate => asService(`select public.jj_relay_write(0,${quote(candidate)});`).then(JSON.parse)));
  assert.equal(results.filter(result => result.ok).length, 1);
  assert.equal(results.filter(result => !result.ok && result.revision === 1).length, 11);
  const winner = contenders[results.findIndex(result => result.ok)];
  assert.deepEqual(JSON.parse(await asService('select public.jj_relay_read();')), { revision: 1, envelope: winner });
  check('twelve independent database writers yield exactly one success and eleven conflicts with persistent winner');

  await sql("create function jj_relay.reject_test_write() returns trigger language plpgsql as $$ begin raise exception 'Synthetic storage failure'; end; $$; create trigger reject_test_write before update on jj_relay.vault for each row execute function jj_relay.reject_test_write();");
  await assert.rejects(asService(`select public.jj_relay_write(1,${quote(envelope())});`), /Synthetic storage failure/);
  assert.deepEqual(JSON.parse(await asService('select public.jj_relay_read();')), { revision: 1, envelope: winner });
  await sql('drop trigger reject_test_write on jj_relay.vault; drop function jj_relay.reject_test_write();');
  check('database write failure rolls back revision and ciphertext');

  const shared = share(); const id = 's'.repeat(32);
  for (const key of Object.keys(shared)) assert.equal(await sql(`select jj_relay.valid_share(${quote({ ...shared, [key]: null })});`), 'f');
  assert.deepEqual(JSON.parse(await asService(`select public.jj_relay_share_create('${id}',${quote(shared)});`)), { ok: true });
  assert.deepEqual(JSON.parse(await asService(`select public.jj_relay_share_read('${id}');`)), shared);
  assert.deepEqual(JSON.parse(await asService(`select public.jj_relay_share_create('${id}',${quote(shared)});`)), { ok: false, reason: 'exists' });
  assert.deepEqual(JSON.parse(await asService(`select public.jj_relay_share_delete('${id}');`)), { revoked: true });
  assert.equal(await asService(`select public.jj_relay_share_read('${id}');`), '');
  await assert.rejects(asService(`select public.jj_relay_share_create('${id}',${quote({ ...shared, expiresAt: new Date(Date.now() - 1000).toISOString() })});`), /Invalid relay request/);
  await assert.rejects(asService(`select public.jj_relay_share_create('${id}',${quote({ ...shared, expiresAt: new Date(Date.now() + 31 * 86400000).toISOString() })});`), /Invalid relay request/);
  await sql(`insert into jj_relay.shares(id,envelope,expires_at) values('${id}',${quote(shared)},now() - interval '1 second');`);
  assert.equal(await asService(`select public.jj_relay_share_read('${id}');`), '');
  check('share validation, creation, retrieval, duplicate handling, revocation and expiry work in the database');

  await sql('update jj_relay.vault set revision = 9007199254740989;');
  assert.deepEqual(JSON.parse(await asService(`select public.jj_relay_write(9007199254740989,${quote(value)});`)), { ok: true, revision: 9007199254740990 });
  await assert.rejects(asService(`select public.jj_relay_write(9007199254740990,${quote(value)});`), /Invalid relay request/);
  await assert.rejects(asService(`select public.jj_relay_write(-1,${quote(value)});`), /Invalid relay request/);
  check('revision overflow and negative revisions fail before mutation');
  console.log(`${checks} PostgreSQL integration groups passed. Only disposable local synthetic data was used.`);
} finally {
  if (started) await run('pg_ctl', ['-D', data, '-m', 'immediate', '-w', 'stop']);
  await rm(directory, { recursive: true, force: true });
}
