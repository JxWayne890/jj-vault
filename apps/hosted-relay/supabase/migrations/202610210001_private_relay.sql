-- Run in a NEW Supabase project owned by the person operating this relay.
-- There are no grants to anon or authenticated, and no plaintext or unlock keys.
begin;

create schema jj_relay;
revoke all on schema jj_relay from public, anon, authenticated, service_role;

create function jj_relay.valid_base64(value text, minimum integer, maximum integer)
returns boolean language plpgsql immutable set search_path = '' as $$
declare decoded bytea;
begin
  if value is null or length(value) > 4 * ((maximum + 2) / 3)
      or value !~ '^[A-Za-z0-9+/]*={0,2}$' then return false; end if;
  decoded := pg_catalog.decode(value, 'base64');
  return octet_length(decoded) between minimum and maximum
    and replace(pg_catalog.encode(decoded, 'base64'), chr(10), '') = value;
exception when others then return false;
end;
$$;

create function jj_relay.valid_envelope(e jsonb)
returns boolean language plpgsql immutable set search_path = '' as $$
declare k jsonb;
begin
  if e is null or jsonb_typeof(e) <> 'object' or octet_length(e::text) > 3145728
      or not (e ?& array['format','version','id','kdf','iv','ciphertext'])
      or e - array['format','version','id','kdf','iv','ciphertext'] <> '{}'::jsonb
      or e->'format' is distinct from '"jjvault"'::jsonb or e->'version' is distinct from '1'::jsonb
      or jsonb_typeof(e->'id') <> 'string' or e->>'id' !~ '^[A-Za-z0-9-]{8,80}$'
      or jsonb_typeof(e->'iv') <> 'string' or jsonb_typeof(e->'ciphertext') <> 'string'
      or not jj_relay.valid_base64(e->>'iv',12,12)
      or not jj_relay.valid_base64(e->>'ciphertext',16,2097152) then return false; end if;
  k := e->'kdf';
  if jsonb_typeof(k) <> 'object' or not (k ?& array['algorithm','salt','memoryKiB','iterations','parallelism'])
      or k - array['algorithm','salt','memoryKiB','iterations','parallelism'] <> '{}'::jsonb
      or k->'algorithm' is distinct from '"argon2id"'::jsonb or k->'parallelism' is distinct from '1'::jsonb
      or jsonb_typeof(k->'salt') <> 'string' or not jj_relay.valid_base64(k->>'salt',16,16)
      or jsonb_typeof(k->'memoryKiB') <> 'number' or k->>'memoryKiB' !~ '^\d{5,6}$'
      or (k->>'memoryKiB')::integer not between 65536 and 262144
      or jsonb_typeof(k->'iterations') <> 'number' or k->>'iterations' !~ '^\d{1,2}$'
      or (k->>'iterations')::integer not between 3 and 10 then return false; end if;
  return true;
exception when others then return false;
end;
$$;

create function jj_relay.valid_share(e jsonb)
returns boolean language plpgsql immutable set search_path = '' as $$
begin
  return coalesce(jsonb_typeof(e) = 'object' and octet_length(e::text) <= 3145728
    and e ?& array['version','iv','ciphertext','expiresAt']
    and e - array['version','iv','ciphertext','expiresAt'] = '{}'::jsonb
    and e->'version' = '1'::jsonb and jsonb_typeof(e->'iv') = 'string'
    and jsonb_typeof(e->'ciphertext') = 'string' and jsonb_typeof(e->'expiresAt') = 'string'
    and jj_relay.valid_base64(e->>'iv',12,12) and jj_relay.valid_base64(e->>'ciphertext',16,2097152)
    and length(e->>'expiresAt') <= 40
    and e->>'expiresAt' ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$'
    and isfinite((e->>'expiresAt')::timestamptz),false);
exception when others then return false;
end;
$$;

create table jj_relay.vault (
  singleton boolean primary key default true check (singleton),
  revision bigint not null default 0 check (revision between 0 and 9007199254740990),
  envelope jsonb check (envelope is null or jj_relay.valid_envelope(envelope)),
  updated_at timestamptz not null default now()
);
insert into jj_relay.vault(singleton) values (true);
create table jj_relay.shares (
  id text primary key check (id ~ '^[A-Za-z0-9_-]{32,64}$'),
  envelope jsonb not null check (jj_relay.valid_share(envelope)),
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index shares_expiry on jj_relay.shares(expires_at);
alter table jj_relay.vault enable row level security;
alter table jj_relay.shares enable row level security;
-- Deliberately no policies. Even service_role uses only the narrowly scoped RPCs.
revoke all on all tables in schema jj_relay from public, anon, authenticated, service_role;
revoke all on all functions in schema jj_relay from public, anon, authenticated, service_role;

create function public.jj_relay_status()
returns jsonb language sql security definer set search_path = '' as $$
  select jsonb_build_object('revision',revision,'vaultId',envelope->>'id')
    from jj_relay.vault where singleton = true;
$$;
create function public.jj_relay_read()
returns jsonb language sql security definer set search_path = '' as $$
  select jsonb_build_object('revision',revision,'envelope',envelope)
    from jj_relay.vault where singleton = true;
$$;
create function public.jj_relay_write(p_expected_revision bigint, p_envelope jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare current_revision bigint;
begin
  if p_expected_revision is null or p_expected_revision < 0 or p_expected_revision >= 9007199254740990
      or not jj_relay.valid_envelope(p_envelope) then raise exception 'Invalid relay request'; end if;
  -- The row lock is held until the RPC transaction commits. Independent Vercel
  -- instances and simultaneous first writes cannot both accept the same revision.
  select revision into strict current_revision from jj_relay.vault where singleton = true for update;
  if current_revision <> p_expected_revision then
    return jsonb_build_object('ok',false,'revision',current_revision);
  end if;
  update jj_relay.vault set envelope = p_envelope, revision = revision + 1, updated_at = now() where singleton = true;
  return jsonb_build_object('ok',true,'revision',current_revision + 1);
end;
$$;
create function public.jj_relay_share_read(p_id text)
returns jsonb language sql security definer set search_path = '' as $$
  select envelope from jj_relay.shares where id = p_id and expires_at > now();
$$;
create function public.jj_relay_share_create(p_id text, p_envelope jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare expiry timestamptz;
begin
  if p_id is null or p_id !~ '^[A-Za-z0-9_-]{32,64}$' or not jj_relay.valid_share(p_envelope)
    then raise exception 'Invalid relay request'; end if;
  expiry := (p_envelope->>'expiresAt')::timestamptz;
  if expiry <= now() or expiry > now() + interval '30 days' then raise exception 'Invalid relay request'; end if;
  -- Serialize the limit check across all stateless instances.
  perform singleton from jj_relay.vault where singleton = true for update;
  delete from jj_relay.shares where expires_at <= now();
  if exists(select 1 from jj_relay.shares where id = p_id) then return '{"ok":false,"reason":"exists"}'::jsonb; end if;
  if (select count(*) from jj_relay.shares) >= 1000 then return '{"ok":false,"reason":"limit"}'::jsonb; end if;
  insert into jj_relay.shares(id,envelope,expires_at) values(p_id,p_envelope,expiry);
  return '{"ok":true}'::jsonb;
end;
$$;
create function public.jj_relay_share_delete(p_id text)
returns jsonb language plpgsql security definer set search_path = '' as $$
begin
  delete from jj_relay.shares where id = p_id;
  return '{"revoked":true}'::jsonb;
end;
$$;

revoke all on function public.jj_relay_status() from public, anon, authenticated, service_role;
revoke all on function public.jj_relay_read() from public, anon, authenticated, service_role;
revoke all on function public.jj_relay_write(bigint,jsonb) from public, anon, authenticated, service_role;
revoke all on function public.jj_relay_share_read(text) from public, anon, authenticated, service_role;
revoke all on function public.jj_relay_share_create(text,jsonb) from public, anon, authenticated, service_role;
revoke all on function public.jj_relay_share_delete(text) from public, anon, authenticated, service_role;
grant execute on function public.jj_relay_status() to service_role;
grant execute on function public.jj_relay_read() to service_role;
grant execute on function public.jj_relay_write(bigint,jsonb) to service_role;
grant execute on function public.jj_relay_share_read(text) to service_role;
grant execute on function public.jj_relay_share_create(text,jsonb) to service_role;
grant execute on function public.jj_relay_share_delete(text) to service_role;
comment on schema jj_relay is 'Private single owner JJ Vault ciphertext relay. No unlock keys or plaintext.';
notify pgrst, 'reload schema';
commit;
