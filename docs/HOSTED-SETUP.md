# Optional Supabase and Vercel relay

JJ Vault works locally by default. The optional [hosted relay](../apps/hosted-relay/README.md) lets an owner store encrypted sync data and encrypted shares in projects they control. It does not change local vault storage or require John to host anyone else's passwords.

The current package is a ciphertext relay. It is not a hosted password manager. There is no remote unlock session or remote agent decryption service. An agent still needs its authorized unlocked JJ Vault service to retrieve credentials. If that service runs only on a Mac, turning off the Mac makes agent access unavailable even when the relay remains online.

Hosted unlock custody, browser vault access, remote agent access and hosted phone enrollment need separate design and verification. Do not promise these capabilities from this relay.

## Private setup for each owner

1. Create a new Supabase project in your own account. Use a dedicated project for this owner. Keep the project database password and secret key private. No signup users or public database policies are needed.
2. Review and apply [the migration](../apps/hosted-relay/supabase/migrations/202610210001_private_relay.sql) once using that project's SQL editor or your normal reviewed migration process. The migration creates the private `jj_relay` schema and six RPC functions in `public`. Only `service_role` may execute those functions. The public schema must remain exposed to PostgREST, as it is in the standard Supabase configuration.
3. Generate a fresh relay token on your own machine. This must be independent of your vault Secret Key, master password, agent tokens and Supabase secret key.

   ```sh
   node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
   ```

4. Create a new Vercel project in your own account from your copy of this repository. Set its Root Directory to `apps/hosted-relay`, framework preset to Other and Node.js version to 24. The included `vercel.json` routes the API through a stateless Node function. Choose a region near your Supabase database if you configure regions.
5. Add `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` and `JJ_VAULT_RELAY_TOKEN` to that project's private server environment. See [the environment example](../apps/hosted-relay/.env.example). No variable uses a browser public prefix. Never commit populated environment files. Use the canonical `https://<20 character project reference>.supabase.co` project origin with no path, query, fragment or alternate port. Custom Supabase domains and local Supabase URLs are intentionally rejected by this package.
6. Deploy only to your own Vercel project when you choose. This repository does not deploy automatically on your behalf. Preserve bearer authentication. Additional Vercel deployment protection can block native sync clients that do not implement its separate authentication, so verify the full client path with your chosen protection settings.
7. In a disposable local JJ Vault instance, use the HTTPS Vercel origin as the relay URL and your independent relay token as the relay token. Configure these through the current desktop sync controls or supported CLI. The relay URL is only the origin, without `/vault` or another path. Keep your existing local vault and backups intact.

The new Supabase secret key format beginning `sb_secret_` is supported, as is the legacy JWT service role key. Anonymous and publishable keys cannot access the private relay RPC functions. Never put the service key into a desktop relay setting, Chrome extension, browser bundle, share link or agent credential.

## Verify before storing important data

Run the hosted package tests locally:

```sh
cd apps/hosted-relay
npm test
npm run test:postgres
```

The PostgreSQL test needs local `initdb`, `pg_ctl` and `psql`. It creates and removes a separate local database cluster. It does not use your environment's database URL or contact Supabase.

For your own hosted setup, use a disposable vault containing synthetic data. Confirm that missing and incorrect relay tokens fail, a correct token can read the initial empty relay, sync can upload and retrieve the same encrypted vault, stale revision writes fail, encrypted shares open and revoke correctly, and another client sync preserves the expected data. Restarting or redeploying the function must preserve the stored revision. Inspect your build output to ensure no private environment value entered public assets.

Confirm the Supabase anonymous and authenticated roles cannot read either private table or execute any relay RPC. Confirm that service key access works only where intended. Verify your selected hosting protection, billing and backup settings. These operator checks remain necessary after the local tests pass.

## Size limits and client behavior

The hosted relay accepts at most 2 MiB of ciphertext per vault or share and at most 3 MiB of JSON per request or response. Base64 adds about one third to ciphertext size. The local relay supports larger vaults, so document heavy vaults can work locally and exceed the hosted limit. There is no chunked upload, external attachment store or automatic fallback in this package.

An oversized vault upload receives HTTP 413. The authenticated `/status` response advertises `limits.ciphertextBytes` (2097152) and `limits.jsonBytes` (3145728). The sync client in this source validates those capabilities and checks its local encrypted export before requesting the remote vault. The vault engine also measures the proposed merged export before changing current vault data or writing it to disk. Both ciphertext and JSON limits are checked. A size rejection leaves the local vault unchanged. Older clients can merge successfully and then fail when uploading a larger result, so use the current verified desktop source with this relay.

Vercel currently documents a 4.5 MB function request and response body cap. The relay chooses lower limits so both the base64 payload and its JSON wrapper stay within that boundary. A large vault needs a different storage protocol, with separate client and server implementation, before this hosted package can accept it. [Vercel function limits](https://vercel.com/docs/functions/limitations)

## Recovery, rotation and scope

Keep independent encrypted vault backups and a separate safe copy of your Secret Key. Hosted ciphertext is not a recovery key. If you lose the information required to unlock your vault, this relay cannot recover it.

To rotate the relay token, generate a new one, replace `JJ_VAULT_RELAY_TOKEN` in your Vercel environment, redeploy and update your trusted local sync clients. A token rotation does not change the vault encryption keys. Rotate the Supabase service key independently if it is exposed. Revoke encrypted shares separately when needed.

There is no automatic migration from an existing local relay file. First sync the intended vault into a fresh private hosted relay using a disposable test of the procedure. Keep the original relay and encrypted backups until you have verified your migration. No operation in this package changes the local app's default mode.

One deployment has one vault slot and one owner bearer. It is unsuitable as a shared service for unrelated owners. Share expiry controls retrieval, with expired rows removed on a later share creation. Copies in recipient browsers and database backups follow their own retention.

Verified locally on October 21, 2026: all 11 HTTP and unit test groups passed under Node.js 24.19.0, and all 7 permanent database integration groups passed against local PostgreSQL 17. Four additional integration groups exercise the current sync client and actual vault engine through the hosted HTTP handler. They verify encrypted sync across paired engines, capability checks before remote retrieval, unchanged local data and disk when a merged union exceeds either size limit, and rejection of malformed limits. These checks run in the desktop `npm test` suite. The database checks include twelve concurrent writers, privilege restrictions, every null envelope and KDF field, write failure rollback, share expiry and revision bounds. A separate synthetic test used the actual JJ Vault core to encrypt and decrypt a vault after its envelope passed through PostgreSQL JSONB. A real Chrome check confirmed share decryption after a transient first request failure, with the key removed from the address bar and absent from all server requests.

A real Supabase gateway, Vercel deployment, hosted phone workflow and full hosted password manager are separate boundaries that have not been verified by those tests. No account, hosting project or live vault was used for the local checks.

## Implementation references

The function uses the documented Node Web Request export and rewrite mechanism. [Vercel Node runtime](https://vercel.com/docs/functions/runtimes/node-js)

RPC functions use a fixed empty search path and explicit execution grants. Private tables have RLS enabled. [Supabase database functions](https://supabase.com/docs/guides/database/functions), [Supabase RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)
