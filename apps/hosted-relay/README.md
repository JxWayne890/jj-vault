# JJ Vault optional hosted relay

This optional server stores ciphertext in your own Supabase project and serves the existing JJ Vault relay API through your own Vercel project. One deployment belongs to one owner. Your local app keeps working without it.

The relay stores an encrypted vault envelope and encrypted temporary shares. It never receives your master password, Secret Key or decrypted vault content. It has no web vault, remote agent service or hosted unlock session. Keeping this relay online does not let agents decrypt your vault while your Mac is off.

Setup and limitations are in [the hosted setup guide](../../docs/HOSTED-SETUP.md). Nothing is deployed by installing or testing this directory.

## Verification

Use Node.js 24.

```sh
cd apps/hosted-relay
npm test
```

The HTTP tests use generated synthetic credentials and a disposable in memory test store. They cover bearer authentication, origin rejection, strict encrypted envelope validation, payload limits, revision conflicts, storage failures, ciphertext round trips and encrypted shares.

For the actual SQL migration, permissions and concurrent database writes, install local PostgreSQL tools and run:

```sh
npm run test:postgres
```

This creates a new local PostgreSQL cluster on a private Unix socket, tests it and removes it. It never connects to an existing or remote database. It requires `initdb`, `pg_ctl` and `psql` on your PATH. The database test does not require Docker, Supabase credentials or Vercel credentials.

Local tests do not establish that your deployed Supabase gateway, Vercel routing, environment variables or network restrictions are correct. Verify a disposable vault against your own deployment before uploading important data.

Verified locally on October 21, 2026: all 11 HTTP and unit test groups passed under Node.js 24.19.0. All 7 permanent PostgreSQL integration groups passed against a fresh local PostgreSQL 17 cluster. A separate synthetic check encrypted a vault with the actual JJ Vault core, stored its envelope in PostgreSQL JSONB and decrypted the retrieved envelope successfully. A real Chrome check confirmed that the share viewer recovers from an injected first request failure on the next click, decrypts on the device, strips the URL fragment and never transmits its key to the server.

## API

| Method | Path | Access | Result |
| --- | --- | --- | --- |
| GET | `/` | Public | Static explanation of this relay |
| GET | `/status` | Relay bearer | Revision, vault identifier and hosted byte limits |
| GET | `/vault` | Relay bearer | Revision and encrypted envelope |
| PUT | `/vault` | Relay bearer | Atomic expected revision update |
| PUT | `/share/:id` | Relay bearer | Create encrypted share |
| GET | `/share/:id` | Public unguessable share identifier | Ciphertext until expiry or revocation |
| DELETE | `/share/:id` | Relay bearer | Revoke share |
| GET | `/s/:id#key` | Share link | Browser viewer that decrypts locally |

The pairing endpoint `/pair` is unavailable. Hosted phone pairing requires a separate enrollment design. Current local phone pairing and the Chrome extension continue to use the desktop service.

All JSON requests and responses are limited to 3 MiB. Vault and share ciphertext are limited to 2 MiB before base64 encoding. The authenticated `/status` response advertises these boundaries as `limits.ciphertextBytes` and `limits.jsonBytes`. These are smaller than local relay limits. Large documents can exceed this hosted limit. There is no object storage or chunking fallback.

The server returns HTTP 409 for stale revisions, HTTP 413 for an oversized vault upload, HTTP 401 for a missing or incorrect bearer and HTTP 503 when configuration or persistent storage is unavailable. Invalid encrypted shares return HTTP 400, including shares exceeding the ciphertext limit. Detailed upstream errors and payloads are never logged or returned.

## Security boundary

The relay bearer allows its holder to read encrypted vault data, replace that data and create or revoke shares. It is separate from each agent credential and from your Supabase secret key. It cannot unlock a vault. Keep it private and rotate it if exposed.

The Supabase secret key exists only in the server environment. The private tables have RLS enabled with no public policies, no direct table grants to application roles and RPC execution granted only to `service_role`. The database commits each revision update atomically under a row lock. Vercel process memory and its filesystem hold no durable state.

Share recipients receive a URL fragment containing the decryption key. The fragment stays in their browser and is removed from the address bar before retrieving ciphertext. The recipient needs the entire link. Anyone who has the complete link can open the share while it remains available. Revocation and expiry stop new retrieval, and cannot erase copies already downloaded. Expired ciphertext is pruned when a new share is created, and may remain in database backups according to the operator's retention settings.

The shared item viewer is delivered by the hosting operator. A compromised host could change the viewer to capture a recipient's share key. Keep the deployment and its administrators trusted, and verify shared ciphertext in a trusted local JJ Vault client when that threat matters. The server never decrypts the owner vault.

There is no account signup, tenant isolation, per agent authorization or rate limiter in this relay. Each user must run a separate project with separate secrets. Configure hosting abuse controls and usage limits appropriate to your own project. Hosting operators can see request timing, IP addresses, ciphertext sizes and unguessable share identifiers, and can delete or replay stored encrypted data. Keep independent encrypted backups.
