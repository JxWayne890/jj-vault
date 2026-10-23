# JJ Vault release candidate

Review updated: October 23, 2026.

Status: private source candidate. The owner has confirmed that the loaded Chrome popup reports Connected. Live filling and saving still require verification. iPhone, Safari and AutoFill support remain experimental. The optional hosted component is an encrypted relay, and a full hosted password manager remains future work.

No Vercel or Supabase project was created or changed. The tested app was installed locally with the previous app backed up, and the owner vault was not moved or replaced. Functional tests used disposable synthetic data. The live native host probe requested an invalid item ID and was rejected before lookup; no saved owner credentials were retrieved.

## Changes prepared

* Browser pairing now installs the private native host, launcher, configuration and Chrome manifest, with the actual service port and bundled runtime. Cancellation makes no installation.
* Agent creation installs its helper and displays a command using the actual token folder and service port. Packaged builds use their own runtime. Commands handle spaces, apostrophes and macOS folder aliases.
* New vault defaults and setup instructions are generic. Existing vault names, data and bundle identifiers are preserved.
* Optional Supabase storage uses private tables and narrowly granted RPC functions. Vercel serves ciphertext without a local computer acting as the relay. Sync checks hosted size limits before retrieval and before committing a merged vault.
* Packaging stages by default with ad hoc signing. Installation requires an explicit option. No personal signing identity is selected automatically.
* The source has an MIT license, security reporting guidance, source checks and GitHub Actions verification. Generated artifacts, local configuration and original project history are excluded.

## Verification evidence

| Check | Result |
| --- | --- |
| Fresh locked dependency installation | Passed |
| TypeScript checking and desktop plus extension build | Passed |
| Core, service and browser suite | 159 passed, zero failures |
| Browser host installer | 11 passed, zero failures |
| Packaging options and mutation guards | 11 passed, zero failures |
| Read only browser connection diagnostic fixtures | 17 passed, zero failures |
| Desktop creation, edits, backups, restoration and permissions | Passed |
| Agent UI, displayed command and actual helper operations | Passed |
| Browser Pair action and generated Electron native host | Passed in an isolated home |
| Protected session resume and lock behavior | Passed with synthetic OS adapters |
| Phone pairing UI and pinned TLS exchange | Passed with disposable fixtures |
| Controlled Chrome content and popup flows | Passed with a mocked extension bridge |
| Hosted relay HTTP and unit groups | 11 passed, zero failures |
| Actual PostgreSQL migration and integration | 7 groups passed in a disposable PostgreSQL 17 cluster |
| Current client and engine through the hosted HTTP handler | 4 groups passed within the service suite |
| Swift core and JavaScript interoperability | 17 tests passed across the suite and optional interoperability run |
| Native biometric helper compilation and signature verification | Passed |
| Ad hoc Mac app packaging, signature and isolated startup | Passed |
| Packaged agent helper without Node on PATH | Passed |
| Packaged browser pairing and actual Electron bridge | Passed |
| Actual installed Chrome popup to local app | Owner confirmed Connected |
| npm dependency audit | Zero findings across production and build dependencies |

Desktop checks exercise actual local services, encrypted files and native framing with synthetic credentials. Browser pairing checks exercise the actual desktop handler and generated Electron launcher, including caller rejection and locked or disabled vaults. The controlled Chrome flow checks exact website matching, login and authenticator filling, cards, identity, hidden fields, foreign forms, frames, navigation changes and explicit save review. Its mocked bridge does not establish live Chrome behavior. A separate owner confirmation now establishes the actual popup connection; live fill and save checks are still pending.

Real Keychain enrollment, Touch ID, an iPhone installation and a deployed Supabase gateway or Vercel function were not tested. Local passing checks do not establish an independent security audit.

## Remaining release boundaries

The original Chrome bridge installation was incomplete. The owner has since loaded the extension, provided its ID and confirmed Connected after the local pairing was corrected. The browser tool still rejects internal extension management pages, so the owner supplies that UI evidence. Complete the remaining fill, save and denial checks described in [Chrome verification](CHROME-VERIFICATION.md).

Each owner keeps a private vault and can choose their own optional hosting. The relay accepts at most 2 MiB of ciphertext and 3 MiB of JSON. Document heavy vaults can exceed that limit. The client rejects an oversized local or merged export without changing local data. See [hosted setup](HOSTED-SETUP.md).

The relay provides encrypted storage and encrypted shares. It does not provide a web vault, hosted unlock, remote agent decryption, agents while the Mac is off, or hosted phone pairing. Those features require further implementation and verification before they can be offered as available.

A staged Mac app is for local verification. Ad hoc signing is not Developer ID signing or notarization. A downloadable distribution needs appropriate signing and distribution checks. Apple companion source is included, but device support must be verified separately.

## Source provenance and publication

Parts of the original working folder were iCloud placeholders. The candidate was assembled outside iCloud from resident current files, Git blob verified files, preserved source write inputs and independently readable source snapshots. The recovered desktop base reproduced all five installed desktop artifacts byte for byte before the reviewed fixes were applied. Latest Apple recovery was checked against preserved source changes and available metadata. The physical bytes of every offloaded working file could not be compared independently.

All candidate source is resident and testable. The original folder and history remain preserved. The candidate uses fresh Git history with selected source only. Internal recovery records, generated screenshots, dependencies, built applications, tokens and vault data are excluded. The automated preflight checks source metadata, selected literal signatures and the release index. Its result is an assembly check, not security certification.

Keep this candidate private until the remaining live Chrome check and the intended source visibility are settled. Do not describe it as a completed hosted password manager or verified iPhone release.
