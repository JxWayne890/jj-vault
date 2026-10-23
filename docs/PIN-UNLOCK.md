# PIN unlock on Mac

Choose any PIN containing exactly 4, 5, or 6 ASCII digits. Leading zeroes are preserved. The setup prompt appears after you save the initial Secret Key or unlock with your master password on a Mac without a PIN. You can skip the prompt and enable PIN unlock later in Settings.

The PIN belongs to this Mac. It is excluded from encrypted backups, sync, browser extensions, and agent connections. Existing vaults keep their current encryption format, master password, Secret Key, items, and access rules.

## Everyday use and recovery

With PIN unlock enabled, the locked screen asks for your PIN. You can choose the master password recovery option, using the remembered Secret Key or entering it again when needed. Settings can change the PIN after verifying the current PIN or master password. Removing the PIN requires the master password. Keep both recovery secrets and an independent encrypted backup.

Manual Lock retains the PIN enrollment. Closing the app window locks it before hiding or quitting. Restarting always starts locked when a PIN is configured, including when Lock after idle is Never. Never still leaves an open app unlocked until you close or lock it. Touch ID remains an optional unlock method.

Backup restoration clears the saved PIN and automatic session cache before replacing the vault. The desktop verifies the backup secrets before clearing those caches. Offline CLI restoration also clears both caches and requires recovery secrets at the next unlock. A replacement vault cannot inherit a prior vault's PIN enrollment.

## Protection

The existing vault key continues to come from the master password and random Secret Key. PIN enrollment wraps a copy of that key with AES 256 GCM using a fresh salt and nonce. Scrypt derives the wrapping key with cost 32768, block size 8, parallelism 1, and a fixed memory limit. The protected payload is then encrypted with Electron safeStorage. On macOS, that service uses Keychain protection. See the [Electron safeStorage documentation](https://www.electronjs.org/docs/latest/api/safe-storage/) and [Node cryptography documentation](https://nodejs.org/docs/latest-v24.x/api/crypto.html#cryptoscryptsyncpassword-salt-keylen-options).

The cache binds to the vault identity and all its key derivation inputs. Ordinary item edits do not change that identity. Storage accepts only private files owned by the current user, rejects links and unsafe paths, bounds reads, and replaces files atomically. Unavailable OS encryption, damaged data, or failure to persist an attempt prevents PIN access. PINs and master passwords are never saved in the cache, returned in application state, or written to activity logs.

Repeated incorrect PINs introduce increasing delays. Attempt state is authenticated by OS protection and saved before verification, so quitting or restarting does not reset the counter. A successful PIN resets the counter. Recovery with the master password remains available during a delay.

A short PIN has limited possible values. OS protection is essential, and the PIN never replaces the strong recovery secrets used for vault encryption. The delay is enforced by this application. It does not protect against an attacker who controls your operating system account, modifies the application, or restores older cache files. JJ Vault remains an early source beta without an independent security audit.

## Verification

`npm test` covers PIN storage, failure delays, persistence, unsafe paths, damaged caches, unavailable OS protection, and restore invalidation. `npm run test:pin` exercises the actual Electron application with disposable synthetic data and an OS encryption test adapter. It covers setup, leading zeroes, incorrect PINs, change, recovery, removal, manual locking, closing and reopening, and cold restart with Never selected.

The tests do not read an owner's vault or enroll a real Keychain item. Live Keychain prompts and Touch ID still require an owner device check. The experimental Apple companion retains its existing unlock flow.
