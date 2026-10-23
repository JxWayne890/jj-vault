# Chrome verification

Verification updated: October 23, 2026.

The Chrome source and desktop pairing flow pass the checks below. The owner loaded the extension manually, provided its ID and confirmed that the actual Chrome popup reports Connected after pairing on October 23. A live fill and save through that popup remain unverified.

The tested app was installed locally with the previous app preserved as a backup. The owner vault was not moved or replaced. Automated functional tests use synthetic data. A real native host probe authenticated to the running app and was rejected for an invalid item ID before any item lookup. The read only connection diagnostic opens no saved login, vault or browser token.

## Completed checks

| Check | Result | Evidence |
| :--- | :--- | :--- |
| Browser matching, field mapping and save offer tests | 10 passed | Controlled source fixtures |
| Connection error guidance | 7 passed | Missing hosts, forbidden extension IDs, stopped apps, locked vaults and bounded fallback messages |
| Native host installer | 11 passed | Private installation, safe paths, runtime and asar source checks |
| Desktop Pair extension action | Passed | Actual handler, cancellation, generated native frames, wrong caller, locked and disabled vaults |
| Controlled Chrome content and popup flow | Passed | Synthetic pages with a mocked native bridge |
| Extension build | Passed | Bundles generated from the resident candidate |
| Baseline installed bundle comparison | Passed | Background, content and popup hashes matched stable local assets |
| Connection diagnostic fixtures | 17 passed | Bounded reads, permissions, origins, launchers, safe source directories and missing files |
| Current local connection diagnostic | Configured | All eight selected files and launcher contracts pass |
| Actual native host to app probe | Passed | Paired caller and browser token accepted, invalid item rejected before lookup, wrong caller refused |
| Actual Chrome popup connection | Confirmed by owner | Popup reports Connected after refreshing the corrected pairing |

The controlled Chrome flow checks username, current password and authenticator codes, cards, identity fields, hidden fields, foreign forms, navigation changes, frames and trusted submit capture. Popup tests check explicit fill, top frame targeting, explicit save, preservation of a username during a password only update, and cancellation after navigation.

The isolated pairing test uses the actual desktop handler, generated launcher, Electron runtime and local vault service. The automated Chrome flow supplies a mocked native bridge. The owner confirmation separately establishes that the regular Chrome extension can reach the registered native host and app. Filling, saving and denial checks through that actual popup still require a live controlled flow.

## Read only connection diagnostic

Run from the source directory:

```sh
node tools/check-browser-connection.mjs
node tools/check-browser-connection.mjs --json
node tools/check-browser-connection.mjs --extension-directory "$PWD/dist/extensions/chrome" --json
node --test tools/check-browser-connection.test.mjs
```

The package commands are `npm run chrome:check` and `npm run test:chrome-connection`.

By default, the diagnostic checks these fixed paths under the current user's home directory:

```text
Library/Application Support/JJ Vault Browser/chrome/manifest.json
Library/Application Support/JJ Vault Browser/chrome/background.js
Library/Application Support/JJ Vault Browser/chrome/content.js
Library/Application Support/JJ Vault Browser/chrome/popup.js
Library/Application Support/Google/Chrome/NativeMessagingHosts/com.john.jjvault.json
Library/Application Support/JJ Vault/browser-host.json
Library/Application Support/JJ Vault/jjvault-browser-host
Library/Application Support/JJ Vault/native-host.cjs
```

These locations follow `tools/install-browser-host.ts`. The native manifest, pairing configuration, launcher and deployed host are now installed. The owner loaded the extension from the source build directory, which is supplied explicitly to the diagnostic below.

For a fresh source build loaded from `dist/extensions/chrome`, supply `--extension-directory "$PWD/dist/extensions/chrome"` or use `npm run chrome:check -- --extension-directory "$PWD/dist/extensions/chrome"`. The supplied directory must remain within your home folder, with no symbolic file or directory links. Public extension build files may use mode `0644`, but must belong to you and cannot be writable by other users. Bridge installation files still require private permissions. This option changes only the four extension file locations; the native manifest and data files still use the default paths above.

The diagnostic inspects file and directory metadata, bounded public configuration, selected extension manifest fields, and both supported launcher formats. It accepts the legacy direct runtime launcher and the current `/usr/bin/env` launcher. The current format must set `JJ_VAULT_BROWSER_CONFIG` to the exact expected pairing file, may additionally set only `ELECTRON_RUN_AS_NODE=1`, and must use the expected native host path. It verifies Chrome ID syntax, exact allowed origins, file ownership, safe permissions, and the launcher runtime path. Runtime binaries may use a safe symlink. Writable runtime paths fail the check, except for root owned temporary directories with the sticky bit.

On macOS, nonempty metadata with zero allocated disk blocks returns `offloaded` before the file is opened. This conservatively includes sparse files, and avoids triggering an iCloud download that could stall a read only check. Make required metadata available locally before repeating the diagnostic.

It never executes the launcher or runtime, opens the JavaScript bundles or native host code, connects to the service, reads a browser token, or opens vault data. Output contains counts, public version metadata, and fixed status labels. It does not include extension IDs, usernames, configuration contents, tokens, or passwords. Home and owner fixture overrides are available only through the imported test function, never command line arguments.

An incomplete or unsafe setup returns a nonzero exit code. A configured result means these selected installation checks passed. Every result keeps `liveAutofillVerified` set to `false`. Bundle integrity, extension loading, service availability, and live filling require separate checks.

## Remaining live verification

Installation and the Connected popup status are confirmed. Before claiming live autofill and saving are verified, run a controlled flow using a temporary vault and synthetic credentials. Setup instructions remain in [CHROME-SETUP.md](CHROME-SETUP.md).

1. In regular Chrome, confirm JJ Vault is loaded, enabled, and has no extension errors. Pair the exact extension ID with the local native host.
2. Run the connection diagnostic and resolve every failure. Confirm the JJ Vault app is running and browser access is enabled only for the temporary vault.
3. On a controlled HTTPS login page with an exact saved origin, open the real toolbar popup and fill a synthetic username, password, and authenticator code. Confirm filling does not submit the form.
4. Confirm the real bridge refuses access when the vault is locked or browser access is disabled. Confirm another vault's items do not appear.
5. Confirm a different hostname, alternate port, changed page, foreign form, hidden field, or frame cannot receive the saved login.
6. Submit synthetic credentials, review the save offer, and confirm the vault changes only after Confirm save. Verify a password only update preserves the existing username.
7. Confirm activity records the expected browser actions without including credentials. Remove the temporary fixture records after verification.

Record the Chrome version, extension ID privately, diagnostic result, tested actions, and any failures. A successful controlled flow with the real installed bridge is the remaining evidence needed for a live Chrome confirmation.
