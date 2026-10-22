# Connect Chrome to JJ Vault

Build and open JJ Vault first:

```sh
npm ci
npm run build
npm start
```

Use a test vault for the first check. Unlock it, add a synthetic login for a controlled website, and enable browser access for that vault.

1. Open `chrome://extensions` in your regular Chrome window.
2. Enable Developer mode, choose **Load unpacked**, and select `dist/extensions/chrome` inside your JJ Vault checkout. Keep that checkout in a stable local folder.
3. Copy the extension ID from the JJ Vault extension card. It contains 32 lowercase letters from a through p.
4. In JJ Vault, open the browser connection settings, enter that ID, and choose **Pair extension**. Confirm the native dialog only after comparing the ID with Chrome.
5. Restart Chrome, pin the JJ Vault toolbar icon, and refresh your test website.

Pairing installs the native host, private launcher, pairing configuration, and Chrome native messaging manifest. It preserves other existing browser pairings. The desktop app supplies its own Electron runtime, so a packaged app's bridge does not need a separate Node installation. Keep the app in its installed location after pairing. Pair again if you move it.

Open the toolbar icon on the test website, choose the matching login, and select **Fill**. Review the filled values and submit the website form yourself. Verify that a locked vault refuses access, then unlock and try again. This manual check establishes that your loaded extension, native bridge, and app work together. Automated source tests alone do not establish that your Chrome profile is connected.

After you submit a password form, the JJ Vault offer can open a review of the captured login. Choose whether to create a login or update an existing item, then select **Confirm save**. The page offer alone saves nothing. Updating an existing login retains its vault and preserves its username when a password change form omits the username.

The offer can follow a login to another HTTPS page on the same exact website and port while the capture remains valid. It does not prove that the website accepted your password. Captures expire after at most 90 seconds, and Chrome may stop its background worker sooner. A changed website, an expired capture, or a save or discard clears the offer. Captures stay in temporary extension memory.

Chrome's own password prompt saves to Chrome. JJ Vault's prompt opens JJ Vault's review. Chrome 127 and later can open the extension popup from the review button. Otherwise, click the toolbar icon. See the [Chrome action API](https://developer.chrome.com/docs/extensions/reference/api/action#method-openPopup) and [service worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).

After rebuilding, return to `chrome://extensions`, choose **Reload** on the JJ Vault card, and refresh your test website. Loading and reloading an unpacked extension are manual Chrome steps. If a different extension ID is assigned, pair the new ID in JJ Vault.

For a source installation, the legacy installer is also available from the checkout:

```sh
npx tsx tools/install-browser-host.ts --chrome EXTENSION_ID
npx tsx tools/install-browser-host.ts --remove-chrome EXTENSION_ID
```

Prefer the app's pairing action when using a custom data directory or service port. The legacy command uses its own runtime and default configuration.

If Chrome reports that the host is unavailable, confirm that JJ Vault is running and unlocked, check browser access for the selected vault, and pair the exact extension ID again. Never share a vault password, Secret Key, or token when asking for help.

Source checks use temporary files and synthetic data:

```sh
npx tsx --test tools/test-browser-install.ts
npm run test:chrome-connection
npm run chrome:check
npm run chrome:check -- --extension-directory "$PWD/dist/extensions/chrome"
npm run test:browser
```

`chrome:check` inspects installation metadata without reading tokens or vault contents. A configured result still requires the manual fill check above. `test:browser` requires Google Chrome installed locally and exercises controlled browser pages rather than your regular Chrome profile.
