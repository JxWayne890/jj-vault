# Connect Chrome to JJ Vault

The Chrome extension needs the JJ Vault Mac app running and unlocked. This beta supports Apple Silicon Macs and Chrome 120 or later. The extension ZIP contains only the browser extension. If you need the Mac app, follow [Build and run](../README.md#build-and-run) first.

## Install the downloaded extension

1. [Download JJ Vault for Chrome](https://github.com/JxWayne890/jj-vault/releases/download/v0.1.0-beta.1/JJ-Vault-Chrome-0.1.0.zip). This contains the built extension, so you do not need to compile its JavaScript.
2. Double click the ZIP to extract it. Move the extracted `JJ-Vault-Chrome` folder to a stable local location where you will keep it. Keep the files together, including `manifest.json`.
3. In Chrome's address bar, enter `chrome://extensions` and press Return. You can also open the puzzle piece menu and choose **Manage Extensions**.
4. Turn on **Developer mode** in the upper right. Click **Load unpacked** and select the extracted `JJ-Vault-Chrome` folder. Select the folder containing `manifest.json`, not the ZIP or its parent folder.
5. JJ Vault now appears as a card on Chrome's Extensions page. Copy its **ID**, a string of 32 lowercase letters. Each installation can receive a different ID, so copy your own.
6. In the unlocked Mac app, open **Settings**. Enable **Browser autofill** for the intended vault. Under **Browser connection**, paste the ID into **Extension ID**. Compare that field with the ID on Chrome's card, then choose **Pair extension**. Confirm **Pair extension** in the native dialog.
7. Restart Chrome. Open its puzzle piece menu and pin **JJ Vault** to the toolbar. Refresh your website and open the JJ Vault icon. The popup should report **Connected**.

Keep the Mac app running and unlocked while filling. Keep both the app and extension folder in stable locations. Moving the extension folder can change its ID and require pairing again. Do not delete the folder after loading it.

The matching [SHA256 checksum](https://github.com/JxWayne890/jj-vault/releases/download/v0.1.0-beta.1/JJ-Vault-Chrome-0.1.0.zip.sha256) is included with the release. To check the downloaded ZIP, put the checksum beside it and run `shasum -a 256 -c JJ-Vault-Chrome-0.1.0.zip.sha256` from that directory.

## Build the extension from source

Source developers can build and open the Mac app with:

```sh
npm ci
npm run build
npm start
```

After building, use `dist/extensions/chrome` in step 4 above instead of the downloaded folder. Continue with the assigned ID and pairing steps. To create the downloadable extension package yourself, run:

```sh
npm run package:chrome
```

The command writes the ZIP and its `.zip.sha256` file into `release`. It includes only the selected public runtime files and installation instructions. It excludes source maps, other build files, local configuration and vault data.

## Check the connection

Use a test vault for the first check. Unlock it, add a synthetic login for a controlled HTTPS website, and enable browser access for that vault.

Pairing installs the native host, private launcher, pairing configuration, and Chrome native messaging manifest. It preserves other existing browser pairings. The desktop app supplies its own Electron runtime, so a packaged app's bridge does not need a separate Node installation. Keep the app in its installed location after pairing. Pair again if you move it.

Open the toolbar icon on the test website, choose the matching login, and select **Fill**. Review the filled values and submit the website form yourself. Verify that a locked vault refuses access, then unlock and try again. This manual check establishes that your loaded extension, native bridge, and app work together. Automated source tests alone do not establish that your Chrome profile is connected.

After you submit a password form, the JJ Vault offer can open a review of the captured login. Choose whether to create a login or update an existing item, then select **Confirm save**. The page offer alone saves nothing. Updating an existing login retains its vault and preserves its username when a password change form omits the username.

The offer can follow a login to another HTTPS page on the same exact website and port while the capture remains valid. It does not prove that the website accepted your password. Captures expire after at most 90 seconds, and Chrome may stop its background worker sooner. A changed website, an expired capture, or a save or discard clears the offer. Captures stay in temporary extension memory.

Chrome's own password prompt saves to Chrome. JJ Vault's prompt opens JJ Vault's review. Chrome 127 and later can open the extension popup from the review button. Otherwise, click the toolbar icon. See the [Chrome action API](https://developer.chrome.com/docs/extensions/reference/api/action#method-openPopup) and [service worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).

After rebuilding or replacing the extension files with an updated download, return to `chrome://extensions`, choose **Reload** on the JJ Vault card, and refresh your test website. Loading and reloading an unpacked extension are manual Chrome steps. This beta download does not update itself. If a different extension ID is assigned, pair the new ID in JJ Vault.

## Chrome Web Store installation

This beta uses manual installation. The normal **Add to Chrome** button requires publication through the Chrome Web Store. An **Unlisted** store item can be installed by anyone with its store URL without appearing in store search. Google still reviews unlisted items under the same policies. This project has not published that store listing.

The [Store submission guide](CHROME-WEB-STORE.md) contains the prepared upload format and listing materials. The [privacy policy](PRIVACY.md) describes the extension's handling of local information.

See Google's [extension installation guide](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world#load-unpacked) and [store visibility options](https://developer.chrome.com/docs/webstore/cws-dashboard-distribution). The store listing and its review are separate from making this GitHub source public.

## Source troubleshooting

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
