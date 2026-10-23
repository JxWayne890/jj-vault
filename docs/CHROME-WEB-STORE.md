# Chrome Web Store submission

Prepared October 23, 2026. This is a submission handoff, not an approved store listing.

## Package and images

Run `npm run package:chrome` after installing the locked dependencies. It creates both the existing manual installation ZIP and a separate Store upload ZIP:

```text
release/JJ-Vault-Chrome-WebStore-0.1.0.zip
release/JJ-Vault-Chrome-WebStore-0.1.0.zip.sha256
```

Upload the WebStore ZIP. Its `manifest.json` is at the archive root. The manual ZIP has an enclosing folder and installation text and is intended for Load unpacked installation. Both formats include only selected public runtime files. They exclude source maps, local configuration and vault data.

Store graphics are generated separately into `release/chrome-web-store`. Screenshots use the production popup with synthetic demonstration data, not an owner's vault. Review them before uploading.

## Listing text

Name: JJ Vault

Language: English

Suggested category: Productivity, using the closest available category in the dashboard.

Short description:

```text
Fill logins, authenticator codes, cards and addresses from your private JJ Vault Mac app.
```

Detailed description:

```text
JJ Vault connects Chrome to your private JJ Vault Mac app so you can choose what gets filled.

Fill a matching saved login, a current authenticator code, a card or an address. After submitting a login form, review the save offer and choose whether to save a new entry or update an existing one. Nothing is saved until you confirm.

The Mac app applies your vault's Browser autofill permissions and refuses browser access while locked. The extension communicates with the app through a paired native host on your Mac. It contains no advertising or analytics system and does not send credentials or browsing activity to a developer server.

Requirements: an Apple Silicon Mac, Chrome 120 or later and the separate JJ Vault Mac app. The Mac app currently installs from source and must remain running and unlocked. Pair the extension's ID in the Mac app before use. This extension does not include the Mac app.

This is an early beta. iPhone and Safari support remain experimental. The optional encrypted relay is separate and does not provide a complete hosted vault or agent access while the Mac is off.

Source and Mac app setup: https://github.com/JxWayne890/jj-vault
Chrome setup: https://github.com/JxWayne890/jj-vault/blob/main/docs/CHROME-SETUP.md
Privacy: https://github.com/JxWayne890/jj-vault/blob/main/docs/PRIVACY.md
```

Homepage: <https://github.com/JxWayne890/jj-vault>

Support URL: <https://github.com/JxWayne890/jj-vault/issues>

Privacy policy URL: <https://github.com/JxWayne890/jj-vault/blob/main/docs/PRIVACY.md>

## Privacy practices

Single purpose:

```text
Connect Chrome to the owner's separate JJ Vault Mac app to fill selected vault information on matching HTTPS pages and review submitted logins before saving or updating them.
```

Permission justification for `nativeMessaging`:

```text
Communicate with the paired JJ Vault native host on the user's Mac. The host relays authenticated requests to the running local Mac app to list permitted items, retrieve an explicitly selected item and save a reviewed login. The Mac app enforces unlocked state and per vault browser access.
```

Host permission justification for `https://*/*`:

```text
Users save logins for arbitrary HTTPS websites. Content scripts identify visible compatible fields, fill only an explicitly selected item on its matching website, and offer review of a submitted login. The popup uses the current page URL to match items and reject a changed page. The extension does not maintain a browsing history or use browsing information for advertising.
```

The Chrome build requests no `tabs` or `activeTab` permission. HTTPS host permissions already provide the matching tab metadata used by this extension. Other browser builds retain their existing declarations.

Remote code: No. All executable JavaScript is bundled in the package. The extension's content security policy blocks remote connections from extension pages and the extension downloads no executable code.

Disclose these handled data categories even though processing stays on the device:

* Personally identifiable information, including usernames, email, names, addresses and contact fields used for filling.
* Authentication information, including login passwords and current authenticator codes.
* Financial and payment information, when a card is selected to fill.
* Web history or browsing activity, limited to the current page URL and matching or captured login URL.
* Website content, limited to form field metadata, submitted login fields and the page title needed for these features.
* User activity, limited to local fill and save operation records in the Mac app, if the dashboard's definition covers these records.

Choose the current dashboard categories that correspond to the above. Do not declare that no user data is handled. There is no analytics, advertising, sale of user information, credit scoring or lending use. The publisher should read the final dashboard certifications and confirm that they accurately reflect the submitted package.

## Reviewer instructions

```text
This extension requires its separate local Mac app and native host. It is not a standalone or cloud password manager.

1. On an Apple Silicon Mac, install Node.js 24, npm and Xcode Command Line Tools. Clone https://github.com/JxWayne890/jj-vault, then run npm ci, npm run build and npm start.
2. Create a disposable test vault. Keep its generated Secret Key and password local. No developer account or external vault is required. Do not use real credentials.
3. Enable Browser autofill for the test vault. In Chrome, copy this extension's assigned ID. In the Mac app, open Settings, Browser connection, paste Extension ID and choose Pair extension. Confirm the pairing.
4. Add a synthetic login with a URL matching a controlled HTTPS sign in page. With the app running and unlocked, open the extension and select the matching item. Confirm visible fields fill without submitting the page.
5. Lock the Mac app and verify the extension refuses to retrieve or save an item. Unlock and try again.
6. Submit synthetic login fields on the controlled HTTPS page, review the offer in the extension and choose Confirm save. Verify the new or updated entry in the Mac app. Remove the disposable test data afterward.

Setup: https://github.com/JxWayne890/jj-vault/blob/main/docs/CHROME-SETUP.md
Verification limits: https://github.com/JxWayne890/jj-vault/blob/main/docs/CHROME-VERIFICATION.md
```

## Publisher dashboard

Use the [Chrome Web Store developer dashboard](https://chrome.google.com/webstore/devconsole/). If it asks for registration, use the publisher's chosen Google account, read the developer agreement and complete the displayed registration requirements. Registration can require a fee and agreement acceptance. Those actions require the owner's direct participation or explicit confirmation at the action.

Upload the WebStore ZIP, enter the listing text, upload the store icon and at least one 1280 by 800 screenshot, then complete Privacy practices, Distribution and Test instructions. Select Free and Unlisted. Unlisted items have a shareable store URL but still require Google's review. Confirm that the separate Mac app requirement is visible before submission.

After the upload, Google assigns the store extension ID. Record that ID, and pair it in the Mac app when testing the store build. Do not reuse the developer's unpacked extension ID as the public store ID. Once Google approves and publishes the item, add its actual Add to Chrome URL to the repository. Until then, use the manual beta download and do not describe the extension as store approved.

Official references: [Publishing](https://developer.chrome.com/docs/webstore/publish), [privacy disclosures](https://developer.chrome.com/docs/webstore/cws-dashboard-privacy), [local data disclosures](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq), [store images](https://developer.chrome.com/docs/webstore/images), [unlisted distribution](https://developer.chrome.com/docs/webstore/cws-dashboard-distribution).
