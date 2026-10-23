# JJ Vault

JJ Vault is a personal password manager for macOS with permissioned access for local AI agents. Each owner runs a separate app and keeps a separate encrypted vault. Local storage is the default. A hosted service is optional.

This is an early source beta candidate. See the [beta release notes](docs/BETA-RELEASE.md), check the [release readiness report](docs/RELEASE-READINESS.md) for the current verification status and read the [security reporting policy](SECURITY.md) before using important information. The candidate combines recovered desktop and Apple source with reviewed release fixes. iPhone, Safari, and AutoFill support remain experimental.

## What it supports

* Encrypted local passwords, private notes, documents, and other vault items.
* Password generation, authenticator codes, password history, encrypted backups, and imports.
* Individual agent identities, selected vault access, permission levels, activity review, and revocation.
* A Chrome extension that connects to the running desktop app for explicit fill and reviewed save actions.
* Apple companion source and an optional encrypted hosted relay, with the limits below.

## Build and run

The supported starting point is a Mac with Apple Silicon, Node.js 24, npm, and Xcode Command Line Tools. Use a normal local checkout and make sure its files have downloaded fully if it lives in iCloud. The Apple companion targets require full Xcode and your own signing setup.

From the checkout:

```sh
npm ci
npm run build
npm start
```

`npm run dev` builds and starts the desktop app in one command. Build before running browser checks. See [build instructions](assets/BUILDING.md) for packaging details. The macOS package targets Apple Silicon. It is not a universal binary.

Create a test vault first. The app stores its data in `~/Library/Application Support/JJ Vault`. Keep the app open and unlocked when using its local browser or agent service. For isolated development, set `JJ_VAULT_DATA_DIR` to a new private folder and `JJ_VAULT_PORT` to a free local port before starting the app.

## Recovery

Save the Secret Key shown during setup and create an Emergency Kit. Recovery needs an encrypted backup, its master password, and its Secret Key. A paired Mac may remember the Secret Key in protected device storage, but that does not replace an independent recovery copy. There is no password reset that can decrypt an existing vault.

Export an encrypted `.jjbackup` file, keep it separately from the Emergency Kit, and verify restoration with a test vault before moving important data. Imports can contain readable credentials, so handle their source files privately.

## Chrome

After building, open `chrome://extensions`, enable Developer mode, and load `dist/extensions/chrome` from this checkout. Copy the assigned extension ID into JJ Vault's browser connection settings and choose **Pair extension**. The app installs its native bridge and uses its own runtime. Restart Chrome and complete the synthetic fill, save, and locked vault checks in the [Chrome setup guide](docs/CHROME-SETUP.md).

An unpacked extension needs manual loading and reloading in Chrome. Keep its folder and the app in stable locations. Source test results alone do not verify a particular Chrome profile.

## Agent access

Create an agent in the app, select its vaults and permissions, and enable agent access for the intended vaults. The app shows a helper command with the correct local runtime, token folder, and service port. Give that command to the intended agent. See [agent commands](docs/AGENT-COMMANDS.md).

The app must be running and the vault unlocked. Agents can retrieve allowed logins again if a service signs them out. The service's verification requirements still apply. Access can be changed or revoked in the app. Tokens authorize the JJ Vault service; they do not isolate an agent from other files that its operating system account can already read.

## Optional hosting and iPhone

The [optional hosted relay](apps/hosted-relay/README.md) can use your own Supabase project and Vercel deployment to store encrypted vault snapshots and encrypted shares. Local use needs neither service. Hosting is a setup each owner manages, and nothing deploys during a normal local build.

The relay does not provide a browser vault interface, remote vault decryption, agent access while your Mac is off, or hosted phone pairing. A complete hosted password manager with agents available around the clock remains future work.

The `apple` directory contains the recovered experimental companion source. This candidate does not establish a verified iPhone, Safari, or AutoFill installation. Those targets require full Xcode, your own signing configuration, and device checks before use. Do not assume App Store distribution or verified support for every Apple device.

## Checks

```sh
npm run typecheck
npm run build
npm test
npx tsx --test tools/test-browser-install.ts
npm run test:chrome-connection
npm run test:hosted-relay
```

Additional local checks include `npm run test:desktop`, `npm run test:agents`, `npm run test:session`, `npm run test:phone`, `npm run test:browser-pairing`, and `npm run test:browser`. The browser flow uses Google Chrome by default. Set `JJ_VAULT_TEST_BROWSER_CHANNEL=chromium` to use an installed Playwright Chromium browser, as CI does. UI and device checks have additional local prerequisites. GitHub Actions runs source checks without deployment secrets. Passing automated checks does not establish an independent security audit.

Source code is available under the [MIT license](LICENSE). Bundled third party components keep their own license notices.
