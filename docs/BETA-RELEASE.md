# JJ Vault v0.1.0-beta.1

An early source beta of a personal encrypted password manager for Apple Silicon Macs. Each owner keeps a separate private vault. Local use needs no Supabase or Vercel account.

* Store passwords, private notes and documents, generate passwords and authenticator codes, keep password history and create encrypted backups.
* Connect the manually installed Chrome extension to the running Mac app for explicit filling and reviewed saving.
* Give individual AI agents access to selected vaults, review activity and revoke permissions. The app must remain running and unlocked. Services can still require their own verification.

The owner confirmed Chrome connection, successful login filling, adding a new login in JJ Vault and refusal of browser access while the vault is locked. The route used to save the new entry was not recorded, so extension capture and Confirm save remain separately unverified in the installed popup. Additional form isolation checks have controlled automated coverage. The owner also reports authorized agents filling information from their computers without repeated login requests.

The source has 159 passing core, service and browser tests, with additional installer, desktop, packaging, Swift and hosted relay checks. This release has not received an independent security audit.

Build from source with Node.js 24, npm and Xcode Command Line Tools. Chrome requires Developer mode, manual loading and pairing. No notarized installer or Chrome Web Store download is included.

The optional Supabase and Vercel component stores encrypted snapshots and shares. It does not provide a complete hosted vault or agent access while the Mac is off. iPhone, Safari and Apple AutoFill support remain experimental.

* [Build and run](https://github.com/JxWayne890/jj-vault#build-and-run)
* [Chrome setup](https://github.com/JxWayne890/jj-vault/blob/main/docs/CHROME-SETUP.md)
* [Agent setup](https://github.com/JxWayne890/jj-vault/blob/main/docs/AGENT-COMMANDS.md)
* [Optional hosting](https://github.com/JxWayne890/jj-vault/blob/main/docs/HOSTED-SETUP.md)
* [Verification and limits](https://github.com/JxWayne890/jj-vault/blob/main/docs/RELEASE-READINESS.md)
* [Security reporting](https://github.com/JxWayne890/jj-vault/blob/main/SECURITY.md)

Source is available under the MIT license. Create a test vault and verify encrypted backup restoration before moving important information.
