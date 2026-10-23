# JJ Vault Chrome extension privacy

Effective October 23, 2026.

JJ Vault connects Chrome to a separate JJ Vault Mac app that you run and control. Its purpose is to fill information you select from your vault and let you review a submitted login before saving or updating it. Each owner keeps a separate vault.

## Information the extension handles

* The current HTTPS page URL and title, used to match vault entries, check that the page has not changed and identify a login you choose to save. A URL can include its path, query and fragment.
* Usernames, passwords and current authenticator codes for a login you select to fill.
* Card details, names, addresses and other identity fields when you select a matching card or identity to fill.
* Visible form fields needed to identify a compatible form and place the selected information.
* A submitted login's username, password, page URL and title, held temporarily so you can review a save offer. A save offer does not establish that the website accepted the login.

The extension does not read your master password, Secret Key, agent tokens, private documents or the whole encrypted vault. The Mac app applies the vault's browser access rules. Browser reads and saves require the app to be running and unlocked.

## Where information goes

The extension communicates with its paired native host on your Mac. That host sends authenticated requests to the local JJ Vault app through loopback. Selecting Fill places the chosen information into visible fields on the current matching HTTPS page. That website then handles the form information under its own practices.

Selecting Confirm save sends the reviewed login to the Mac app for encrypted storage. The Mac app can record browser activity metadata, including the operation, item identifier and timestamp, without recording password values in activity entries. A saved item can contain its website URL.

The extension makes no direct requests to a developer server, analytics service, advertising service, Supabase or Vercel. It contains no advertising or tracking system. The developer does not receive your credentials or browsing activity through the extension.

## Temporary data and retention

Save offers expire after at most 90 seconds and may disappear sooner if Chrome stops the background worker. Background captures are cleared after saving, dismissal, expiration, tab closure or navigation to a different website. An open review popup can retain its temporary copy until it is closed, saved or dismissed; expired offers cannot be saved.

Captures are held in extension memory and are not written to Chrome storage or Chrome sync. The extension clears its temporary references after a fill request. Information already inserted into a website remains part of that page until you or the page change it.

Saved vault items, encrypted backups and local activity records are managed by the separate Mac app. Removing the Chrome extension does not delete the Mac app's vault or backups. You can edit or delete entries in the app, disable a vault's Browser autofill setting, lock the vault or remove a browser pairing. Browser pairing changes do not revoke a website session that is already signed in.

## Optional hosting and agents

The Mac app can separately connect to an owner configured encrypted relay for snapshots and shares. The extension does not configure or directly contact that relay. Owners control their own hosting and backups.

Agent access is a separate Mac app feature with its own vault permissions. Installing this extension does not give an agent access to your vault. A complete hosted vault with agent access while the Mac is off remains future work.

## Limited use

JJ Vault uses information received through Chrome APIs only for the password manager features described here. Its use follows the Chrome Web Store User Data Policy, including the Limited Use requirements. The extension does not sell user information, use it for advertising, or use it to determine creditworthiness or lending eligibility.

## Questions and changes

The source, setup instructions and current policy are available in the [JJ Vault repository](https://github.com/JxWayne890/jj-vault). For a privacy question, open a [support issue](https://github.com/JxWayne890/jj-vault/issues) containing only a request for a private contact channel. Do not include passwords, tokens, vault files or private documents. Follow the [security reporting instructions](../SECURITY.md) for a suspected vulnerability.

Material changes to data handling will be reflected in this policy and the extension's store disclosures. This early beta has not received an independent security audit.
