# Security reporting

Report a suspected vulnerability privately. If this repository has GitHub private vulnerability reporting enabled, use **Security**, then **Report a vulnerability**. Otherwise, ask the repository owner for a private reporting channel. A public issue should contain only a request for a private contact.

Include the affected version or commit, operating system, reproduction steps, and expected and observed behavior. Use a new vault with synthetic information when reproducing a problem.

Never include real passwords, authenticator seeds, Secret Keys, agent tokens, vault files, backups, private documents, or environment files in an issue, screenshot, log, or attachment. If a credential may have been exposed, revoke it through the service that issued it.

JJ Vault is an early source release. Automated checks are useful evidence, but they do not establish that the application has received an independent security audit. Review the source and release readiness notes before trusting it with important information. Keep a separate, recoverable backup and verify recovery with a test vault.
