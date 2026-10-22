# Agent access

Unlock JJ Vault in the Mac app. Create an agent, choose its vaults and permission level, and enable agent access on those vaults. If item approval is enabled, approve the intended items too. Use a separate identity for each agent.

After creation, the app displays a command ending in `check CLIENT`, where `CLIENT` is the registered client name. Copy the whole command. It contains the actual helper path, private token folder, and local service port. A packaged app uses its bundled runtime. A source installation uses Node from your `PATH`.

Run the copied command to check the connection. Preserve its environment and runtime prefix when changing commands. Replace only the trailing `check CLIENT` with one of these forms:

| Command suffix | Result |
| --- | --- |
| `check CLIENT` | Check the local service and expected tools |
| `list CLIENT` | List metadata for allowed logins |
| `get CLIENT 'Exact login name'` | Retrieve username, password, and any current authenticator code |
| `search CLIENT 'query'` | Search allowed item metadata |
| `generate CLIENT < input.json` | Generate a password from a JSON request |
| `add CLIENT < input.json` | Add a login if permissions allow |
| `update CLIENT < input.json` | Update a login if permissions allow |
| `delete CLIENT 'Exact login name'` | Move a login to Recently Deleted if permissions allow |

The helper reads the named agent token from its private pairing file. Never put a token, password, authenticator seed, or other secret in command arguments. Keep sensitive JSON input private and pass it through standard input. Avoid writing retrieved credentials to logs, messages, screenshots, or shared files.

A generation request can contain:

```json
{"length":32,"options":{"symbols":true}}
```

An update request can contain:

```json
{"name":"Example account","fields":{"password":"synthetic replacement"}}
```

The app offers these permission levels:

| Permission | Allowed actions |
| --- | --- |
| `read` | Read permitted logins, search, and generate passwords |
| `read_add` | Read actions and add logins |
| `read_add_edit` | Read, add, and edit logins |
| `full` | Read, add, edit, and delete logins |

Vault access, item approval, travel settings, and protected item restrictions also apply. Login retrieval is limited to 10 requests per hour for each agent. Writes are limited to 30 per hour. The app records access attempts and allows the owner to edit permissions or revoke an identity.

The Mac app must remain running and the vault must be unlocked. The helper never unlocks the vault, changes owner permissions, or bypasses a website's verification requirements. If the service is unavailable, open the app and retry. If access is denied, review that agent's permissions in the app.

Granting a token does not create an operating system sandbox. An agent running under your account may already be able to read other files available to that account. Use an appropriate account or process boundary when you need stronger isolation.
