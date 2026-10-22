# Local Mac packaging

This packaging target requires an Apple silicon Mac, a supported Node.js release, npm, and the Xcode command line tools (including Swift). Start with a complete, readable source checkout and the committed lockfile. Install the locked dependencies and build the native biometric helper before packaging:

```sh
npm ci
npm run build:biometric
npm run package:mac
```

## Locked build dependencies

Use Node.js 24 and the committed lockfile. A scoped override selects `global-agent` 4.1.3 only beneath `app-builder-lib` and its `@electron/get` dependency. This removes the `roarr` and `sprintf-js` chain implicated in [GHSA-hp3w-g68c-fv3c](https://github.com/advisories/GHSA-hp3w-g68c-fv3c), for which `sprintf-js` has no patched version.

The [upstream 4.1 release](https://github.com/gajus/global-agent/releases/tag/v4.1.0) removes `roarr`. It preserves the [`bootstrap` export](https://github.com/gajus/global-agent/blob/v4.1.3/src/index.ts) called by [`@electron/get` 3.1.0](https://github.com/electron/get/blob/v3.1.0/src/proxy.ts). Compatibility was checked on Node.js 24 using a synthetic artifact, a local HTTP proxy, progress callbacks, SHA256 validation, and rejection of an incorrect checksum. Production dependency versions are unchanged. Revisit this override when the packaging tool updates its dependency chain, and repeat the full audit and packaging checks after any lockfile change.

`build:biometric` compiles and signs only the desktop helper. The separate `build:apple` command builds the experimental iPhone and Safari targets and requires full Xcode plus XcodeGen. See the [Apple source guide](../apple/README.md) before using it.

The packaging command builds the application, creates the JJ shield icon, packages the local Electron distribution, signs the app and helper, and verifies startup using an isolated temporary directory. The check creates no vault. It disables protected device storage and uses Chromium's mock Keychain switch so the check does not use the installed app's saved credentials.

Packaging stages by default. The signed app remains inside `~/.cache/jj-vault-build/package-*`, and `release/STAGED-PACKAGE-STATUS.json` records its exact path and verification result. The installed app and release symlink stay unchanged. This target produces an Apple silicon app. It does not produce an Intel or universal binary, publish a build, or request notarization.

## Signing

The default is ad hoc signing. It requires no personal signing certificate and never searches the Keychain for a preferred identity. Ad hoc signing verifies the bundle's integrity locally; it is not a Developer ID distribution signature or notarization.

To use a signing certificate that is already installed on your Mac, explicitly configure its exact name or SHA1 fingerprint:

```sh
JJ_VAULT_SIGN_IDENTITY='Developer ID Application: Example Company (EXAMPLE123)' npm run package:mac
```

The script checks public signing identity metadata only when this variable is configured. An unavailable identity, a failed identity lookup, an empty value, or `-` causes the packaging script to fail before it creates staging files. Omit the variable to request ad hoc signing. The package status records the signing result. A configured certificate does not enable notarization.

The app identifier remains `com.john.jjvault`, and the native biometric helper identifier remains `com.john.jjvault.biometric`. Changing either identifier can affect existing macOS permissions and Keychain access. Preserve them when preparing updates for an existing installation.

For an existing biometric enrollment, use the same explicit owner signing identity for both `npm run build:biometric` and packaging. An ad hoc helper is suitable for local development, but its identity can change when rebuilt. These build commands do not enroll biometrics or change the installed app's protected storage.

## Explicit installation

Only the explicit installation option permits the packaging script to replace `~/Applications/JJ Vault.app`:

```sh
npm run package:mac -- --install
```

Close the current app before choosing installation. An existing app is preserved beside it with a timestamped name. The installed path remains outside iCloud managed Documents. `release/mac-arm64/JJ Vault.app` becomes a symlink to the installed app, and `release/PACKAGE-STATUS.txt` records the verification result. Packaging does not migrate or initialize your personal vault.

The legacy `JJ_VAULT_STAGE_ONLY=1` environment variable still requests staging. Combining it with `--install` is an error. Unknown arguments and duplicate installation options also fail before the packaging script creates files.

To package an already built checkout without rebuilding it:

```sh
./node_modules/.bin/tsx tools/package-mac.ts
```

## Generated resources

The SVG is the editable icon source. `assets/render-icon.swift` draws its native raster counterpart, and macOS `sips` and `iconutil` create the icon package. Certificate signing uses the JIT entitlement. Ad hoc signing also disables library validation because the Electron frameworks carry a different signing identity.

The script stages outside iCloud, removes generated Finder metadata, signs nested Mach code before frameworks and app wrappers, then verifies the complete resource seals. Locale resource packs remain covered by their containing framework seal.

## iCloud managed source folders

If source files show the `dataless` filesystem flag, download the full checkout in Finder before building. A cached build output does not replace missing source files.

If only generated dependencies are offloaded, keep the source in place and prepare dependencies in the local cache:

```sh
node tools/prepare-build-dependencies.mjs
```

This installs the exact committed lockfile from the npm cache, verifies the cached Electron archive checksum, extracts that archive, and creates a `node_modules` symlink to `~/.cache/jj-vault-build`. It preserves the previous dependency tree with a timestamped name. Run it while other builds and tests are stopped. It changes no source files or dependency versions.

If a required npm package or Electron archive is missing from the local cache, permit downloads of the locked versions:

```sh
node tools/prepare-build-dependencies.mjs --online
```

Keep preserved dependency folders until the local cache build passes. They are not bundled in the Mac application.

Development signing, distribution signing, and notarization are separate operations. See the [Electron signing guidance](https://www.electronjs.org/docs/latest/tutorial/code-signing) for distribution requirements.
