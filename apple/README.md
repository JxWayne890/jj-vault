# JJ Vault Apple source

This directory contains the recovered source for the desktop biometric helper, iPhone app, iOS AutoFill provider, Safari companion, and macOS credential provider. The iPhone, Safari, and AutoFill targets remain experimental. A successful compile or unit test does not establish that installation, biometric approval, phone pairing, or website filling works on a particular device.

The latest source was reconstructed from readable source caches and authored source write inputs. Current offloaded Apple files could not all be independently hashed. Recovery records preserve that distinction. The candidate keeps the source bundle identifiers and removes the original personal signing team.

## Desktop helper

Use a Mac with Apple Silicon, Node.js 24, npm, and Xcode Command Line Tools:

```sh
npm ci
npm run build:biometric
```

This compiles `Sources/JJBiometric.swift` into `build/JJBiometric` and applies ad hoc signing by default. It creates no biometric enrollment and changes no installed app or vault storage. For updates to an existing biometric enrollment, explicitly select the same owner signing identity used by that installation:

```sh
JJ_VAULT_SIGN_IDENTITY='Your installed signing identity' npm run build:biometric
```

Use the same explicit identity when packaging the desktop app. An ad hoc helper can change its identity when rebuilt. See the [desktop packaging guide](../assets/BUILDING.md).

## Companion builds

The companion targets require full Xcode with the relevant SDKs and XcodeGen. The source targets iOS 18 and macOS 14 or later. Confirm that your Xcode installation supports your actual device OS.

From the repository root:

```sh
npm run build:extensions
npm run build:apple
```

The full Apple build compiles the desktop helper, copies the generated Safari extension resources, regenerates the Xcode project, runs Swift core tests, and builds the iPhone simulator and Safari targets with signing disabled. It does not install or publish them. You can open `apple/JJVault.xcodeproj` for development after generation.

Device installation requires your own signing team and provisioning. Review bundle identifiers, App Groups, shared Keychain groups, push entitlements, and extension capabilities for your account. Keep related app and extension settings consistent. No personal signing team is preselected. A distribution build requires its own distribution signing and provisioning process.

## Local phone pairing

Run and unlock the desktop app, then start its phone pairing flow. Keep both devices on a reachable private network. In the phone app, scan the temporary QR code, review the displayed Mac and certificate information, and confirm the connection. The pairing code expires and is usable once.

Each device decrypts its own encrypted vault locally. Keep the master password, Secret Key, and a separate encrypted backup for recovery. The phone app's relay sync operates while the app is open and unlocked. It does not promise a persistent background connection. The optional hosted relay does not support this phone pairing flow.

Phone notifications require your own APNs provider configuration and matching app entitlements. Local source tests do not prove real phone delivery. Safari and OS AutoFill also require owner enablement and device checks after installation.

## Swift core checks

```sh
swift test --package-path apple
```

To include the JavaScript and Swift round trip check after installing the root npm dependencies:

```sh
JJ_VAULT_NODE_SOURCE="$PWD" swift test --package-path apple
```

The test suite uses synthetic fixtures and disposable local relay servers. It covers encrypted envelope compatibility, vault behavior, merging, and phone relay logic. Device installation, real biometrics, Safari enablement, website ceremonies, and APNs delivery require separate verification.
