#!/bin/zsh
set -euo pipefail
helper_only=0
if (( $# > 1 )); then
  print -u2 'Usage: apple/build.sh [--helper-only]'
  exit 2
fi
if (( $# == 1 )); then
  if [[ "$1" != '--helper-only' ]]; then
    print -u2 'Usage: apple/build.sh [--helper-only]'
    exit 2
  fi
  helper_only=1
fi
# Choose a stable owner identity explicitly when preserving biometric enrollment.
sign_identity='-'
if (( ${+JJ_VAULT_SIGN_IDENTITY} )); then
  if [[ -z "$JJ_VAULT_SIGN_IDENTITY" || "$JJ_VAULT_SIGN_IDENTITY" == '-' ]]; then
    print -u2 'Set a nonempty JJ_VAULT_SIGN_IDENTITY, or omit it for ad hoc signing.'
    exit 2
  fi
  sign_identity="$JJ_VAULT_SIGN_IDENTITY"
fi
cd "${0:A:h}/.."
mkdir -p apple/build
swiftc apple/Sources/JJBiometric.swift -o apple/build/JJBiometric -framework Security -framework LocalAuthentication
codesign --force --options runtime --timestamp=none --sign "$sign_identity" --identifier com.john.jjvault.biometric apple/build/JJBiometric
codesign --verify --strict apple/build/JJBiometric
if [[ "$sign_identity" == '-' ]]; then
  print 'Built an ad hoc biometric helper. Set JJ_VAULT_SIGN_IDENTITY explicitly for stable biometric enrollment.'
fi
if (( helper_only )); then
  exit 0
fi
if [[ -d dist/extensions/safari ]]; then
  cp dist/extensions/safari/* apple/SafariResources/
fi
xcodegen generate --spec apple/project.yml
swift test --package-path apple
xcodebuild -project apple/JJVault.xcodeproj -scheme JJVault -sdk iphonesimulator -configuration Debug -derivedDataPath apple/build/iOS CODE_SIGNING_ALLOWED=NO build
xcodebuild -project apple/JJVault.xcodeproj -scheme JJVaultSafari -configuration Debug -derivedDataPath apple/build/Safari CODE_SIGNING_ALLOWED=NO build
