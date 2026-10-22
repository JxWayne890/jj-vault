// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "JJVaultKit", platforms: [.iOS("18.0"), .macOS(.v14)], products: [.library(name: "JJVaultCore", targets: ["JJVaultCore"])], targets: [
.target(name: "CArgon2", path: "Vendor/Argon2", sources: ["src/argon2.c","src/core.c","src/encoding.c","src/ref.c","src/thread.c","src/blake2/blake2b.c"], publicHeadersPath: "include", cSettings: [.headerSearchPath("src"), .define("ARGON2_NO_THREADS")]),
.target(name: "JJVaultCore", dependencies: ["CArgon2"], path: "Sources/JJVaultCore"),
.testTarget(name: "JJVaultCoreTests", dependencies: ["JJVaultCore"], path: "Tests/JJVaultCoreTests", exclude: ["interop.json", "conflict.json"])])
