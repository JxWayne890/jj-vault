import Foundation
import CryptoKit
import CArgon2

public enum VaultError: LocalizedError {
    case invalid(String)
    public var errorDescription: String? { switch self { case .invalid(let message): return message } }
}
public struct Envelope: Codable {
    public var format: String
    public var version: Int
    public var id: String
    public var kdf: KDF
    public var iv: String
    public var ciphertext: String
    public struct KDF: Codable {
        public var algorithm: String
        public var salt: String
        public var memoryKiB: UInt32
        public var iterations: UInt32
        public var parallelism: UInt32
    }
    public var aad: Data { Data("JJVault:1:\(id):\(kdf.salt):\(kdf.memoryKiB):\(kdf.iterations):\(kdf.parallelism)".utf8) }
}
public enum VaultCrypto {
    public static func random(_ count: Int) throws -> Data {
        var bytes = Data(count: count)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }) == errSecSuccess else { throw VaultError.invalid("Random generator failed") }
        return bytes
    }
    public static func secretKey() throws -> String { "JJ1." + (try random(32)).base64URL }
    public static func derive(master: String, secret: String, envelope: Envelope) throws -> Data {
        let k = envelope.kdf
        guard envelope.format == "jjvault", envelope.version == 1, !envelope.id.isEmpty, envelope.id.utf8.count <= 128,
              k.algorithm == "argon2id", k.memoryKiB >= 65536, k.memoryKiB <= 262144, k.iterations >= 3, k.iterations <= 10, k.parallelism >= 1, k.parallelism <= 4,
              let salt = Data(base64Encoded: k.salt), salt.count >= 16, salt.count <= 64, secret.hasPrefix("JJ1."), let sk = Data(base64URL: String(secret.dropFirst(4))), sk.count == 32 else { throw VaultError.invalid("Invalid vault encryption parameters or Secret Key") }
        var output = Data(count: 32)
        let password = Data(master.precomposedStringWithCompatibilityMapping.utf8)
        let result = password.withUnsafeBytes { p in salt.withUnsafeBytes { s in output.withUnsafeMutableBytes { o in
            argon2id_hash_raw(k.iterations, k.memoryKiB, k.parallelism, p.baseAddress, password.count, s.baseAddress, salt.count, o.baseAddress, 32)
        } } }
        guard result == ARGON2_OK.rawValue else { throw VaultError.invalid("Key derivation failed") }
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: output), salt: sk, info: Data("JJ Vault root key v1".utf8), outputByteCount: 32)
        output.resetBytes(in: 0..<output.count)
        return key.withUnsafeBytes { Data($0) }
    }
    public static func create(data: Data, master: String, secret: String) throws -> (Envelope, Data) {
        var e = Envelope(format: "jjvault", version: 1, id: UUID().uuidString.lowercased(), kdf: .init(algorithm: "argon2id", salt: try random(16).base64EncodedString(), memoryKiB: 65536, iterations: 3, parallelism: 1), iv: "", ciphertext: "")
        let key = try derive(master: master, secret: secret, envelope: e)
        e = try seal(data: data, key: key, envelope: e)
        return (e, key)
    }
    public static func seal(data: Data, key: Data, envelope: Envelope) throws -> Envelope {
        guard key.count == 32 else { throw VaultError.invalid("Invalid key") }
        var e = envelope
        let nonce = try AES.GCM.Nonce(data: random(12))
        let box = try AES.GCM.seal(data, using: SymmetricKey(data: key), nonce: nonce, authenticating: e.aad)
        e.iv = Data(nonce).base64EncodedString()
        e.ciphertext = (box.ciphertext + box.tag).base64EncodedString()
        return e
    }
    public static func open(_ envelope: Envelope, key: Data) throws -> Data {
        guard key.count == 32, let iv = Data(base64Encoded: envelope.iv), iv.count == 12, let cipher = Data(base64Encoded: envelope.ciphertext), cipher.count >= 16 else { throw VaultError.invalid("Invalid encrypted vault") }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: cipher.dropLast(16), tag: cipher.suffix(16))
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: envelope.aad)
    }
    public static func open(_ envelope: Envelope, master: String, secret: String) throws -> (Data, Data) {
        let key = try derive(master: master, secret: secret, envelope: envelope)
        return (try open(envelope, key: key), key)
    }
}
public extension Data {
    var base64URL: String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    init?(base64URL: String) { var s = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"); s += String(repeating: "=", count: (4 - s.count % 4) % 4); self.init(base64Encoded: s) }
}
