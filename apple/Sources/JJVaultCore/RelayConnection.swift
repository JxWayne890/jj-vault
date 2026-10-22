import Foundation
import CryptoKit
import Security

public struct VaultPairingCode: Codable, Equatable, Identifiable {
    public let type: String
    public let version: Int
    public let url: String
    public let name: String
    public let certificate: String
    public let nonce: String
    public let vaultId: String
    public let expiresAt: String
    public var id: String { nonce }
    public var baseURL: URL { URL(string: url)! }
    public var certificateData: Data { Data(base64Encoded: certificate)! }
    public var fingerprint: String { SHA256.hash(data: certificateData).map { String(format: "%02X", $0) }.joined(separator: ":") }

    public static func parse(_ text: String, now: Date = Date()) throws -> VaultPairingCode {
        guard let bytes = text.data(using: .utf8), bytes.count <= 16_384 else { throw VaultError.invalid("Invalid pairing QR code") }
        let code = try JSONDecoder().decode(Self.self, from: bytes)
        try code.validate(now: now)
        return code
    }
    public func validate(now: Date = Date()) throws {
        guard type == "jjvault-pairing", version == 1,
              let base = URLComponents(string: url), base.scheme == "https", let host = base.host, !host.isEmpty,
              base.user == nil, base.password == nil, base.query == nil, base.fragment == nil,
              base.path.isEmpty || base.path == "/", base.url != nil,
              !name.isEmpty, name.count <= 128, !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !vaultId.isEmpty, vaultId.count <= 256,
              nonce.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              let cert = Data(base64Encoded: certificate), cert.count <= 8192, cert.base64EncodedString() == certificate,
              SecCertificateCreateWithData(nil, cert as CFData) != nil else { throw VaultError.invalid("Invalid pairing QR code") }
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let expiry = formatter.date(from: expiresAt) ?? ISO8601DateFormatter().date(from: expiresAt)
        guard let expiry, expiry > now, expiry.timeIntervalSince(now) <= 300 else { throw VaultError.invalid("Pairing code expired. Open a fresh code on your Mac") }
    }
}

public struct VaultRelayConnection: Codable, Equatable {
    public let url: String
    public let name: String
    public let certificate: String
    public let token: String
    public let vaultId: String
    public var baseURL: URL { URL(string: url)! }
    public var certificateData: Data { Data(base64Encoded: certificate)! }
    public init(code: VaultPairingCode, token: String) throws {
        try code.validate()
        guard token.count >= 32, token.count <= 512, token.range(of: "^[A-Za-z0-9._~-]+$", options: .regularExpression) != nil else { throw VaultError.invalid("Invalid relay pairing response") }
        url = code.url; name = code.name; certificate = code.certificate; self.token = token; vaultId = code.vaultId
    }
    public func validate() throws {
        guard let u = URLComponents(string: url), u.scheme == "https", u.host != nil, u.user == nil, u.password == nil, u.query == nil, u.fragment == nil,
              u.path.isEmpty || u.path == "/", let cert = Data(base64Encoded: certificate), cert.count <= 8192,
              SecCertificateCreateWithData(nil, cert as CFData) != nil, token.count >= 32, token.count <= 512,
              token.range(of: "^[A-Za-z0-9._~-]+$", options: .regularExpression) != nil,
              !vaultId.isEmpty, vaultId.count <= 256 else { throw VaultError.invalid("Invalid saved relay pairing") }
    }
}

public enum VaultRelayTrust {
    public static func accepts(_ trust: SecTrust, host: String, certificate: Data) -> Bool {
        guard let anchor = SecCertificateCreateWithData(nil, certificate as CFData),
              SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString)) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil),
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else { return false }
        return SecCertificateCopyData(leaf) as Data == certificate
    }
}

final class VaultRelayTransport: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    private let host: String
    private let certificate: Data?
    init(base: URL, certificate: Data? = nil) { host = (base.host ?? "").lowercased(); self.certificate = certificate }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let certificate else { completionHandler(.performDefaultHandling, nil); return }
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host.lowercased() == host,
              let trust = challenge.protectionSpace.serverTrust,
              VaultRelayTrust.accepts(trust, host: host, certificate: certificate) else { completionHandler(.cancelAuthenticationChallenge, nil); return }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
    static func session(base: URL, certificate: Data? = nil) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil; config.httpShouldSetCookies = false; config.urlCache = nil
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 60
        return URLSession(configuration: config, delegate: VaultRelayTransport(base: base, certificate: certificate), delegateQueue: nil)
    }
}

public enum VaultRelayAPI {
    public struct PairingResult { public let connection: VaultRelayConnection; public let encryptedBackup: Data }
    public static func pair(_ code: VaultPairingCode) async throws -> PairingResult {
        try code.validate()
        var request = URLRequest(url: code.baseURL.appendingPathComponent("pair")); request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["nonce": code.nonce])
        let session = VaultRelayTransport.session(base: code.baseURL, certificate: code.certificateData); defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == 200, bytes.count <= 64 * 1024 * 1024,
              let payload = try JSONSerialization.jsonObject(with: bytes) as? Record,
              let token = payload["token"] as? String, let revision = payload["revision"] as? Int, revision >= 0,
              let encrypted = payload["envelope"] as? Record, encrypted["id"] as? String == code.vaultId else { throw VaultError.invalid("Pairing was rejected. Open a fresh code on your Mac") }
        let backup = try JSONSerialization.data(withJSONObject: encrypted)
        _ = try JSONDecoder().decode(Envelope.self, from: backup)
        return PairingResult(connection: try VaultRelayConnection(code: code, token: token), encryptedBackup: backup)
    }
    public static func status(_ connection: VaultRelayConnection) async throws -> Int {
        try connection.validate()
        var request = URLRequest(url: connection.baseURL.appendingPathComponent("status")); request.setValue("Bearer \(connection.token)", forHTTPHeaderField: "Authorization")
        let session = VaultRelayTransport.session(base: connection.baseURL, certificate: connection.certificateData); defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == 200, bytes.count <= 16_384,
              let payload = try JSONSerialization.jsonObject(with: bytes) as? Record,
              payload["vaultId"] as? String == connection.vaultId,
              let revision = payload["revision"] as? Int, revision >= 0 else { throw VaultError.invalid("Relay is unavailable or belongs to another vault") }
        return revision
    }
}

public enum VaultRelayKeychain {
    private static let service = "com.john.jjvault.relay"
    private static func query(accessGroup: String?) -> Record {
        var q: Record = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "paired-relay", kSecUseDataProtectionKeychain as String: true]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }
    public static func save(_ connection: VaultRelayConnection, accessGroup: String? = nil) throws {
        try connection.validate()
        let data = try JSONEncoder().encode(connection)
        let q = query(accessGroup: accessGroup)
        let attributes: Record = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemUpdate(q as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var add = q; attributes.forEach { add[$0.key] = $0.value }
            guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw VaultError.invalid("Unable to protect relay pairing in Keychain") }
        } else if status != errSecSuccess { throw VaultError.invalid("Unable to update protected relay pairing") }
    }
    public static func load(accessGroup: String? = nil) throws -> VaultRelayConnection? {
        var q = query(accessGroup: accessGroup); q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?; let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let bytes = result as? Data else { throw VaultError.invalid("Unable to read protected relay pairing") }
        let value = try JSONDecoder().decode(VaultRelayConnection.self, from: bytes); try value.validate(); return value
    }
    public static func delete(accessGroup: String? = nil) throws {
        let status = SecItemDelete(query(accessGroup: accessGroup) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultError.invalid("Unable to remove relay pairing") }
    }
}
