import Foundation
import Security

struct ProviderError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct ProviderCredential: Decodable {
    let credentialId: String
    let rpId: String
    let userHandle: String
    let userName: String
    let title: String
}
struct ProviderVault: Decodable {
    let id: String
    let name: String
}
struct ProviderList: Decodable {
    let credentials: [ProviderCredential]
    let vaults: [ProviderVault]
}
struct ProviderRegistration: Decodable {
    let relyingParty: String
    let clientDataHash: String
    let credentialId: String
    let attestationObject: String
}
struct ProviderAssertion: Decodable {
    let relyingParty: String
    let clientDataHash: String
    let credentialId: String
    let signature: String
    let authenticatorData: String
    let userHandle: String
}
private struct ProviderResponse<T: Decodable>: Decodable {
    let ok: Bool
    let result: T?
    let error: String?
}

/// This token can request passkey operations only. The Mac app independently verifies
/// Touch ID for every registration or assertion and never returns a private key.
enum ProviderPairing {
    private static let service = "com.john.jjvault.macprovider.pairing"
    private static var query: [String: Any] {
        var value: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "provider",
            kSecUseDataProtectionKeychain as String: true
        ]
        if let group = Bundle.main.object(forInfoDictionaryKey: "JJVaultProviderKeychainGroup") as? String,
           !group.contains("$("), !group.isEmpty {
            value[kSecAttrAccessGroup as String] = group
        }
        return value
    }
    static func load() throws -> String {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &value)
        guard status == errSecSuccess, let bytes = value as? Data,
              let token = String(data: bytes, encoding: .utf8), token.utf8.count >= 32 else {
            throw ProviderError(message: "Pair this provider using the token from JJ Vault Settings.")
        }
        return token
    }
    static func save(_ token: String) throws {
        guard token.utf8.count >= 32, token.utf8.count <= 4096,
              !token.contains(where: { $0.isWhitespace || $0.isNewline }) else {
            throw ProviderError(message: "Enter the complete provider pairing token from JJ Vault Settings.")
        }
        let attributes: [String: Any] = [
            kSecValueData as String: Data(token.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            let entry = query.merging(attributes) { _, new in new }
            let added = SecItemAdd(entry as CFDictionary, nil)
            guard added == errSecSuccess else {
                throw ProviderError(message: "Device Keychain pairing failed (\(added)).")
            }
        } else if status != errSecSuccess {
            throw ProviderError(message: "Device Keychain pairing failed (\(status)).")
        }
    }
}

private final class ProviderNoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

enum ProviderClient {
    static func request<T: Decodable>(_ payload: [String: Any], as type: T.Type) async throws -> T {
        let token = try ProviderPairing.load()
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false
        config.urlCache = nil
        let session = URLSession(configuration: config, delegate: ProviderNoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: URL(string: "http://127.0.0.1:17373/provider")!)
        request.httpMethod = "POST"
        request.timeoutInterval = 90
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: payload)
        let (bytes, response) = try await session.data(for: request)
        guard bytes.count <= 2 * 1024 * 1024, let http = response as? HTTPURLResponse else {
            throw ProviderError(message: "Invalid response from the local JJ Vault app.")
        }
        if http.statusCode == 423 { throw ProviderError(message: "Vault is locked. Unlock the JJ Vault Mac app first.") }
        if http.statusCode == 401 { throw ProviderError(message: "Provider pairing was rejected. Pair again using JJ Vault Settings.") }
        let body = try JSONDecoder().decode(ProviderResponse<T>.self, from: bytes)
        guard (200..<300).contains(http.statusCode), body.ok, let result = body.result else {
            throw ProviderError(message: body.error ?? "JJ Vault could not complete this request.")
        }
        return result
    }
    static func data(_ encoded: String, minimum: Int = 1, maximum: Int = 65536) throws -> Data {
        guard let bytes = Data(base64Encoded: encoded), bytes.count >= minimum, bytes.count <= maximum else {
            throw ProviderError(message: "Invalid credential data from the local JJ Vault app.")
        }
        return bytes
    }
}
