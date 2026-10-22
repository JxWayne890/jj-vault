import Foundation
import Security
import LocalAuthentication

public enum VaultKeychain {
    static let service = "com.john.jjvault.root"
    public static func save(_ key: Data, account: String = "root", accessGroup: String? = nil) throws {
        guard key.count == 32 else { throw VaultError.invalid("Invalid root key") }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.biometryCurrentSet], &error) else { throw VaultError.invalid("Biometric access unavailable") }
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        if let group = accessGroup { q[kSecAttrAccessGroup as String] = group }
        SecItemDelete(q as CFDictionary)
        q[kSecValueData as String] = key
        q[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultError.invalid("Keychain enrollment failed (\(status))") }
    }
    public static func load(account: String = "root", accessGroup: String? = nil, reason: String = "Unlock JJ Vault") throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne, kSecUseAuthenticationContext as String: context]
        if let group = accessGroup { q[kSecAttrAccessGroup as String] = group }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, data.count == 32 else { throw VaultError.invalid("Biometric unlock failed (\(status))") }
        return data
    }
    @discardableResult public static func delete(account: String = "root", accessGroup: String? = nil) -> OSStatus {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        if let group = accessGroup { q[kSecAttrAccessGroup as String] = group }
        return SecItemDelete(q as CFDictionary)
    }
}
