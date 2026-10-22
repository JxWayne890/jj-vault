import Foundation
import Security
import LocalAuthentication

let service = "com.john.jjvault.desktop"
let account = "root"
var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
do {
    guard CommandLine.arguments.count == 2 else { throw NSError(domain: "JJVault", code: 1, userInfo: [NSLocalizedDescriptionKey: "Usage: JJBiometric enroll|unlock|delete"]) }
    switch CommandLine.arguments[1] {
    case "enroll":
        guard let line = readLine(), let key = Data(base64Encoded: line), key.count == 32 else { throw NSError(domain: "JJVault", code: 2, userInfo: [NSLocalizedDescriptionKey: "Expected one base64 encoded 32 byte key on stdin"]) }
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.biometryCurrentSet], &err) else { throw NSError(domain: "JJVault", code: 3) }
        SecItemDelete(query as CFDictionary)
        query[kSecAttrAccessControl as String] = access
        query[kSecValueData as String] = key
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    case "unlock":
        let context = LAContext(); context.localizedReason = "Unlock JJ Vault"
        query[kSecUseAuthenticationContext as String] = context
        query[kSecReturnData as String] = true
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        guard status == errSecSuccess, let key = value as? Data, key.count == 32 else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        print(key.base64EncodedString())
    case "delete":
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    default: throw NSError(domain: "JJVault", code: 4, userInfo: [NSLocalizedDescriptionKey: "Unknown command"])
    }
} catch {
    FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8)); exit(1)
}
