#if os(iOS)
import Foundation
import AuthenticationServices
public extension VaultStore {
    func updateAutoFillIndex() {
        let allowed = Set(vaults.filter{$0["allowBrowser"] as? Bool == true}.compactMap{$0["id"] as? String})
        var identities:[any ASCredentialIdentity] = []
        for item in visibleItems() where allowed.contains(item["vaultId"] as? String ?? "") {
            guard let id = item["id"] as? String else{continue}
            if let pk = item["passkey"] as? Record,let rp = pk["rpId"] as? String,let credential = Data(base64URL:pk["credentialId"] as? String ?? ""),let user = Data(base64URL:pk["userHandle"] as? String ?? "") {
                identities.append(ASPasskeyCredentialIdentity(relyingPartyIdentifier:rp,userName:pk["userName"] as? String ?? "",credentialID:credential,userHandle:user,recordIdentifier:id))
            }
            guard item["type"] as? String == "login" else{continue}
            for url in item["urls"] as? [String] ?? [] {let service = ASCredentialServiceIdentifier(identifier:url,type:.URL);identities.append(ASPasswordCredentialIdentity(serviceIdentifier:service,user:item["username"] as? String ?? "",recordIdentifier:id));if !(item["totp"] as? String ?? "").isEmpty {identities.append(ASOneTimeCodeCredentialIdentity(serviceIdentifier:service,label:item["title"] as? String ?? "JJ Vault",recordIdentifier:id))}}
        }
        ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities,completion:{_,_ in})
    }
}
#endif
