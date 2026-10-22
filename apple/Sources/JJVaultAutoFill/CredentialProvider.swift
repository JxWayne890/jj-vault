import UIKit
import AuthenticationServices
import LocalAuthentication
import JJVaultCore

final class CredentialProviderViewController: ASCredentialProviderViewController,UITableViewDataSource,UITableViewDelegate {
    let store = VaultStore()
    var candidates:[Record] = []
    var requestedServices:[ASCredentialServiceIdentifier] = []
    var parameters:ASPasskeyCredentialRequestParameters?
    let table = UITableView(frame:.zero,style:.insetGrouped)
    var group:String? {Bundle.main.object(forInfoDictionaryKey:"JJVaultKeychainGroup") as? String}
    override func viewDidLoad(){super.viewDidLoad();view.backgroundColor = .systemBackground;table.frame = view.bounds;table.autoresizingMask = [.flexibleWidth,.flexibleHeight];table.dataSource = self;table.delegate = self;view.addSubview(table)}
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {extensionContext.cancelRequest(withError:NSError(domain:ASExtensionErrorDomain,code:ASExtensionError.userInteractionRequired.rawValue))}
    override func prepareInterfaceToProvideCredential(for credentialRequest:any ASCredentialRequest){Task{@MainActor in do{try await authenticate();try provide(credentialRequest)}catch{fail(error)}}}
    override func prepareCredentialList(for serviceIdentifiers:[ASCredentialServiceIdentifier]){requestedServices = serviceIdentifiers;parameters = nil;loadList()}
    override func prepareCredentialList(for serviceIdentifiers:[ASCredentialServiceIdentifier],requestParameters:ASPasskeyCredentialRequestParameters){requestedServices = serviceIdentifiers;parameters = requestParameters;loadList()}
    override func prepareInterface(forPasskeyRegistration registrationRequest:any ASCredentialRequest){Task{@MainActor in do{
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,request.supportedAlgorithms.contains(.ES256) else{throw VaultError.invalid("This site requires an unsupported passkey algorithm")}
        try await authenticate()
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {throw VaultError.invalid("Invalid passkey identity")}
        let rp = identity.relyingPartyIdentifier
        let existing = eligible().compactMap{$0["passkey"] as? Record}
        for excluded in request.excludedCredentials ?? [] {if existing.contains(where:{Data(base64URL:$0["credentialId"] as? String ?? "") == excluded.credentialID}) {throw VaultError.invalid("A matching passkey already exists")}}
        guard let vault = store.vaults.first(where:{$0["allowBrowser"] as? Bool == true && (!(store.settings["travelMode"] as? Bool ?? false) || $0["travelSafe"] as? Bool == true)}),let vaultID = vault["id"] as? String else{throw VaultError.invalid("Enable browser access for a vault in JJ Vault")}
        let (item,attestation) = try VaultPasskeys.registration(rpID:rp,userName:identity.userName,userHandle:identity.userHandle,clientDataHash:request.clientDataHash,vaultID:vaultID)
        try store.upsert(item)
        guard let pk = item["passkey"] as? Record,let id = Data(base64URL:pk["credentialId"] as? String ?? "")else{throw VaultError.invalid("Passkey creation failed")}
        let credential = ASPasskeyRegistrationCredential(relyingParty:rp,clientDataHash:request.clientDataHash,credentialID:id,attestationObject:attestation)
        store.lock();extensionContext.completeRegistrationRequest(using:credential,completionHandler:nil)
    }catch{fail(error)}}}
    override func performWithoutUserInteractionIfPossible(passkeyRegistration:ASPasskeyCredentialRequest){extensionContext.cancelRequest(withError:NSError(domain:ASExtensionErrorDomain,code:ASExtensionError.userInteractionRequired.rawValue))}
    func authenticate() async throws {
        // Keychain item requires current biometrics and is shared only with the signed app.
        // Every provider request prompts for verification; no background unlock path exists.
        try store.unlockBiometric(accessGroup:group)
    }
    func eligible()->[Record]{let allowed = Set(store.vaults.filter{$0["allowBrowser"] as? Bool == true}.compactMap{$0["id"] as? String});return store.visibleItems().filter{allowed.contains($0["vaultId"] as? String ?? "")}}
    func loadList(){Task{@MainActor in do{try await authenticate();let all = eligible();if let p = parameters {candidates = all.filter{item in guard let key = item["passkey"] as? Record,key["rpId"] as? String == p.relyingPartyIdentifier,let id = Data(base64URL:key["credentialId"] as? String ?? "")else{return false};return p.allowedCredentials.isEmpty || p.allowedCredentials.contains(id)}}else{candidates = all.filter{item in item["type"] as? String == "login" && requestedServices.contains{service in (item["urls"] as? [String] ?? []).contains{saved in VaultUtilities.matches(saved,service.type == .domain ? "https://"+service.identifier:service.identifier)}}}};table.reloadData();if candidates.isEmpty{let label = UILabel();label.text = "No matching credentials in allowed vaults";label.textAlignment = .center;label.numberOfLines = 0;table.backgroundView = label}}catch{fail(error)}}}
    func tableView(_ tableView:UITableView,numberOfRowsInSection section:Int)->Int{candidates.count}
    func tableView(_ tableView:UITableView,cellForRowAt indexPath:IndexPath)->UITableViewCell{let cell = UITableViewCell(style:.subtitle,reuseIdentifier:nil);let i = candidates[indexPath.row];cell.textLabel?.text = i["title"] as? String;cell.detailTextLabel?.text = i["username"] as? String;return cell}
    func tableView(_ tableView:UITableView,didSelectRowAt indexPath:IndexPath){do{let item = candidates[indexPath.row];if let p = parameters {try providePasskey(item,rp:p.relyingPartyIdentifier,hash:p.clientDataHash)}else{try store.record("autofill",itemID:item["id"] as? String);let credential = ASPasswordCredential(user:item["username"] as? String ?? "",password:item["password"] as? String ?? "");store.lock();extensionContext.completeRequest(withSelectedCredential:credential)}}catch{fail(error)}}
    func provide(_ request:any ASCredentialRequest)throws{
        guard let item = eligible().first(where:{$0["id"] as? String == request.credentialIdentity.recordIdentifier})else{throw VaultError.invalid("Credential unavailable")}
        if !(request is ASPasskeyCredentialRequest) {
            let service = request.credentialIdentity.serviceIdentifier
            let page = service.type == .domain ? "https://" + service.identifier : service.identifier
            guard (item["urls"] as? [String] ?? []).contains(where:{VaultUtilities.matches($0,page)}) else {throw VaultError.invalid("Credential website no longer matches")}
        }
        if let pass = request as? ASPasskeyCredentialRequest {guard let identity = pass.credentialIdentity as? ASPasskeyCredentialIdentity else{throw VaultError.invalid("Invalid passkey identity")};try providePasskey(item,rp:identity.relyingPartyIdentifier,hash:pass.clientDataHash)}
        else if request is ASOneTimeCodeCredentialRequest {let code = try VaultUtilities.totp(item["totp"] as? String ?? "");try store.record("autofillTOTP",itemID:item["id"] as? String);store.lock();extensionContext.completeOneTimeCodeRequest(using:ASOneTimeCodeCredential(code:code))}
        else if request is ASPasswordCredentialRequest {try store.record("autofill",itemID:item["id"] as? String);let credential = ASPasswordCredential(user:item["username"] as? String ?? "",password:item["password"] as? String ?? "");store.lock();extensionContext.completeRequest(withSelectedCredential:credential)}
        else{throw VaultError.invalid("Unsupported credential request")}
    }
    func providePasskey(_ item:Record,rp:String,hash:Data)throws{let (updated,authData,signature) = try VaultPasskeys.assertion(item:item,rpID:rp,clientDataHash:hash);try store.upsert(updated);guard let key = updated["passkey"] as? Record,let user = Data(base64URL:key["userHandle"] as? String ?? ""),let id = Data(base64URL:key["credentialId"] as? String ?? "")else{throw VaultError.invalid("Invalid passkey")};let credential = ASPasskeyAssertionCredential(userHandle:user,relyingParty:rp,signature:signature,clientDataHash:hash,authenticatorData:authData,credentialID:id);store.lock();extensionContext.completeAssertionRequest(using:credential)}
    func fail(_ error:Error){store.lock();extensionContext.cancelRequest(withError:NSError(domain:ASExtensionErrorDomain,code:ASExtensionError.failed.rawValue,userInfo:[NSLocalizedDescriptionKey:error.localizedDescription]))}
}
