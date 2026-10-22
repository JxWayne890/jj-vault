import AppKit
import AuthenticationServices
import CryptoKit

/// Apple supplies the relying party and client data hash. Web page JavaScript cannot
/// inject an origin through the ordinary browser extension or request silent signing.
final class MacCredentialProviderViewController: ASCredentialProviderViewController,
    NSTableViewDataSource, NSTableViewDelegate {

    private let heading = NSTextField(labelWithString: "JJ Vault Passkeys")
    private let details = NSTextField(wrappingLabelWithString: "")
    private let status = NSTextField(wrappingLabelWithString: "")
    private let tokenField = NSSecureTextField()
    private let pairingButton = NSButton(title: "Save provider pairing", target: nil, action: nil)
    private let primaryButton = NSButton(title: "Continue", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel", target: nil, action: nil)
    private let repairButton = NSButton(title: "Pair provider", target: nil, action: nil)
    private let vaultPicker = NSPopUpButton()
    private let table = NSTableView()
    private let scroll = NSScrollView()
    private var candidates: [ProviderCredential] = []
    private var vaults: [ProviderVault] = []
    private var parameters: ASPasskeyCredentialRequestParameters?
    private var directAssertion: ASPasskeyCredentialIdentity?
    private var directHash: Data?
    private var registration: ASPasskeyCredentialRequest?
    private var configuration = false
    private var generation = UUID()
    private var busy = false
    private var loaded = false

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 580, height: 490))
        preferredContentSize = view.frame.size
        heading.font = .boldSystemFont(ofSize: 23)
        details.font = .systemFont(ofSize: 14)
        details.maximumNumberOfLines = 4
        status.textColor = .secondaryLabelColor
        status.maximumNumberOfLines = 4
        tokenField.placeholderString = "Provider pairing token from JJ Vault Settings"
        tokenField.isHidden = true
        pairingButton.target = self
        pairingButton.action = #selector(savePairing)
        pairingButton.isHidden = true
        primaryButton.target = self
        primaryButton.action = #selector(performPrimary)
        primaryButton.bezelStyle = .rounded
        primaryButton.keyEquivalent = "\r"
        cancelButton.target = self
        cancelButton.action = #selector(cancel)
        cancelButton.bezelStyle = .rounded
        cancelButton.keyEquivalent = "\u{1b}"
        repairButton.target = self
        repairButton.action = #selector(showPairing)
        repairButton.bezelStyle = .rounded
        pairingButton.bezelStyle = .rounded
        vaultPicker.isHidden = true
        vaultPicker.setAccessibilityLabel("Vault for the new passkey")
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("account"))
        column.title = "Account"
        table.addTableColumn(column)
        table.headerView = nil
        table.rowHeight = 48
        table.delegate = self
        table.dataSource = self
        table.allowsEmptySelection = false
        table.setAccessibilityLabel("Matching passkeys")
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.heightAnchor.constraint(equalToConstant: 172).isActive = true
        scroll.isHidden = true
        let buttons = NSStackView(views: [repairButton, cancelButton, primaryButton])
        buttons.orientation = .horizontal
        buttons.spacing = 10
        let stack = NSStackView(views: [heading, details, tokenField, pairingButton,
                                        vaultPicker, scroll, status, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.distribution = .fill
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 26),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -26),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: view.bottomAnchor, constant: -24),
            details.widthAnchor.constraint(equalTo: stack.widthAnchor),
            status.widthAnchor.constraint(equalTo: stack.widthAnchor),
            tokenField.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        loaded = true
    }
    private func ready() { if !loaded { loadView() } }
    private func reset() {
        ready()
        generation = UUID()
        busy = false
        candidates = []
        vaults = []
        parameters = nil
        directAssertion = nil
        directHash = nil
        registration = nil
        configuration = false
        status.stringValue = ""
        tokenField.stringValue = ""
        tokenField.isHidden = true
        pairingButton.isHidden = true
        scroll.isHidden = true
        vaultPicker.isHidden = true
        primaryButton.isHidden = false
        primaryButton.isEnabled = false
        repairButton.isEnabled = true
    }
    override func prepareInterfaceForExtensionConfiguration() {
        reset()
        configuration = true
        details.stringValue = "Copy the macOS provider pairing token from the JJ Vault Mac app Settings. This provider connects only to the local app and stores its token in this device's Keychain."
        primaryButton.title = "Done"
        primaryButton.isEnabled = (try? ProviderPairing.load()) != nil
        showPairing()
    }
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue))
    }
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        reset()
        guard let request = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
              request.clientDataHash.count == 32 else {
            reject("This provider supplies passkeys. Use the JJ Vault browser extension for passwords.")
            return
        }
        directAssertion = identity
        directHash = request.clientDataHash
        details.stringValue = "Website: \(identity.relyingPartyIdentifier)\nAccount: \(identity.userName)"
        primaryButton.title = "Use passkey with Touch ID"
        primaryButton.isEnabled = true
        status.stringValue = "Review the website and account before continuing. JJ Vault must be unlocked."
        ensurePaired()
    }
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        reset()
        reject("Choose JJ Vault from a passkey request. Password AutoFill uses the JJ Vault browser extension.")
    }
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        reset()
        parameters = requestParameters
        details.stringValue = "Website: \(requestParameters.relyingPartyIdentifier)\nChoose the account you want to use."
        primaryButton.title = "Use selected passkey with Touch ID"
        scroll.isHidden = false
        if ensurePaired() { refreshList() }
    }
    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        reset()
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
              request.clientDataHash.count == 32, request.supportedAlgorithms.contains(.ES256),
              !identity.userHandle.isEmpty, identity.userHandle.count <= 64 else {
            reject("This request requires an unsupported passkey algorithm or invalid account data.")
            return
        }
        registration = request
        details.stringValue = "Save a passkey for \(identity.relyingPartyIdentifier)\nAccount: \(identity.userName)"
        primaryButton.title = "Save passkey with Touch ID"
        vaultPicker.isHidden = false
        if ensurePaired() { refreshList() }
    }
    @available(macOS 15.0, *)
    override func performWithoutUserInteractionIfPossible(passkeyRegistration: ASPasskeyCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue))
    }
    @discardableResult private func ensurePaired() -> Bool {
        if (try? ProviderPairing.load()) != nil { return true }
        showPairing()
        return false
    }
    @objc private func showPairing() {
        ready()
        tokenField.isHidden = false
        pairingButton.isHidden = false
        status.stringValue = "Paste the separate macOS provider pairing token from JJ Vault Settings."
    }
    @objc private func savePairing() {
        do {
            try ProviderPairing.save(tokenField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines))
            tokenField.stringValue = ""
            tokenField.isHidden = true
            pairingButton.isHidden = true
            status.stringValue = "Provider token saved in this device's Keychain."
            if configuration { primaryButton.isEnabled = true }
            else if parameters != nil || registration != nil { refreshList() }
            else { primaryButton.isEnabled = true }
        } catch { status.stringValue = error.localizedDescription }
    }
    private var rpID: String? {
        if let registration,
           let identity = registration.credentialIdentity as? ASPasskeyCredentialIdentity {
            return identity.relyingPartyIdentifier
        }
        return parameters?.relyingPartyIdentifier ?? directAssertion?.relyingPartyIdentifier
    }
    private func refreshList() {
        guard let rp = rpID else { return }
        let current = generation
        setBusy(true)
        status.stringValue = "Reading matching passkeys from the local JJ Vault app…"
        Task { @MainActor in
            do {
                let list = try await ProviderClient.request(["action": "list", "rpId": rp], as: ProviderList.self)
                guard current == generation else { return }
                candidates = list.credentials.filter { candidate in
                    guard candidate.rpId == rp, let id = Data(base64Encoded: candidate.credentialId) else { return false }
                    guard let parameters else { return true }
                    return parameters.allowedCredentials.isEmpty || parameters.allowedCredentials.contains(id)
                }
                vaults = list.vaults
                vaultPicker.removeAllItems()
                vaultPicker.addItems(withTitles: vaults.map(\.name))
                table.reloadData()
                if !candidates.isEmpty { table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false) }
                setBusy(false)
                primaryButton.isEnabled = registration != nil ? !vaults.isEmpty : !candidates.isEmpty
                status.stringValue = registration != nil
                    ? "Choose a vault. Touch ID will confirm this registration in the Mac app."
                    : candidates.isEmpty ? "No matching passkeys in browser enabled vaults."
                    : "The Mac app requests Touch ID before using the selected passkey."
                index(candidates)
            } catch {
                guard current == generation else { return }
                setBusy(false)
                primaryButton.isEnabled = false
                status.stringValue = error.localizedDescription
            }
        }
    }
    @objc private func performPrimary() {
        if configuration {
            tokenField.stringValue = ""
            extensionContext.completeExtensionConfigurationRequest()
            return
        }
        guard !busy, ensurePaired() else { return }
        if let request = registration { register(request); return }
        if let identity = directAssertion, let hash = directHash {
            assertCredential(rp: identity.relyingPartyIdentifier, credentialID: identity.credentialID,
                             hash: hash, allowed: [identity.credentialID])
            return
        }
        guard let parameters, candidates.indices.contains(table.selectedRow),
              let id = Data(base64Encoded: candidates[table.selectedRow].credentialId) else { return }
        assertCredential(rp: parameters.relyingPartyIdentifier, credentialID: id,
                         hash: parameters.clientDataHash, allowed: parameters.allowedCredentials)
    }
    private func register(_ request: ASPasskeyCredentialRequest) {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
              vaults.indices.contains(vaultPicker.indexOfSelectedItem) else { return }
        var excluded: [String] = []
        if #available(macOS 15.0, *) {
            excluded = (request.excludedCredentials ?? []).map { $0.credentialID.base64EncodedString() }
        }
        let payload: [String: Any] = [
            "action": "register", "rpId": identity.relyingPartyIdentifier,
            "userName": identity.userName, "userHandle": identity.userHandle.base64EncodedString(),
            "clientDataHash": request.clientDataHash.base64EncodedString(),
            "vaultId": vaults[vaultPicker.indexOfSelectedItem].id,
            "excludedCredentialIds": excluded, "supportedAlgorithms": [-7]
        ]
        let current = generation
        setBusy(true)
        status.stringValue = "Confirm Touch ID in JJ Vault to save this passkey."
        Task { @MainActor in
            do {
                let result = try await ProviderClient.request(payload, as: ProviderRegistration.self)
                guard current == generation else { return }
                let hash = try ProviderClient.data(result.clientDataHash, minimum: 32, maximum: 32)
                let id = try ProviderClient.data(result.credentialId, maximum: 1023)
                guard result.relyingParty == identity.relyingPartyIdentifier,
                      hash == request.clientDataHash,
                      !excluded.contains(id.base64EncodedString()) else {
                    throw ProviderError(message: "The returned passkey does not match Apple's request.")
                }
                let attestation = try ProviderClient.data(result.attestationObject, maximum: 16384)
                let credential = ASPasskeyRegistrationCredential(relyingParty: result.relyingParty,
                    clientDataHash: hash, credentialID: id, attestationObject: attestation)
                let metadata = ASPasskeyCredentialIdentity(relyingPartyIdentifier: result.relyingParty,
                    userName: identity.userName, credentialID: id, userHandle: identity.userHandle,
                    recordIdentifier: id.base64EncodedString())
                ASCredentialIdentityStore.shared.saveCredentialIdentities([metadata], completion: { _, _ in })
                generation = UUID()
                extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
            } catch { showFailure(error, current: current) }
        }
    }
    private func assertCredential(rp: String, credentialID: Data, hash: Data, allowed: [Data]) {
        guard hash.count == 32, allowed.isEmpty || allowed.contains(credentialID) else {
            reject("The selected passkey is not allowed by this website.")
            return
        }
        let current = generation
        setBusy(true)
        status.stringValue = "Confirm Touch ID in JJ Vault to use this passkey."
        let payload: [String: Any] = [
            "action": "assert", "rpId": rp, "credentialId": credentialID.base64EncodedString(),
            "clientDataHash": hash.base64EncodedString(),
            "allowedCredentialIds": allowed.map { $0.base64EncodedString() }
        ]
        Task { @MainActor in
            do {
                let result = try await ProviderClient.request(payload, as: ProviderAssertion.self)
                guard current == generation else { return }
                let returnedHash = try ProviderClient.data(result.clientDataHash, minimum: 32, maximum: 32)
                let returnedID = try ProviderClient.data(result.credentialId, maximum: 1023)
                let auth = try ProviderClient.data(result.authenticatorData, minimum: 37)
                guard result.relyingParty == rp, returnedHash == hash, returnedID == credentialID,
                      auth.prefix(32) == Data(SHA256.hash(data: Data(rp.utf8))), auth[32] & 0x05 == 0x05 else {
                    throw ProviderError(message: "The signed passkey response does not match Apple's request.")
                }
                let credential = ASPasskeyAssertionCredential(
                    userHandle: try ProviderClient.data(result.userHandle, maximum: 64),
                    relyingParty: rp, signature: try ProviderClient.data(result.signature, maximum: 256),
                    clientDataHash: hash, authenticatorData: auth, credentialID: returnedID)
                generation = UUID()
                extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
            } catch { showFailure(error, current: current) }
        }
    }
    private func showFailure(_ error: Error, current: UUID) {
        guard current == generation else { return }
        setBusy(false)
        status.stringValue = error.localizedDescription
    }
    private func setBusy(_ value: Bool) {
        busy = value
        primaryButton.isEnabled = !value
        repairButton.isEnabled = !value
        pairingButton.isEnabled = !value
        table.isEnabled = !value
    }
    private func index(_ credentials: [ProviderCredential]) {
        let entries = credentials.compactMap { entry -> ASPasskeyCredentialIdentity? in
            guard let id = Data(base64Encoded: entry.credentialId),
                  let user = Data(base64Encoded: entry.userHandle), !user.isEmpty, user.count <= 64 else { return nil }
            return ASPasskeyCredentialIdentity(relyingPartyIdentifier: entry.rpId, userName: entry.userName,
                credentialID: id, userHandle: user, recordIdentifier: entry.credentialId)
        }
        ASCredentialIdentityStore.shared.saveCredentialIdentities(entries, completion: { _, _ in })
    }
    private func reject(_ message: String) {
        ready()
        status.stringValue = message
        primaryButton.isEnabled = false
    }
    @objc private func cancel() {
        generation = UUID()
        tokenField.stringValue = ""
        candidates = []
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
            code: ASExtensionError.userCanceled.rawValue))
    }
    func numberOfRows(in tableView: NSTableView) -> Int { candidates.count }
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard candidates.indices.contains(row) else { return nil }
        let entry = candidates[row]
        let text = NSTextField(wrappingLabelWithString: entry.userName + "\n" + entry.title)
        text.lineBreakMode = .byTruncatingTail
        return text
    }
    func tableViewSelectionDidChange(_ notification: Notification) {
        if !busy { primaryButton.isEnabled = candidates.indices.contains(table.selectedRow) }
    }
}
