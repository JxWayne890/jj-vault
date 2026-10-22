import SwiftUI
import UIKit
import JJVaultCore

@MainActor final class RelayCoordinator: ObservableObject {
    @Published private(set) var connection: VaultRelayConnection?
    @Published private(set) var working = false
    @Published var message = ""
    @Published var automatic = UserDefaults.standard.object(forKey: "relayAutomatic") as? Bool ?? true {
        didSet { UserDefaults.standard.set(automatic, forKey: "relayAutomatic") }
    }
    func load() {
        do { connection = try VaultRelayKeychain.load(accessGroup: sharedKeychainGroup) }
        catch { message = error.localizedDescription }
    }
    func accept(_ result: VaultRelayAPI.PairingResult, store: VaultStore) throws {
        if store.initialized {
            guard store.vaultIdentifier == result.connection.vaultId else { throw VaultError.invalid("This phone has a different vault. Keep an encrypted backup before changing vaults") }
        } else { try store.installPairedEncryptedBackup(result.encryptedBackup, vaultID: result.connection.vaultId) }
        try VaultRelayKeychain.save(result.connection, accessGroup: sharedKeychainGroup)
        connection = result.connection
        message = store.locked ? "Paired. Enter your master password and Secret Key to unlock the encrypted copy." : "Paired with your Mac."
    }
    func forget() {
        do { try VaultRelayKeychain.delete(accessGroup: sharedKeychainGroup); connection = nil; message = "Sync pairing removed." }
        catch { message = error.localizedDescription }
    }
    func reconcile(_ store: VaultStore, force: Bool = false) async {
        guard (automatic || force), !working, !store.locked, let connection else { return }
        guard store.vaultIdentifier == connection.vaultId else { message = "The paired Mac has a different vault identity."; return }
        working = true; defer { working = false }
        let generation = store.lockGeneration
        do {
            let revision = try await VaultRelayAPI.status(connection)
            guard generation == store.lockGeneration, !store.locked else { return }
            if force || store.syncNeedsUpload || store.lastSyncRemoteRevision != revision {
                try await store.sync(base: connection.baseURL, token: connection.token, certificate: connection.certificateData)
                guard generation == store.lockGeneration, !store.locked else { return }
                message = "Synced with \(connection.name) at \(Date().formatted(date: .omitted, time: .shortened))."
            }
        } catch { if generation == store.lockGeneration { message = error.localizedDescription } }
    }
}

struct RelayPairingView: View {
    @EnvironmentObject var store: VaultStore
    @EnvironmentObject var relay: RelayCoordinator
    @Environment(\.dismiss) var dismiss
    @Environment(\.scenePhase) var phase
    @State private var scanning = false
    @State private var code: VaultPairingCode?
    @State private var error = ""
    @State private var working = false
    @State private var operation: Task<Void, Never>?
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label("Pair your own Mac", systemImage: "desktopcomputer").font(.title2.bold())
                    Text("Open Pair iPhone in the Mac app, then scan its temporary QR code. The encrypted vault transfers directly. Enter your master password and Secret Key only on this phone after pairing.")
                    Button("Scan Mac pairing code", systemImage: "qrcode.viewfinder") { scanning = true }.disabled(working)
                }
                if let code {
                    Section("Confirm your Mac") {
                        LabeledContent("Mac", value: code.name)
                        LabeledContent("Address", value: code.url)
                        Text("Certificate fingerprint").font(.caption).foregroundStyle(.secondary)
                        Text(code.fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                        Text("Confirm this is the Mac and address you intended to connect to.").font(.caption)
                        Button(working ? "Connecting…" : "Connect to this Mac") { connect(code) }.buttonStyle(.borderedProminent).disabled(working)
                    }
                }
                if !error.isEmpty { Text(error).foregroundStyle(.red) }
                if working { ProgressView("Verifying the pinned connection") }
            }.navigationTitle("Pair with Mac").toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { operation?.cancel(); dismiss() } } }
        }.sheet(isPresented: $scanning) {
            QRScanner(accepts: { $0.hasPrefix("{") && $0.utf8.count <= 16_384 }) { text in
                scanning = false
                do { code = try VaultPairingCode.parse(text); error = "" }
                catch { code = nil; self.error = error.localizedDescription }
            }
        }.onChange(of: phase) { _, phase in if phase == .background { operation?.cancel(); code = nil; scanning = false; dismiss() } }
        .onDisappear { operation?.cancel(); operation = nil; code = nil }
    }
    private func connect(_ code: VaultPairingCode) {
        working = true; error = ""
        let generation = store.lockGeneration
        let beganLocked = store.locked
        operation = Task { @MainActor in
            defer { working = false }
            do {
                let result = try await VaultRelayAPI.pair(code)
                try Task.checkCancellation()
                // Onboarding contains only encrypted data. Camera or local network system
                // permission prompts may make an already locked app inactive temporarily.
                guard UIApplication.shared.applicationState != .background, UIApplication.shared.isProtectedDataAvailable,
                      generation == store.lockGeneration || (beganLocked && store.locked) else { throw VaultError.invalid("Pairing was interrupted. Scan a fresh code") }
                try relay.accept(result, store: store)
                self.code = nil
                if !store.locked { Task { await relay.reconcile(store, force: true) } }
                dismiss()
            } catch is CancellationError {} catch { self.error = error.localizedDescription }
        }
    }
}
