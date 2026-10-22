import SwiftUI
import JJVaultCore
import UIKit
import Security
import AuthenticationServices
struct SettingsView: View {
    @EnvironmentObject var store: VaultStore
    @EnvironmentObject var relay: RelayCoordinator
    @ObservedObject var phoneNotifications = PhoneNotifications.shared
    @Environment(\.dismiss) var dismiss
    @State var vaultName = ""
    @State var relayURL = ""
    @State var relayToken = ""
    @State var status = ""
    @State var showPairing = false
    @State var deleted = false
    @State var breachStatus = ""
    @State var backup: URL?
    @State var importFile = false
    @State var backupMaster = ""
    @State var backupSecret = ""
    var body: some View { NavigationStack { Form {
        if !status.isEmpty { Text(status) }
        Section("Security") {
            Stepper((store.settings["idleMinutes"] as? Int ?? 5) == 0 ? "No idle lock while open" : "Lock after \(store.settings["idleMinutes"] as? Int ?? 5) idle minutes",value:Binding(get:{store.settings["idleMinutes"] as? Int ?? 5},set:{value in var s = store.settings;s["idleMinutes"] = value;attempt {try store.updateSettings(s)}}),in:0...1440)
            Button("Enable Face ID or Touch ID") { attempt { try store.enableBiometric(accessGroup:sharedKeychainGroup);status = "Biometric unlock enabled for this device" } }
            Button("Disable biometric unlock") { let result = VaultKeychain.delete(accessGroup:sharedKeychainGroup); status = result == errSecSuccess || result == errSecItemNotFound ? "Biometric root key removed" : "Keychain removal failed (\(result))" }
            Toggle("Travel Mode",isOn:Binding(get:{store.settings["travelMode"] as? Bool ?? false},set:{value in var s = store.settings;s["travelMode"] = value;attempt { try store.updateSettings(s) }}))
            Text("The vault locks whenever the app leaves the foreground. Copied secrets expire after 90 seconds and stay on this device.").font(.caption).foregroundStyle(.secondary)
        }
        Section("Vaults") {
            ForEach(store.travelVisibleVaults,id:\.recordID) { vault in VStack(alignment:.leading) {
                Text(vault["name"] as? String ?? "Vault").font(.headline)
                Toggle("Safe for travel",isOn:vaultFlag(vault,"travelSafe"));Toggle("Allow browser AutoFill",isOn:vaultFlag(vault,"allowBrowser"));Toggle("Allow assistant access",isOn:vaultFlag(vault,"allowAssistant"))
            } }
            HStack {TextField("New vault name",text:$vaultName);Button("Add"){attempt {try store.addVault(vaultName);vaultName = ""}}}
        }
        Section("Watchtower") {
            let alerts = VaultUtilities.watchtower(store.travelVisibleItems)
            let score = max(0,100 - alerts.count * 5)
            Gauge(value:Double(score),in:0...100){Text("Security score")}.tint(score > 75 ? .green:.orange)
            ForEach(Array(alerts.enumerated()),id:\.offset) { _, alert in VStack(alignment:.leading){Text(alert.0);Text(alert.1).font(.caption).foregroundStyle(.orange)} }
            Button("Check breached passwords privately") { Task { await checkBreaches() } }
            if !breachStatus.isEmpty {Text(breachStatus).font(.caption)}
        }
        Section("Encrypted device sync") {
            Button(relay.connection == nil ? "Pair with Mac" : "Pair again with Mac",systemImage:"qrcode.viewfinder") { showPairing = true }
            if let connection = relay.connection {
                LabeledContent("Mac",value:connection.name)
                Text(connection.url).font(.caption).foregroundStyle(.secondary)
                Toggle("Sync automatically while open",isOn:$relay.automatic)
                Button(relay.working ? "Syncing…" : "Sync now") { Task { await relay.reconcile(store,force:true) } }.disabled(relay.working)
                Button("Forget sync pairing",role:.destructive) { relay.forget() }
                Text("The relay token stays in this device's protected Keychain. The connection uses the exact certificate approved when pairing. Automatic sync checks every ten seconds while this app is open and unlocked.").font(.caption).foregroundStyle(.secondary)
            }
            if !relay.message.isEmpty { Text(relay.message).font(.caption) }
            DisclosureGroup("Advanced relay connection") {
                TextField("Relay URL, https://…",text:$relayURL).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                SecureField("Relay bearer token",text:$relayToken).textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Sync with this relay once") { Task { do { guard let url = URL(string:relayURL) else {throw VaultError.invalid("Invalid relay URL")}; try await store.sync(base:url,token:relayToken);status = "Encrypted vault synced" } catch {status = error.localizedDescription} } }
                Text("For a separately hosted relay with a trusted HTTPS certificate. Import the same encrypted Mac backup first. This token remains in memory in this screen.").font(.caption).foregroundStyle(.secondary)
            }
        }
        Section("Assistant phone notifications") {
            Text("Optional Apple Push Notification service can deliver a generic notice when an assistant requests or changes a login. Apple receives a routing token and generic notification content. No vault item name, website, or secret is included.").font(.caption).foregroundStyle(.secondary)
            Button("Enable assistant phone notifications") { Task { await phoneNotifications.register() } }
            if !phoneNotifications.status.isEmpty { Text(phoneNotifications.status).font(.caption) }
            if !phoneNotifications.deviceToken.isEmpty {
                Text("APNs device token").font(.caption.bold())
                Text(phoneNotifications.deviceToken).font(.caption.monospaced()).textSelection(.enabled)
                Button("Copy device token") { copySecret(phoneNotifications.deviceToken) }
            }
        }
        Section("Backup and restore") {
            Button("Export encrypted backup") { attempt { let data = try store.exportBackup(); let url = FileManager.default.temporaryDirectory.appendingPathComponent("JJVault-backup.jjvault");try data.write(to:url,options:.completeFileProtection);backup = url } }
            if let url = backup { ShareLink(item:url){Label("Share encrypted backup",systemImage:"square.and.arrow.up")} }
            SecureField("Backup master password",text:$backupMaster);SecureField("Backup Secret Key",text:$backupSecret)
            Button("Restore encrypted backup") {importFile = true}
            Text("Restore replaces this device's vault after authenticated decryption. Keep an encrypted backup first.").font(.caption).foregroundStyle(.secondary)
        }
        Section("AutoFill") { Button("Open password AutoFill settings") { ASSettingsHelper.openCredentialProviderAppSettings {error in if let error {status = error.localizedDescription} } };Text("Enable JJ Vault in Settings, General, AutoFill & Passwords. Complete one master password unlock and enroll biometrics first.").font(.caption) }
        Section("Archive") { ForEach(store.travelVisibleItems.filter { $0["deletedAt"] == nil && $0["archived"] as? Bool == true },id:\.recordID) { item in
            HStack { Text(item["title"] as? String ?? "Item"); Spacer(); Button("Unarchive") { attempt { var restored = item; restored["archived"] = false; restored["allowAssistant"] = false; try store.upsert(restored) } } }
        } }
        Section("Recently deleted") { ForEach(store.travelVisibleItems.filter{$0["deletedAt"] != nil},id:\.recordID) { item in HStack {Text(item["title"] as? String ?? "Item");Spacer();Button("Restore"){attempt {try store.delete(item,restore:true)}}} }
        }
        Section("Activity") { ForEach(Array(store.activity.suffix(50).reversed()),id:\.recordID) { activity in VStack(alignment:.leading){Text(activity["action"] as? String ?? "Event");Text(activity["at"] as? String ?? "").font(.caption).foregroundStyle(.secondary)} } }
    }.navigationTitle("Settings").sheet(isPresented:$showPairing) { RelayPairingView().environmentObject(store).environmentObject(relay) }.toolbar {Button("Done"){dismiss()}}.fileImporter(isPresented:$importFile,allowedContentTypes:[.data,.json]) {result in attempt {let url = try result.get();let access = url.startAccessingSecurityScopedResource();defer{if access{url.stopAccessingSecurityScopedResource()}};try store.importBackup(Data(contentsOf:url),master:backupMaster,secret:backupSecret);backupMaster = "";backupSecret = "";status = "Backup restored"}}.overlay { if store.locked { Color(.systemBackground).overlay { Label("JJ Vault is locked",systemImage:"lock.fill") }.ignoresSafeArea() } }.onChange(of:store.locked) { _, locked in if locked { showPairing = false; phoneNotifications.deviceToken = ""; phoneNotifications.status = ""; relayToken = ""; backupMaster = ""; backupSecret = ""; backup = nil; importFile = false; dismiss() } } } }
    func vaultFlag(_ vault: Record,_ field:String)->Binding<Bool> {Binding(get:{store.vaults.first{$0.recordID == vault.recordID}?[field] as? Bool ?? false},set:{value in var v = store.vaults.first{$0.recordID == vault.recordID} ?? vault;v[field] = value;attempt{try store.updateVault(v)}})}
    func attempt(_ f:()throws->Void) {do{try f()}catch{status = error.localizedDescription}}
    func checkBreaches() async {breachStatus = "Checking password hash prefixes…";var breached = 0;var checked = Set<String>();do{for item in store.visibleItems(){if let password = item["password"] as? String,!password.isEmpty,!checked.contains(password){checked.insert(password);if try await VaultUtilities.breached(password)>0{breached += 1}}};breachStatus = "Checked \(checked.count) distinct passwords. \(breached) appeared in breaches."}catch{breachStatus = error.localizedDescription}}
}
struct EmergencyKit: View {
    @EnvironmentObject var store: VaultStore
    @Environment(\.dismiss) var dismiss
    let secret:String
    @State var exported:Data?
    var body:some View {NavigationStack{ScrollView{VStack(alignment:.leading,spacing:24){Image(systemName:"lifepreserver.fill").font(.system(size:54)).foregroundStyle(.indigo);Text("Emergency Kit").font(.largeTitle.bold());Text("Save this Secret Key now. You need it and your master password to unlock a new device.");Text(secret).font(.body.monospaced()).textSelection(.enabled);Text("1. Store this kit offline in a safe place.\n2. Keep your master password separate.\n3. Restore your encrypted backup on a new device.\n4. Enter your master password and this Secret Key.\n5. There is no account reset or cloud recovery.");Button("Create Emergency Kit PDF"){exported = makePDF()};if let bytes = exported{ShareLink(item:EmergencyPDF(data:bytes),preview:SharePreview("JJ Vault Emergency Kit")){Label("Save or print PDF",systemImage:"square.and.arrow.up")}}}.padding(28)}}.toolbar { Button("Done") { dismiss() } }.overlay { if store.locked { Color(.systemBackground).overlay { Label("JJ Vault is locked",systemImage:"lock.fill") }.ignoresSafeArea() } }.onChange(of:store.locked) { _, locked in if locked { exported = nil; dismiss() } }}
    func makePDF()->Data {let renderer = UIGraphicsPDFRenderer(bounds:CGRect(x:0,y:0,width:612,height:792));let data = renderer.pdfData{context in context.beginPage();let title = "JJ VAULT\nEMERGENCY KIT\n\n";let body = "Secret Key\n\(secret)\n\nRecovery steps\n1. Keep this kit offline in a safe place.\n2. Keep your master password separate.\n3. Restore an encrypted JJ Vault backup on a new device.\n4. Unlock with your master password and Secret Key.\n5. No cloud reset exists. Losing either secret and all unlocked devices can make your vault unrecoverable.\n\nGenerated \(VaultStore.now())";let text = NSMutableAttributedString(string:title,attributes:[.font:UIFont.boldSystemFont(ofSize:25)]);text.append(NSAttributedString(string:body,attributes:[.font:UIFont.monospacedSystemFont(ofSize:14,weight:.regular)]));text.draw(in:CGRect(x:48,y:50,width:516,height:690))};return data}
}

struct EmergencyPDF: Transferable { var data:Data; static var transferRepresentation:some TransferRepresentation { DataRepresentation(exportedContentType:.pdf) { $0.data }.suggestedFileName("JJ Vault Emergency Kit.pdf") } }
