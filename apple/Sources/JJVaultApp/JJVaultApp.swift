import SwiftUI
import JJVaultCore
import UniformTypeIdentifiers
import AuthenticationServices
import UIKit

@main struct JJVaultApp: App {
    @UIApplicationDelegateAdaptor(JJVaultAppDelegate.self) private var appDelegate
    @StateObject var store = VaultStore()
    @StateObject var relay = RelayCoordinator()
    @Environment(\.scenePhase) private var phase
    var body: some Scene { WindowGroup { RootView().environmentObject(store).environmentObject(relay).onAppear { relay.load() }.onChange(of: store.locked) { _, locked in if !locked { Task { await relay.reconcile(store) } } }.onReceive(Timer.publish(every:10,on:.main,in:.common).autoconnect()) { _ in if phase == .active && !store.locked { Task { await relay.reconcile(store) } } }.onReceive(NotificationCenter.default.publisher(for: UIApplication.willResignActiveNotification)) { _ in PrivacyShield.cover(); store.lock() }.onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in DispatchQueue.main.async { PrivacyShield.uncover() } }.onChange(of:phase) { _, new in if new != .active { store.lock() } }.onReceive(Timer.publish(every:5,on:.main,in:.common).autoconnect()) { _ in store.checkIdle() } } }
}
struct RootView: View {
    @EnvironmentObject var store: VaultStore
    @EnvironmentObject var relay: RelayCoordinator
    @State var master = ""
    @State var confirmMaster = ""
    @State var secret = ""
    @State var kitSecret = ""
    @State var restoreMaster = ""
    @State var restoreSecret = ""
    @State var query = ""
    @State var selection: Record?
    @State var showSettings = false
    @State var showKit = false
    @State var importing = false
    @State var showPairing = false
    var body: some View {
        Group {
            if store.locked {
                NavigationStack { Form {
                    Section { Image(systemName:"lock.shield.fill").font(.system(size:58)).foregroundStyle(.indigo).frame(maxWidth:.infinity).padding(); Text("JJ Vault").font(.largeTitle.bold()).frame(maxWidth:.infinity); Text("Your vault stays encrypted on your own devices.").foregroundStyle(.secondary) }
                    if let problem = store.storageProblem { Text(problem).foregroundStyle(.red) }
                    Section(store.initialized ? "Unlock" : "Create your vault") {
                        SecureField("Master password",text:$master).textContentType(.password)
                        if !store.initialized { SecureField("Confirm master password",text:$confirmMaster).textContentType(.newPassword) }
                        if store.initialized { SecureField("Secret Key, JJ1.…",text:$secret).textInputAutocapitalization(.never).autocorrectionDisabled() }
                        Button(store.initialized ? "Unlock vault" : "Create vault") { attempt {
                            if store.initialized { try store.unlock(master:master,secret:secret) } else { guard master == confirmMaster else { throw VaultError.invalid("Master passwords do not match") }; kitSecret = try store.create(master:master); showKit = true }
                            master = ""; confirmMaster = ""; secret = ""
                        } }.buttonStyle(.borderedProminent).disabled(!store.storageConfigured)
                        if store.initialized { Button("Unlock with Face ID or Touch ID",systemImage:"faceid") { attempt { try store.unlockBiometric(accessGroup:sharedKeychainGroup) } } }
                    }
                    Section("Connect your Mac") { Button("Pair with Mac",systemImage:"qrcode.viewfinder") { showPairing = true }.disabled(!store.storageConfigured); if let paired = relay.connection { Text("Paired with \(paired.name)").font(.caption); Text(relay.message).font(.caption).foregroundStyle(.secondary) } }
                    Section("Restore encrypted backup") { SecureField("Backup master password",text:$restoreMaster); SecureField("Backup Secret Key",text:$restoreSecret).textInputAutocapitalization(.never).autocorrectionDisabled(); Button("Choose encrypted backup") { importing = true }.disabled(restoreMaster.isEmpty || restoreSecret.isEmpty) }
                    if !store.error.isEmpty { Text(store.error).foregroundStyle(.red) }
                }.navigationTitle("Private. Personal. Yours.") }
            } else {
                NavigationStack { List {
                    if !store.error.isEmpty { Text(store.error).foregroundStyle(.red) }
                    ForEach(store.visibleItems(query:query),id:\.recordID) { item in
                        Button { selection = item; store.touch() } label: { HStack { Image(systemName:icon(item["type"] as? String ?? "login")).font(.title2).foregroundStyle(.indigo).frame(width:32); VStack(alignment:.leading) { Text(item["title"] as? String ?? "Untitled").foregroundStyle(.primary); Text(item["username"] as? String ?? item["type"] as? String ?? "").font(.caption).foregroundStyle(.secondary) }; Spacer(); if item["favorite"] as? Bool == true { Image(systemName:"star.fill").foregroundStyle(.yellow) } } }
                    }.onDelete { offsets in let all = store.visibleItems(query:query); for offset in offsets { attempt { try store.delete(all[offset]) } } }
                    if store.visibleItems(query:query).isEmpty { ContentUnavailableView("Your private vault",systemImage:"lock.rectangle.stack",description:Text("Add an item, or restore an encrypted backup from your Mac.")) }
                }.searchable(text:$query,prompt:"Search titles, usernames, websites, tags").navigationTitle("JJ Vault").toolbar {
                    ToolbarItem(placement:.topBarLeading) { Button("Settings",systemImage:"gearshape") { showSettings = true } }
                    ToolbarItem(placement:.topBarTrailing) { Button("Add",systemImage:"plus") { selection = VaultStore.newItem(vaultID:store.travelVisibleVaults.first?["id"] as? String ?? "") }.disabled(store.travelVisibleVaults.isEmpty) }
                    ToolbarItem(placement:.bottomBar) { Button("Lock",systemImage:"lock.fill") { store.lock() } }
                } }
            }
        }.sheet(isPresented:$showPairing) { RelayPairingView().environmentObject(store).environmentObject(relay) }.sheet(isPresented:$showSettings) { SettingsView().environmentObject(store) }.sheet(item:Binding(get:{selection.map { ItemSelection(value:$0) }},set:{selection = $0?.value})) { chosen in ItemEditor(item:chosen.value).environmentObject(store) }.sheet(isPresented:$showKit) { EmergencyKit(secret:kitSecret).onDisappear { kitSecret = "" } }.fileImporter(isPresented:$importing,allowedContentTypes:[.data,.json]) { result in attempt {
            let url = try result.get(); let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
            try store.importBackup(Data(contentsOf:url),master:restoreMaster,secret:restoreSecret); restoreMaster = ""; restoreSecret = ""
        } }.onChange(of:store.lockGeneration) { _, _ in clearSensitiveState() }
    }
    func clearSensitiveState() {
        selection = nil; showSettings = false; showKit = false; importing = false
        kitSecret = ""; master = ""; confirmMaster = ""; secret = ""; restoreMaster = ""; restoreSecret = ""; query = ""
    }
    func attempt(_ action: () throws -> Void) { do { try action(); store.error = "" } catch { store.error = error.localizedDescription } }
}
struct ItemSelection: Identifiable { var value: Record; var id: String { value.recordID } }
extension Dictionary where Key == String, Value == Any { var recordID: String { self["id"] as? String ?? "" } }
var sharedKeychainGroup: String? { guard let group = Bundle.main.object(forInfoDictionaryKey:"JJVaultKeychainGroup") as? String, !group.contains("$(") else { return nil }; return group }
func icon(_ type: String) -> String { switch type { case "creditCard":return "creditcard"; case "bankAccount":return "building.columns"; case "secureNote":return "note.text"; case "passkey":return "person.badge.key"; case "document":return "doc"; default:return "key.fill" } }
func copySecret(_ text: String) { UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic:text]],options:[.localOnly:true,.expirationDate:Date().addingTimeInterval(90)]) }
struct ItemEditor: View {
    @EnvironmentObject var store: VaultStore
    @Environment(\.dismiss) var dismiss
    @State var item: Record
    @State var generatorMode = "random"
    @State var generatorLength = 24
    @State var generatorWords = 6
    @State var generatorSymbols = true
    @State var showQR = false
    @State var showPassword = false
    @State var attach = false
    let types = ["login","password","creditCard","bankAccount","identity","secureNote","document","softwareLicense","apiCredential","sshKey","passport","driversLicense","wifi","membership","cryptoWallet","xMoney"]
    func text(_ key: String) -> Binding<String> { Binding(get:{item[key] as? String ?? ""},set:{item[key] = $0}) }
    func flag(_ key: String) -> Binding<Bool> { Binding(get:{item[key] as? Bool ?? false},set:{item[key] = $0}) }
    var body: some View {
        NavigationStack { Form {
            Section("Item") {
                TextField("Title",text:text("title"))
                Picker("Type",selection:text("type")) { ForEach(types,id:\.self) { Text($0).tag($0) } }
                Picker("Vault",selection:text("vaultId")) { ForEach(store.travelVisibleVaults,id:\.recordID) { Text($0["name"] as? String ?? "Vault").tag($0.recordID) } }
                TextField("Username",text:text("username")).textInputAutocapitalization(.never).autocorrectionDisabled()
                HStack { Group { if showPassword { TextField("Password",text:text("password")) } else { SecureField("Password",text:text("password")) } }.textInputAutocapitalization(.never).autocorrectionDisabled(); Button { showPassword.toggle() } label:{Image(systemName:showPassword ? "eye.slash":"eye")}; Button { copySecret(item["password"] as? String ?? "") } label:{Image(systemName:"doc.on.doc")} }
                Picker("Generator",selection:$generatorMode){Text("Random").tag("random");Text("Memorable").tag("passphrase");Text("PIN").tag("pin")}
                if generatorMode == "passphrase" {Stepper("Words: \(generatorWords)",value:$generatorWords,in:4...20)} else {Stepper("Length: \(generatorLength)",value:$generatorLength,in:4...128);if generatorMode == "random"{Toggle("Symbols",isOn:$generatorSymbols)}}
                Button("Generate password") { do { if generatorMode == "passphrase"{item["password"] = try VaultUtilities.passphrase(words:generatorWords)}else{let alphabet = generatorMode == "pin" ? "0123456789" : "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789" + (generatorSymbols ? "!@#$%^&*":"");item["password"] = try VaultUtilities.password(length:generatorLength,alphabet:alphabet)}}catch{store.error = error.localizedDescription} }

                TextField("Website URLs, one per line",text:Binding(get:{(item["urls"] as? [String] ?? []).joined(separator:"\n")},set:{item["urls"] = $0.components(separatedBy:.newlines).filter{!$0.isEmpty}}),axis:.vertical).textInputAutocapitalization(.never).autocorrectionDisabled()
            }
            Section("Authenticator") { SecureField("TOTP secret or otpauth URI",text:text("totp")).textInputAutocapitalization(.never).autocorrectionDisabled(); Button("Scan authenticator QR code",systemImage:"qrcode.viewfinder") { showQR = true }; TimelineView(.periodic(from:.now,by:1)) { _ in if let secret = item["totp"] as? String, let code = try? VaultUtilities.totp(secret) { Button { copySecret(code) } label:{Text(code).font(.largeTitle.monospacedDigit()).tracking(4)}; Text("Updates in \(30 - Int(Date().timeIntervalSince1970) % 30) seconds").font(.caption) } } }
            Section("Details") { TextField("Notes",text:text("notes"),axis:.vertical).lineLimit(4...12); TextField("Tags, comma separated",text:Binding(get:{(item["tags"] as? [String] ?? []).joined(separator:", ")},set:{item["tags"] = $0.split(separator:",").map{$0.trimmingCharacters(in:.whitespaces)}})); TextField("Expiry, YYYY-MM-DD",text:text("expiresAt")); Toggle("Favorite",isOn:flag("favorite")); Toggle("Archive",isOn:flag("archived")); Toggle("Allow assistant",isOn:flag("allowAssistant")).disabled(VaultUtilities.assistantForbidden(item)) }
            Section("Custom fields") {
                let fields = item["fields"] as? [Record] ?? []
                ForEach(Array(fields.enumerated()),id:\.offset) { index, field in
                    VStack { TextField("Section",text:fieldText(index,"section")); TextField("Label",text:fieldText(index,"label")); if field["kind"] as? String == "password" { SecureField("Value",text:fieldText(index,"value")) } else { TextField("Value",text:fieldText(index,"value")) }; Picker("Kind",selection:fieldText(index,"kind")) { ForEach(["text","password","url","date","email","phone"],id:\.self) { Text($0).tag($0) } } }
                }.onDelete { offsets in var all = fields; all.remove(atOffsets:offsets); item["fields"] = all }
                Button("Add field") { var all = fields; all.append(["id":VaultStore.id(),"label":"","value":"","kind":"text"]); item["fields"] = all }
            }
            Section("Encrypted attachments") { ForEach(item["attachments"] as? [Record] ?? [],id:\.recordID) { attachment in if let data = Data(base64Encoded:attachment["data"] as? String ?? "") { ShareLink(item:AttachmentFile(data:data),preview:SharePreview(attachment["name"] as? String ?? "Attachment")) { Label(attachment["name"] as? String ?? "Attachment",systemImage:"doc") } } }; Button("Add document") { attach = true } }
            Section("Password history") { ForEach(Array((item["passwordHistory"] as? [Record] ?? []).enumerated()),id:\.offset) { _, entry in Button(entry["changedAt"] as? String ?? "Previous password") { copySecret(entry["password"] as? String ?? "") } } }
            if item["deletedAt"] != nil { Button("Restore item") { do { try store.delete(item,restore:true); dismiss() } catch { store.error = error.localizedDescription } } }
        }.navigationTitle("Item").toolbar { ToolbarItem(placement:.cancellationAction){Button("Cancel"){dismiss()}}; ToolbarItem(placement:.confirmationAction){Button("Save"){save()}.disabled((item["title"] as? String ?? "").isEmpty)} }.sheet(isPresented:$showQR) { QRScanner { value in if !store.locked { item["totp"] = value }; showQR = false } }.fileImporter(isPresented:$attach,allowedContentTypes:[.data]) { result in do {
            let url = try result.get(); let access = url.startAccessingSecurityScopedResource(); defer { if access {url.stopAccessingSecurityScopedResource()} }; let data = try Data(contentsOf:url); guard data.count <= 20*1024*1024 else { throw VaultError.invalid("Attachments are limited to 20 MB") }; var all = item["attachments"] as? [Record] ?? []; all.append(["id":VaultStore.id(),"name":url.lastPathComponent,"mime":"application/octet-stream","data":data.base64EncodedString()]); item["attachments"] = all
        } catch {store.error = error.localizedDescription} }.overlay { if store.locked { Color(.systemBackground).overlay { Label("JJ Vault is locked",systemImage:"lock.fill") }.ignoresSafeArea() } }.onChange(of:store.locked) { _, locked in if locked { item = [:]; showQR = false; attach = false; dismiss() } }
    }
    }
    func fieldText(_ index:Int,_ key:String) -> Binding<String> { Binding(get:{{ let fields = item["fields"] as? [Record] ?? []; return fields.indices.contains(index) ? fields[index][key] as? String ?? "" : "" }()},set:{value in var fields = item["fields"] as? [Record] ?? []; guard fields.indices.contains(index), !store.locked else { return }; fields[index][key] = value; item["fields"] = fields}) }
    func save() { do { try store.upsert(item); dismiss() } catch { store.error = error.localizedDescription } }
}
struct AttachmentFile: Transferable { var data: Data; static var transferRepresentation: some TransferRepresentation { DataRepresentation(exportedContentType:.data) { $0.data } } }
