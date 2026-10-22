import Foundation
import Combine
import CryptoKit
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif
public typealias Record = [String: Any]
public final class VaultStore: ObservableObject {
    @Published public private(set) var document: Record?
    @Published public var error = ""
    @Published public private(set) var initialized = false
    @Published public private(set) var lockGeneration: UInt64 = 0
    public var locked: Bool { document == nil }
    public let fileURL: URL
    public let storageConfigured: Bool
    public var storageProblem: String? { storageConfigured ? nil : "Shared vault storage is unavailable. Install a correctly signed build with the JJ Vault App Group enabled for both app and AutoFill extension." }
    private var key = Data()
    private var envelope: Envelope?
    private var lastUse = Date()
    private var sessionGeneration = UUID()
    private var syncInProgress = false
    public private(set) var syncNeedsUpload = true
    public private(set) var lastSyncRemoteRevision: Int?
    public static let appGroup = "group.com.john.jjvault"
    public static var defaultURL: URL {
        let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("JJVault")
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        var excluded = base
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        try? excluded.setResourceValues(values)
        return base.appendingPathComponent("vault.jjvault")
    }
    public init(url: URL? = nil) {
        fileURL = url ?? VaultStore.defaultURL
        #if os(iOS)
        storageConfigured = url != nil || FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup) != nil
        #else
        storageConfigured = true
        #endif
        initialized = storageConfigured && FileManager.default.fileExists(atPath: fileURL.path)
    }
    private func requireStorage() throws { if let storageProblem { throw VaultError.invalid(storageProblem) } }
    public var items: [Record] { document?["items"] as? [Record] ?? [] }
    public var vaults: [Record] { document?["vaults"] as? [Record] ?? [] }
    public var activity: [Record] { document?["activity"] as? [Record] ?? [] }
    public var settings: Record { document?["settings"] as? Record ?? [:] }
    public static func id() -> String { UUID().uuidString.lowercased() }
    public static func now() -> String { let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return formatter.string(from: Date()) }
    public func create(master: String) throws -> String {
        try requireStorage()
        guard !initialized else { throw VaultError.invalid("A vault already exists") }
        guard master.count >= 14 else { throw VaultError.invalid("Use a master password of at least 14 characters") }
        let secret = try VaultCrypto.secretKey()
        let first = Self.id()
        let data: Record = ["schema": 1, "deviceId": Self.id(), "vaults": [["id": first,"name":"Personal","allowAssistant":false,"allowBrowser":true,"travelSafe":false]],"items": [Record](),"activity": [Record](),"settings": ["idleMinutes": 5,"travelMode":false,"notifyAssistant":false],"assistantTokens":[Record](),"revision":0]
        let result = try VaultCrypto.create(data: JSONSerialization.data(withJSONObject: data), master: master, secret: secret)
        envelope = result.0; key = result.1; document = data; initialized = true
        try record("initialize"); return secret
    }
    public func unlock(master: String, secret: String) throws {
        try requireStorage()
        let e = try JSONDecoder().decode(Envelope.self, from: Data(contentsOf: fileURL))
        let (plain, derived) = try VaultCrypto.open(e, master: master, secret: secret)
        try adopt(e, plain: plain, key: derived)
        try record("unlock")
    }
    public func unlockBiometric(accessGroup: String? = nil) throws {
        try requireStorage()
        let e = try JSONDecoder().decode(Envelope.self, from: Data(contentsOf: fileURL))
        let derived = try VaultKeychain.load(accessGroup: accessGroup)
        try adopt(e, plain: VaultCrypto.open(e, key: derived), key: derived)
        try record("unlockBiometric")
    }
    public func enableBiometric(accessGroup: String? = nil) throws {
        guard !locked else { throw VaultError.invalid("Vault is locked") }
        try VaultKeychain.save(key, accessGroup: accessGroup)
    }
    private func adopt(_ e: Envelope, plain: Data, key: Data) throws {
        guard let object = try JSONSerialization.jsonObject(with: plain) as? Record, object["schema"] as? Int == 1, object["vaults"] is [Record], object["items"] is [Record] else { throw VaultError.invalid("Invalid vault data") }
        sessionGeneration = UUID(); envelope = e; self.key = key; document = object; touch()
    }
    public func lock() { lockGeneration &+= 1; sessionGeneration = UUID(); key.resetBytes(in: 0..<key.count); key = Data(); document = nil; envelope = nil; error = "" }
    public func touch() { lastUse = Date() }
    public func checkIdle() { let minutes = settings["idleMinutes"] as? Int ?? 5; if !locked && minutes > 0 && Date().timeIntervalSince(lastUse) >= Double(minutes) * 60 { lock() } }
    public func save() throws {
        try requireStorage()
        guard var data = document, let e = envelope, !key.isEmpty else { throw VaultError.invalid("Vault is locked") }
        data["revision"] = (data["revision"] as? Int ?? 0) + 1
        let updated = try VaultCrypto.seal(data: JSONSerialization.data(withJSONObject: data), key: key, envelope: e)
        try JSONEncoder().encode(updated).write(to: fileURL, options: [.atomic, .completeFileProtection])
        envelope = updated; document = data; syncNeedsUpload = true; touch()
        #if os(iOS)
        updateAutoFillIndex()
        #endif
    }
    public func record(_ action: String, itemID: String? = nil) throws {
        guard var data = document else { throw VaultError.invalid("Vault is locked") }
        var log = activity
        var event: Record = ["id": Self.id(),"at":Self.now(),"action":action]
        event["itemId"] = itemID
        log.append(event); data["activity"] = log; document = data; try save()
    }
    public func addVault(_ name: String) throws {
        guard var data = document, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        var all = vaults; all.append(["id":Self.id(),"name":name,"allowAssistant":false,"allowBrowser":true,"travelSafe":false]); data["vaults"] = all; document = data; try record("addVault")
    }
    public func updateVault(_ vault: Record) throws {
        guard var data = document else { throw VaultError.invalid("Vault is locked") }
        data["vaults"] = vaults.map { $0["id"] as? String == vault["id"] as? String ? vault : $0 }; document = data; try record("editVault")
    }
    public func updateSettings(_ settings: Record) throws { guard var data = document else { return }; data["settings"] = settings; document = data; try record("settings") }
    public func upsert(_ item: Record) throws {
        guard var data = document else { throw VaultError.invalid("Vault is locked") }
        var updated = item; let id = item["id"] as? String ?? Self.id(); updated["id"] = id; updated["updatedAt"] = Self.now()
        var all = items
        if let index = all.firstIndex(where: { $0["id"] as? String == id }) {
            let old = all[index]
            var history = old["passwordHistory"] as? [Record] ?? []
            if let password = old["password"] as? String, password != updated["password"] as? String { history.append(["password":password,"changedAt":Self.now()]) }
            updated["passwordHistory"] = history; all[index] = updated
        } else { updated["createdAt"] = Self.now(); updated["passwordHistory"] = [Record](); all.append(updated) }
        if VaultUtilities.assistantForbidden(updated) || updated["archived"] as? Bool == true || updated["deletedAt"] != nil { updated["allowAssistant"] = false; if let i = all.firstIndex(where: { $0["id"] as? String == id }) { all[i] = updated } }
        data["items"] = all; document = data; try record("edit", itemID: id)
    }
    public func delete(_ item: Record, restore: Bool = false) throws { var i = item; let now = Self.now(); i["deletedAt"] = restore ? nil : now; if restore { i["restoredAt"] = now }; i["allowAssistant"] = false; try upsert(i) }
    public static func newItem(type: String = "login", title: String = "", vaultID: String) -> Record {
        ["id":id(),"vaultId":vaultID,"type":type,"title":title,"urls":[String](),"fields":[Record](),"tags":[String](),"favorite":false,"archived":false,"allowAssistant":false,"attachments":[Record](),"passwordHistory":[Record](),"createdAt":now(),"updatedAt":now()]
    }
    public var travelVisibleVaults: [Record] {
        let travel = settings["travelMode"] as? Bool ?? false
        return vaults.filter { !travel || ($0["travelSafe"] as? Bool ?? false) }
    }
    public var travelVisibleItems: [Record] {
        let ids = Set(travelVisibleVaults.compactMap { $0["id"] as? String })
        return items.filter { ids.contains($0["vaultId"] as? String ?? "") }
    }
    public func visibleItems(query: String = "", includeDeleted: Bool = false) -> [Record] {
        let travel = settings["travelMode"] as? Bool ?? false
        let visibleVaults = Set(vaults.filter { !travel || ($0["travelSafe"] as? Bool ?? false) }.compactMap { $0["id"] as? String })
        return items.filter { i in
            visibleVaults.contains(i["vaultId"] as? String ?? "") && (includeDeleted ? i["deletedAt"] != nil : i["deletedAt"] == nil && !(i["archived"] as? Bool ?? false)) && (query.isEmpty || [i["title"] as? String ?? "",i["username"] as? String ?? "",(i["urls"] as? [String] ?? []).joined(separator:" "),(i["tags"] as? [String] ?? []).joined(separator:" ")].joined(separator:" ").localizedCaseInsensitiveContains(query))
        }.sorted { ($0["title"] as? String ?? "") < ($1["title"] as? String ?? "") }
    }
    public var vaultIdentifier: String? {
        if let envelope { return envelope.id }
        guard initialized, let bytes = try? Data(contentsOf: fileURL), let stored = try? JSONDecoder().decode(Envelope.self, from: bytes) else { return nil }
        return stored.id
    }
    public func installPairedEncryptedBackup(_ bytes: Data, vaultID: String) throws {
        try requireStorage()
        guard !initialized, locked else { throw VaultError.invalid("This phone already has a vault") }
        let received = try JSONDecoder().decode(Envelope.self, from: bytes)
        guard received.id == vaultID else { throw VaultError.invalid("The paired vault identity does not match") }
        try bytes.write(to: fileURL, options: [.atomic, .completeFileProtection])
        initialized = true
    }
    public func importBackup(_ bytes: Data, master: String, secret: String) throws {
        try requireStorage()
        let e = try JSONDecoder().decode(Envelope.self, from: bytes)
        let (plain, key) = try VaultCrypto.open(e, master: master, secret: secret)
        try adopt(e, plain: plain, key: key); initialized = true; try record("importBackup")
        let group = Bundle.main.object(forInfoDictionaryKey: "JJVaultKeychainGroup") as? String
        VaultKeychain.delete(accessGroup: group)
    }
    public func exportBackup() throws -> Data { guard !locked else { throw VaultError.invalid("Vault is locked") }; return try Data(contentsOf: fileURL) }
    @MainActor public func sync(base: URL, token: String, certificate: Data? = nil) async throws {
        guard !syncInProgress else { throw VaultError.invalid("Sync is already in progress") }
        syncInProgress = true; defer { syncInProgress = false }
        let generation = sessionGeneration
        guard !locked, base.scheme == "https" || (["127.0.0.1","localhost","::1"].contains(base.host ?? "") && base.scheme == "http") else { throw VaultError.invalid("Use an HTTPS relay, or HTTP localhost") }
        let endpoint = base.appendingPathComponent("vault")
        var get = URLRequest(url: endpoint); get.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let session = VaultRelayTransport.session(base: base, certificate: certificate)
        defer { session.invalidateAndCancel() }
        let (remoteData, response) = try await session.data(for: get)
        guard generation == sessionGeneration, !locked else { throw VaultError.invalid("Vault is locked") }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw VaultError.invalid("Sync relay rejected request") }
        guard let payload = try JSONSerialization.jsonObject(with: remoteData) as? Record, let revision = payload["revision"] as? Int else { throw VaultError.invalid("Invalid sync response") }
        if let remoteObject = payload["envelope"] as? Record {
            let e = try JSONDecoder().decode(Envelope.self, from: JSONSerialization.data(withJSONObject: remoteObject))
            guard e.id == envelope?.id else { throw VaultError.invalid("Different vault identity. Import the desktop backup first") }
            let plain = try VaultCrypto.open(e, key: key)
            guard let remote = try JSONSerialization.jsonObject(with: plain) as? Record else { throw VaultError.invalid("Invalid sync data") }
            try merge(remote)
        }
        guard let e = envelope, var projection = document else { throw VaultError.invalid("Vault is locked") }
        projection["items"] = Self.markPasskeysBackedUp(projection["items"] as? [Record] ?? [])
        projection["assistantTokens"] = [Record]()
        projection["activity"] = [Record]()
        if settings["travelMode"] as? Bool == true {
            let safe = vaults.filter { $0["travelSafe"] as? Bool == true }
            let ids = Set(safe.compactMap { $0["id"] as? String })
            projection["vaults"] = safe
            projection["items"] = Self.markPasskeysBackedUp(items.filter { ids.contains($0["vaultId"] as? String ?? "") })
        }
        let exported = try VaultCrypto.seal(data: JSONSerialization.data(withJSONObject: projection), key: key, envelope: e)
        var put = URLRequest(url: endpoint); put.httpMethod = "PUT"; put.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization"); put.setValue("application/json", forHTTPHeaderField: "Content-Type")
        put.httpBody = try JSONSerialization.data(withJSONObject: ["expectedRevision":revision,"envelope":JSONSerialization.jsonObject(with: JSONEncoder().encode(exported))])
        let pushedLocalRevision = document?["revision"] as? Int
        let (resultBytes, result) = try await session.data(for: put)
        guard generation == sessionGeneration, !locked else { throw VaultError.invalid("Vault is locked") }
        guard let http = result as? HTTPURLResponse, http.statusCode == 200 else { throw VaultError.invalid("Sync conflict. Retry to merge the newest changes") }
        let changedWhileSending = document?["revision"] as? Int != pushedLocalRevision
        if var data = document { data["items"] = Self.markPasskeysBackedUp(items); document = data }
        try record("sync")
        syncNeedsUpload = changedWhileSending
        lastSyncRemoteRevision = (try? JSONSerialization.jsonObject(with: resultBytes) as? Record)?["revision"] as? Int
    }
    private func merge(_ remote: Record) throws {
        guard var data = document, remote["schema"] as? Int == 1 else { throw VaultError.invalid("Invalid sync schema") }
        let local = Dictionary(items.compactMap { entry -> (String,Record)? in guard let id = entry["id"] as? String else { return nil }; return (id,entry) }, uniquingKeysWith: {a,_ in a})
        let incoming = Dictionary((remote["items"] as? [Record] ?? []).compactMap { entry -> (String,Record)? in guard let id = entry["id"] as? String else { return nil }; return (id,entry) }, uniquingKeysWith: {a,_ in a})
        var mergedItems:[Record] = []
        var conflicts:[Record] = []
        var knownIDs = Set(local.keys).union(incoming.keys)
        for id in Set(local.keys).union(incoming.keys) {
            guard let a = local[id] else { var item = incoming[id]!; item["allowAssistant"] = false; mergedItems.append(item); continue }
            guard let b = incoming[id] else { mergedItems.append(a); continue }
            let aTime = Self.timestamp(a["updatedAt"] as? String), bTime = Self.timestamp(b["updatedAt"] as? String)
            var item = bTime > aTime ? b : a
            item["allowAssistant"] = (a["allowAssistant"] as? Bool ?? false) && !VaultUtilities.assistantForbidden(item)
            let deletes = [a["deletedAt"] as? String,b["deletedAt"] as? String].compactMap{$0}
            let restores = [a["restoredAt"] as? String,b["restoredAt"] as? String].compactMap{$0}
            let deleted = deletes.max{Self.timestamp($0) < Self.timestamp($1)}
            let restored = restores.max{Self.timestamp($0) < Self.timestamp($1)}
            if let deleted, Self.timestamp(deleted) >= Self.timestamp(restored) {item["deletedAt"] = deleted;item["allowAssistant"] = false} else if restored != nil {item["deletedAt"] = nil}
            if let restored {item["restoredAt"] = restored}
            if aTime == bTime, (deleted == nil || Self.timestamp(restored) > Self.timestamp(deleted)), try Self.comparable(a) != Self.comparable(b) {
                let conflictID = try Self.conflictIdentifier(b)
                if knownIDs.insert(conflictID).inserted {
                    var conflict = b; conflict["id"] = conflictID; conflict["title"] = (b["title"] as? String ?? "Untitled") + " (sync conflict)"; conflict["allowAssistant"] = false
                    conflicts.append(conflict)
                }
            }

            var history = (a["passwordHistory"] as? [Record] ?? []) + (b["passwordHistory"] as? [Record] ?? [])
            let loser = bTime > aTime ? a : b
            if let password = loser["password"] as? String, password != item["password"] as? String {history.append(["password":password,"changedAt":loser["updatedAt"] as? String ?? Self.now()])}
            var seen = Set<String>(); history = history.filter { entry in let marker = (entry["password"] as? String ?? "") + "\u{0}" + (entry["changedAt"] as? String ?? ""); return seen.insert(marker).inserted }
            item["passwordHistory"] = history.sorted{Self.timestamp($0["changedAt"] as? String) < Self.timestamp($1["changedAt"] as? String)}
            mergedItems.append(item)
        }
        data["items"] = mergedItems + conflicts
        var vaultByID = Dictionary(vaults.compactMap { v -> (String,Record)? in guard let id = v["id"] as? String else{return nil};return (id,v) }, uniquingKeysWith:{a,_ in a})
        for var v in remote["vaults"] as? [Record] ?? [] {guard let id = v["id"] as? String,vaultByID[id] == nil else{continue};v["allowAssistant"] = false;v["allowBrowser"] = false;v["travelSafe"] = false;vaultByID[id] = v}
        data["vaults"] = Array(vaultByID.values)
        var logByID:[String:Record] = [:]
        for event in activity + (remote["activity"] as? [Record] ?? []) {if let id = event["id"] as? String {logByID[id] = event}}
        data["activity"] = Array(logByID.values).sorted{Self.timestamp($0["at"] as? String) < Self.timestamp($1["at"] as? String)}
        document = data; try save()
    }
    static func comparable(_ item:Record) throws -> String {
        var content = item; content["allowAssistant"] = nil; content["passwordHistory"] = nil
        return try canonicalJSON(content)
    }
    static func conflictIdentifier(_ item:Record) throws -> String {
        let input = (item["id"] as? String ?? "") + "\u{0}" + (try comparable(item))
        let hash = SHA256.hash(data:Data(input.utf8)).map{String(format:"%02x",$0)}.joined()
        let chars = Array(hash)
        func part(_ start:Int,_ end:Int)->String {String(chars[start..<end])}
        return part(0,8) + "-" + part(8,12) + "-4" + part(13,16) + "-a" + part(17,20) + "-" + part(20,32)
    }
    private static func canonicalJSON(_ value:Any) throws -> String {
        if let object = value as? Record {
            let keys = object.keys.filter{$0 != "backedUp"}.sorted{Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16))}
            return "{" + (try keys.map{key in (try canonicalJSON(key)) + ":" + (try canonicalJSON(object[key]!))}).joined(separator:",") + "}"
        }
        if let array = value as? [Any] {return "[" + (try array.map{try canonicalJSON($0)}).joined(separator:",") + "]"}
        let data = try JSONSerialization.data(withJSONObject:value,options:[.fragmentsAllowed,.withoutEscapingSlashes])
        return String(decoding:data,as:UTF8.self)
    }
    private static func markPasskeysBackedUp(_ items:[Record])->[Record] {
        items.map { original in var item = original; if var passkey = item["passkey"] as? Record { passkey["backedUp"] = true; item["passkey"] = passkey }; return item }
    }
    private static func timestamp(_ text:String?)->TimeInterval {
        guard let text else{return 0}
        let f = ISO8601DateFormatter();f.formatOptions = [.withInternetDateTime,.withFractionalSeconds]
        if let value = f.date(from:text){return value.timeIntervalSince1970}
        f.formatOptions = [.withInternetDateTime];return f.date(from:text)?.timeIntervalSince1970 ?? 0
    }

}
