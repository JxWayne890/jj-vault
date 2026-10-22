import XCTest
import CryptoKit
@testable import JJVaultCore
final class CoreTests: XCTestCase {
    func testEncryptionAndTamper() throws {
        let secret = try VaultCrypto.secretKey()
        let (e,key) = try VaultCrypto.create(data: Data("fixture".utf8), master:"correct horse battery staple", secret:secret)
        XCTAssertEqual(try VaultCrypto.open(e,master:"correct horse battery staple",secret:secret).0,Data("fixture".utf8))
        XCTAssertThrowsError(try VaultCrypto.open(e,master:"incorrect password",secret:secret))
        XCTAssertThrowsError(try VaultCrypto.open(e,master:"correct horse battery staple",secret:VaultCrypto.secretKey()))
        var altered = e; altered.id = "different"
        XCTAssertThrowsError(try VaultCrypto.open(altered,key:key))
        altered = e; altered.kdf.memoryKiB = 4294967295
        XCTAssertThrowsError(try VaultCrypto.derive(master:"test",secret:secret,envelope:altered))
    }
    func testTOTP() throws {
        XCTAssertEqual(try VaultUtilities.totp("otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",time:59),"94287082")
        XCTAssertEqual(try VaultUtilities.totp("otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",time:1111111109),"07081804")
    }
    func testOriginMatching() {
        XCTAssertTrue(VaultUtilities.matches("https://example.com","https://example.com/account"))
        XCTAssertFalse(VaultUtilities.matches("https://example.com","http://example.com"))
        XCTAssertFalse(VaultUtilities.matches("https://example.com","https://example.com.attacker.test"))
        XCTAssertFalse(VaultUtilities.matches("https://example.com","https://sub.example.com"))
    }
    func testStoreHistoryAndRestrictions() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at:url) }
        let store = VaultStore(url:url); let secret = try store.create(master:"long test master password")
        var item = VaultStore.newItem(type:"bankAccount",title:"Test bank",vaultID:store.vaults[0]["id"] as! String)
        item["password"] = "old"; item["allowAssistant"] = true; try store.upsert(item)
        XCTAssertEqual(store.items[0]["allowAssistant"] as? Bool,false)
        item = store.items[0]; item["password"] = "new"; try store.upsert(item)
        XCTAssertEqual((store.items[0]["passwordHistory"] as? [Record])?.first?["password"] as? String,"old")
        store.lock(); XCTAssertTrue(store.locked)
        try store.unlock(master:"long test master password",secret:secret); XCTAssertFalse(store.locked)
        try store.delete(store.items[0]); XCTAssertTrue(store.visibleItems().isEmpty)
        try store.delete(store.items[0],restore:true); XCTAssertEqual(store.visibleItems().count,1)
    }
    func testWatchtower() {
        let a: Record = ["title":"one","password":"short","type":"login","urls":["http://test.example"]]
        let b: Record = ["title":"two","password":"short"]
        XCTAssertGreaterThanOrEqual(VaultUtilities.watchtower([a,b]).count,5)
    }
    func testPasskeySignatureAndRPBinding() throws {
        let hash = Data(repeating: 17, count: 32)
        let (item,attestation) = try VaultPasskeys.registration(rpID:"example.com",userName:"fixture",userHandle:Data([1,2,3]),clientDataHash:hash,vaultID:"fixture-vault")
        XCTAssertEqual(attestation.first,0xa3)
        let (_,auth,signature) = try VaultPasskeys.assertion(item:item,rpID:"example.com",clientDataHash:hash)
        let pk = item["passkey"] as! Record
        let key = try P256.Signing.PublicKey(derRepresentation:Data(base64Encoded:pk["publicKey"] as! String)!)
        XCTAssertTrue(key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation:signature),for:auth+hash))
        XCTAssertEqual(auth.count,37)
        XCTAssertEqual(auth[32],0x0d)
        XCTAssertThrowsError(try VaultPasskeys.assertion(item:item,rpID:"evil.example",clientDataHash:hash))
        XCTAssertThrowsError(try VaultPasskeys.registration(rpID:"example.com/path",userName:"fixture",userHandle:Data([1]),clientDataHash:hash,vaultID:"fixture"))
    }
    func testGeneratorAndAssistantRestrictions() throws {
        XCTAssertEqual(try VaultUtilities.passphrase(words:6).split(separator:" ").count,6)
        XCTAssertEqual(try VaultUtilities.password(length:8,alphabet:"0123456789").count,8)
        XCTAssertTrue(VaultUtilities.assistantForbidden(["type":"login","title":"X Money","urls":[]]))
        XCTAssertTrue(VaultUtilities.assistantForbidden(["type":"login","title":"Wallet","urls":["https://money.x.com"]]))
        XCTAssertTrue(VaultUtilities.assistantForbidden(["type":"creditCard","title":"Card"]))
        XCTAssertFalse(VaultUtilities.assistantForbidden(["type":"login","title":"Example","urls":["https://example.com"]]))
    }
    #if os(macOS)
    func testEncryptedSyncBetweenDevices() async throws {
        let server = Process();server.executableURL = URL(fileURLWithPath:"/usr/bin/python3")
        server.arguments = ["-u","-c", """
import http.server,json,time
state={'revision':0,'envelope':None}
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def reply(self,status,payload):
  self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(payload).encode())
 def do_GET(self):
  time.sleep(0.1)
  if self.headers.get('Authorization')!='Bearer synthetic-relay-token': return self.reply(401,{})
  self.reply(200,state)
 def do_PUT(self):
  if self.headers.get('Authorization')!='Bearer synthetic-relay-token': return self.reply(401,{})
  body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
  if body['expectedRevision']!=state['revision']: return self.reply(409,{})
  state.update(revision=state['revision']+1,envelope=body['envelope']);self.reply(200,{'revision':state['revision']})
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
print(server.server_port,flush=True)
server.serve_forever()
"""]
        let pipe = Pipe();server.standardOutput = pipe;server.standardError = Pipe();try server.run();defer{server.terminate()}
        var portLine = Data()
        while let byte = try pipe.fileHandleForReading.read(upToCount:1),!byte.isEmpty {if byte[0] == 10 {break};portLine.append(byte)}
        let port = try XCTUnwrap(Int(String(data:portLine,encoding:.utf8)!));let base = URL(string:"http://127.0.0.1:\(port)")!
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString);try FileManager.default.createDirectory(at:folder,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:folder)}
        let a = VaultStore(url:folder.appendingPathComponent("a"));let secret = try a.create(master:"synthetic master password only")
        let b = VaultStore(url:folder.appendingPathComponent("b"));try b.importBackup(a.exportBackup(),master:"synthetic master password only",secret:secret)
        var item = VaultStore.newItem(title:"Synthetic sync example",vaultID:a.vaults[0]["id"] as! String);item["password"] = "fake fixture value";try a.upsert(item)
        try await a.sync(base:base,token:"synthetic-relay-token")
        try await b.sync(base:base,token:"synthetic-relay-token")
        XCTAssertEqual(b.items.first?["password"] as? String,"fake fixture value")
        var changed = try XCTUnwrap(b.items.first);changed["title"] = "Changed on phone";try b.upsert(changed)
        try await b.sync(base:base,token:"synthetic-relay-token");try await a.sync(base:base,token:"synthetic-relay-token")
        XCTAssertEqual(a.items.first?["title"] as? String,"Changed on phone")
        do {try await a.sync(base:base,token:"wrong-token");XCTFail("Unauthorized sync succeeded")}catch{}
        // A stale ordinary edit cannot restore a deletion.
        let stale = try XCTUnwrap(b.items.first)
        try a.delete(a.items[0]);try await a.sync(base:base,token:"synthetic-relay-token")
        var staleEdit = stale;staleEdit["notes"] = "Stale device edit";try b.upsert(staleEdit)
        try await b.sync(base:base,token:"synthetic-relay-token")
        XCTAssertNotNil(b.items[0]["deletedAt"])
        XCTAssertEqual(b.items[0]["allowAssistant"] as? Bool,false)
        try b.delete(b.items[0],restore:true);try await b.sync(base:base,token:"synthetic-relay-token");try await a.sync(base:base,token:"synthetic-relay-token")
        XCTAssertNil(a.items[0]["deletedAt"])
        // An in-flight fetch cannot repopulate a session that has since locked.
        let syncing = Task {try await a.sync(base:base,token:"synthetic-relay-token")}
        try await Task.sleep(nanoseconds:20_000_000)
        await MainActor.run {a.lock()}
        do {try await syncing.value;XCTFail("Locked session continued syncing")}catch{}
        XCTAssertTrue(a.locked)

    }
    #endif
    func testConflictCanonicalizationMatchesNode() throws {
        let path = URL(fileURLWithPath:#filePath).deletingLastPathComponent().appendingPathComponent("conflict.json")
        let fixture = try JSONSerialization.jsonObject(with:Data(contentsOf:path)) as! Record
        let item = fixture["item"] as! Record
        XCTAssertEqual(try VaultStore.comparable(item),fixture["canonical"] as? String)
        XCTAssertEqual(try VaultStore.conflictIdentifier(item),fixture["expectedId"] as? String)
    }
    func testTravelFiltersAllCollections() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString);defer{try? FileManager.default.removeItem(at:url)}
        let store = VaultStore(url:url);_ = try store.create(master:"synthetic master password")
        let unsafe = store.vaults[0]["id"] as! String
        try store.addVault("Travel safe")
        var safe = store.vaults[1];safe["travelSafe"] = true;try store.updateVault(safe)
        try store.upsert(VaultStore.newItem(title:"Unsafe title",vaultID:unsafe))
        try store.upsert(VaultStore.newItem(title:"Safe title",vaultID:safe["id"] as! String))
        var settings = store.settings;settings["travelMode"] = true;try store.updateSettings(settings)
        XCTAssertEqual(store.travelVisibleVaults.count,1)
        XCTAssertEqual(store.travelVisibleItems.count,1)
        XCTAssertEqual(store.travelVisibleItems.first?["title"] as? String,"Safe title")
    }
    func testEveryLockEmitsInputClearingGeneration() {
        let store = VaultStore(url:FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
        XCTAssertTrue(store.locked)
        let generation = store.lockGeneration
        store.lock();store.lock()
        XCTAssertTrue(store.locked)
        XCTAssertEqual(store.lockGeneration,generation + 2)
    }
    func testInteropFixture() throws {
        let fixture = URL(fileURLWithPath:#filePath).deletingLastPathComponent().appendingPathComponent("interop.json")
        guard FileManager.default.fileExists(atPath:fixture.path) else { throw XCTSkip("TypeScript interoperability fixture has not been generated") }
        let data = try JSONSerialization.jsonObject(with:Data(contentsOf:fixture)) as! Record
        let e = try JSONDecoder().decode(Envelope.self,from:JSONSerialization.data(withJSONObject:data["envelope"]!))
        let (plain,_) = try VaultCrypto.open(e,master:data["password"] as! String,secret:data["secretKey"] as! String)
        let decoded = try JSONSerialization.jsonObject(with:plain) as! Record
        XCTAssertEqual(decoded["schema"] as? Int,1)
    }
}
