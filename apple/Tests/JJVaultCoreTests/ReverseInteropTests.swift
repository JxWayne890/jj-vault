import XCTest
@testable import JJVaultCore

#if os(macOS)
final class ReverseInteropTests: XCTestCase {
    func testJavaScriptBootstrapSwiftEditJavaScriptMergeAndSwiftDecrypt() throws {
        guard let nodeRoot = ProcessInfo.processInfo.environment["JJ_VAULT_NODE_SOURCE"] else { throw XCTSkip("Set JJ_VAULT_NODE_SOURCE to the repository with installed JavaScript dependencies") }
        let fixtureURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("interop.json")
        let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? Record)
        let original = try JSONSerialization.data(withJSONObject: fixture["envelope"]!)
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("synthetic-phone.jjvault"); try original.write(to: file)
        let phone = VaultStore(url: file)
        let master = try XCTUnwrap(fixture["password"] as? String); let secret = try XCTUnwrap(fixture["secretKey"] as? String)
        try phone.unlock(master: master, secret: secret)
        if phone.vaults.isEmpty { try phone.addVault("Synthetic interoperability vault") }
        var item = phone.items.first ?? VaultStore.newItem(vaultID: phone.vaults[0]["id"] as! String)
        item["title"] = "Synthetic native edit"; item["password"] = "Synthetic native password only"; try phone.upsert(item)
        var input = fixture
        input["nativeEnvelope"] = try JSONSerialization.jsonObject(with: phone.exportBackup())
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/env"); process.currentDirectoryURL = URL(fileURLWithPath: nodeRoot)
        process.arguments = ["node", "--import", "tsx", "--input-type=module", "-e", """
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import {deriveKey,open,seal} from './packages/core/src/crypto.ts';
import {mergeData} from './packages/core/src/engine.ts';
const fixture=JSON.parse(readFileSync(0,'utf8'));
const key=await deriveKey(fixture.password,fixture.secretKey,fixture.envelope);
try {
 const local=open(fixture.envelope,key),native=open(fixture.nativeEnvelope,key);
 const merged=mergeData(local,native);
 const item=merged.items.find(item=>item.title==='Synthetic native edit');
 assert.equal(item?.password,'Synthetic native password only');
 item.username='Synthetic JavaScript merge';
 process.stdout.write(JSON.stringify(seal(merged,key,fixture.nativeEnvelope)));
}finally{key.fill(0);}
"""]
        let incoming = Pipe(), outgoing = Pipe(), errors = Pipe(); process.standardInput = incoming; process.standardOutput = outgoing; process.standardError = errors
        try process.run()
        let watchdog = DispatchWorkItem { if process.isRunning { process.terminate() } }; DispatchQueue.global().asyncAfter(deadline: .now() + 30, execute: watchdog); defer { watchdog.cancel() }
        incoming.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject: input)); try incoming.fileHandleForWriting.close()
        let result = outgoing.fileHandleForReading.readDataToEndOfFile(); let errorText = errors.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: errorText, as: UTF8.self))
        let returned = try JSONDecoder().decode(Envelope.self, from: result)
        let (plain, _) = try VaultCrypto.open(returned, master: master, secret: secret)
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: plain) as? Record)
        let changed = try XCTUnwrap((body["items"] as? [Record])?.first { $0["title"] as? String == "Synthetic native edit" })
        XCTAssertEqual(changed["username"] as? String, "Synthetic JavaScript merge")
        XCTAssertEqual(changed["password"] as? String, "Synthetic native password only")
        XCTAssertEqual(returned.id, phone.vaultIdentifier)
    }
}
#endif
