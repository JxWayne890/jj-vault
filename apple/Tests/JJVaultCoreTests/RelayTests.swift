import XCTest
import Security
@testable import JJVaultCore

#if os(macOS)
final class RelayTests: XCTestCase {
    private func fixtureCertificate() throws -> (URL, Data) {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "extendedKeyUsage=serverAuth", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-keyout", folder.appendingPathComponent("synthetic.key").path, "-out", folder.appendingPathComponent("synthetic.der").path, "-outform", "DER"]
        process.standardOutput = Pipe(); process.standardError = Pipe(); try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { try? FileManager.default.removeItem(at: folder); throw VaultError.invalid("Unable to generate synthetic TLS certificate") }
        return (folder, try Data(contentsOf: folder.appendingPathComponent("synthetic.der")))
    }
    private func trust(_ certificate: Data, host: String) throws -> SecTrust {
        let cert = try XCTUnwrap(SecCertificateCreateWithData(nil, certificate as CFData))
        var result: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(cert, SecPolicyCreateSSL(true, host as CFString), &result), errSecSuccess)
        return try XCTUnwrap(result)
    }
    private func code(_ certificate: Data, now: Date = Date(), changes: Record = [:]) throws -> VaultPairingCode {
        var object: Record = ["type": "jjvault-pairing", "version": 1, "url": "https://localhost:17374", "name": "Synthetic Mac", "certificate": certificate.base64EncodedString(), "nonce": Data(repeating: 7, count: 32).base64URL, "vaultId": "synthetic-vault", "expiresAt": ISO8601DateFormatter().string(from: now.addingTimeInterval(120))]
        changes.forEach { object[$0.key] = $0.value }
        return try VaultPairingCode.parse(String(decoding: JSONSerialization.data(withJSONObject: object), as: UTF8.self), now: now)
    }
    func testPairingCodeValidation() throws {
        let (folder, certificate) = try fixtureCertificate(); defer { try? FileManager.default.removeItem(at: folder) }
        let now = Date(); let valid = try code(certificate, now: now)
        XCTAssertEqual(valid.certificateData, certificate)
        XCTAssertEqual(valid.baseURL.host, "localhost")
        XCTAssertEqual(valid.fingerprint.split(separator: ":").count, 32)
        XCTAssertThrowsError(try code(certificate, now: now, changes: ["type": "otpauth"]))
        XCTAssertThrowsError(try code(certificate, now: now, changes: ["version": 2]))
        XCTAssertThrowsError(try code(certificate, now: now, changes: ["url": "http://localhost"]))
        XCTAssertThrowsError(try code(certificate, now: now, changes: ["url": "https://token@localhost"]))
        XCTAssertThrowsError(try code(certificate, now: now, changes: ["url": "https://localhost/forward?destination=other"]))
        XCTAssertThrowsError(try code(certificate, now: now, changes: ["expiresAt": ISO8601DateFormatter().string(from: now.addingTimeInterval(-1))]))
        XCTAssertThrowsError(try code(certificate, now: now, changes: ["expiresAt": ISO8601DateFormatter().string(from: now.addingTimeInterval(3600))]))
        XCTAssertThrowsError(try code(certificate, now: now, changes: ["certificate": Data("not a certificate".utf8).base64EncodedString()]))
        XCTAssertThrowsError(try VaultRelayConnection(code: valid, token: "bad\nheader"))
    }
    func testPinnedCertificateRequiresHostPinAndDate() throws {
        let (folder, certificate) = try fixtureCertificate(); defer { try? FileManager.default.removeItem(at: folder) }
        let validTrust = try trust(certificate, host: "localhost")
        let accepted = VaultRelayTrust.accepts(validTrust, host: "localhost", certificate: certificate)
        var failure: CFError?; _ = SecTrustEvaluateWithError(validTrust, &failure)
        XCTAssertTrue(accepted, failure.map { CFErrorCopyDescription($0) as String } ?? "No trust error")
        XCTAssertFalse(VaultRelayTrust.accepts(try trust(certificate, host: "attacker.example"), host: "attacker.example", certificate: certificate))
        XCTAssertFalse(VaultRelayTrust.accepts(try trust(certificate, host: "localhost"), host: "localhost", certificate: Data([1, 2, 3])))
        let expired = try trust(certificate, host: "localhost")
        XCTAssertEqual(SecTrustSetVerifyDate(expired, Date().addingTimeInterval(3 * 86400) as CFDate), errSecSuccess)
        XCTAssertFalse(VaultRelayTrust.accepts(expired, host: "localhost", certificate: certificate))
    }
    func testPairedEnvelopeDoesNotUnlockOrReplaceExistingVault() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: folder) }
        let source = VaultStore(url: folder.appendingPathComponent("source"))
        let secret = try source.create(master: "synthetic pairing master password")
        let bytes = try source.exportBackup(); let id = try XCTUnwrap(source.vaultIdentifier)
        let phone = VaultStore(url: folder.appendingPathComponent("phone"))
        XCTAssertThrowsError(try phone.installPairedEncryptedBackup(bytes, vaultID: "other"))
        XCTAssertFalse(phone.initialized)
        try phone.installPairedEncryptedBackup(bytes, vaultID: id)
        XCTAssertTrue(phone.initialized); XCTAssertTrue(phone.locked); XCTAssertTrue(phone.items.isEmpty)
        XCTAssertThrowsError(try phone.installPairedEncryptedBackup(bytes, vaultID: id))
        XCTAssertThrowsError(try phone.unlock(master: "wrong password", secret: secret))
        try phone.unlock(master: "synthetic pairing master password", secret: secret)
        XCTAssertFalse(phone.locked); XCTAssertEqual(phone.vaultIdentifier, id)
    }
    func testPinnedHTTPSPairStatusAndRejectedRedirect() async throws {
        let (folder, certificate) = try fixtureCertificate(); defer { try? FileManager.default.removeItem(at: folder) }
        let source = VaultStore(url: folder.appendingPathComponent("synthetic-source")); _ = try source.create(master: "synthetic HTTPS pairing master")
        let envelope = folder.appendingPathComponent("envelope.json"); try source.exportBackup().write(to: envelope)
        let server = Process(); server.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        server.arguments = ["-u", "-c", """
import http.server,json,ssl,sys,pathlib
folder=pathlib.Path(sys.argv[1]);envelope=json.loads((folder/'envelope.json').read_text());used=False
(folder/'synthetic.pem').write_text(ssl.DER_cert_to_PEM_cert((folder/'synthetic.der').read_bytes()))
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,status,value):
  self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(value).encode())
 def do_POST(self):
  global used
  body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
  if body.get('nonce')=='CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk':
   (folder/'redirect-issued').write_text('302');self.send_response(302);self.send_header('Location','https://localhost:'+str(self.server.server_port)+'/steal');self.end_headers();return
  if self.path!='/pair' or used:return self.reply(401,{})
  used=True;self.reply(200,{'token':'A'*43,'revision':0,'envelope':envelope})
 def do_GET(self):
  if self.path=='/steal':(folder/'redirect-target-hit').write_text('unexpected redirect')
  if self.headers.get('Authorization')!='Bearer '+'A'*43:return self.reply(401,{})
  self.reply(200,{'revision':0,'vaultId':envelope['id']})
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
context.load_cert_chain(str(folder/'synthetic.pem'),str(folder/'synthetic.key'));server.socket=context.wrap_socket(server.socket,server_side=True)
print(server.server_port,flush=True);server.serve_forever()
""", folder.path]
        let output = Pipe(); server.standardOutput = output; server.standardError = Pipe(); try server.run(); defer { server.terminate() }
        var line = Data()
        while let byte = try output.fileHandleForReading.read(upToCount: 1), !byte.isEmpty { if byte[0] == 10 { break }; line.append(byte) }
        let port = try XCTUnwrap(Int(String(decoding: line, as: UTF8.self)))
        let pairing = try code(certificate, changes: ["url": "https://localhost:\(port)", "vaultId": source.vaultIdentifier!])
        let result = try await VaultRelayAPI.pair(pairing)
        XCTAssertEqual(result.connection.vaultId, source.vaultIdentifier)
        XCTAssertEqual(try JSONDecoder().decode(Envelope.self, from: result.encryptedBackup).id, source.vaultIdentifier)
        let revision = try await VaultRelayAPI.status(result.connection); XCTAssertEqual(revision, 0)
        do { _ = try await VaultRelayAPI.pair(pairing); XCTFail("Replayed pairing nonce was accepted") } catch {}
        let redirect = try code(certificate, changes: ["url": "https://localhost:\(port)", "vaultId": source.vaultIdentifier!, "nonce": Data(repeating: 9, count: 32).base64URL])
        do { _ = try await VaultRelayAPI.pair(redirect); XCTFail("Pairing followed a redirect") } catch {}
        XCTAssertTrue(FileManager.default.fileExists(atPath: folder.appendingPathComponent("redirect-issued").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: folder.appendingPathComponent("redirect-target-hit").path))
    }
}
#endif
