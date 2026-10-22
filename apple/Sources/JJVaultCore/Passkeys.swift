import Foundation
import CryptoKit
public enum CBOR {
    static func header(_ major: UInt8,_ n: Int) -> Data {
        if n < 24 {return Data([major << 5 | UInt8(n)])}
        if n <= 255 {return Data([major << 5 | 24,UInt8(n)])}
        if n <= 65535 {return Data([major << 5 | 25,UInt8(n >> 8),UInt8(n & 255)])}
        return Data([major << 5 | 26,UInt8((n >> 24)&255),UInt8((n >> 16)&255),UInt8((n >> 8)&255),UInt8(n&255)])
    }
    public static func integer(_ n:Int)->Data {n >= 0 ? header(0,n):header(1,-1-n)}
    public static func bytes(_ d:Data)->Data {header(2,d.count)+d}
    public static func text(_ s:String)->Data {let d = Data(s.utf8);return header(3,d.count)+d}
    public static func map(_ entries:[(Data,Data)])->Data {entries.reduce(header(5,entries.count)){$0+$1.0+$1.1}}
}
public enum VaultPasskeys {
    public static func registration(rpID:String,userName:String,userHandle:Data,clientDataHash:Data,vaultID:String) throws -> (Record,Data) {
        guard validRP(rpID),clientDataHash.count == 32,userHandle.count <= 64,!userHandle.isEmpty else {throw VaultError.invalid("Invalid passkey request")}
        let key = P256.Signing.PrivateKey();let raw = key.publicKey.x963Representation;let credential = try VaultCrypto.random(32)
        let cose = CBOR.map([(CBOR.integer(1),CBOR.integer(2)),(CBOR.integer(3),CBOR.integer(-7)),(CBOR.integer(-1),CBOR.integer(1)),(CBOR.integer(-2),CBOR.bytes(raw.subdata(in:1..<33))),(CBOR.integer(-3),CBOR.bytes(raw.subdata(in:33..<65)))])
        let authenticator = Data(SHA256.hash(data:Data(rpID.utf8)))+Data([0x4d,0,0,0,0])+Data(repeating:0,count:16)+Data([0,32])+credential+cose
        let attestation = CBOR.map([(CBOR.text("fmt"),CBOR.text("none")),(CBOR.text("attStmt"),CBOR.map([])),(CBOR.text("authData"),CBOR.bytes(authenticator))])
        var item = VaultStore.newItem(type:"passkey",title:rpID + " (" + userName + ")",vaultID:vaultID)
        item["username"] = userName;item["urls"] = ["https://"+rpID]
        item["passkey"] = ["credentialId":credential.base64URL,"rpId":rpID,"userHandle":userHandle.base64URL,"userName":userName,"privateKey":key.derRepresentation.base64EncodedString(),"publicKey":key.publicKey.derRepresentation.base64EncodedString(),"signCount":0,"backedUp":false]
        return (item,attestation)
    }
    public static func assertion(item:Record,rpID:String,clientDataHash:Data) throws -> (Record,Data,Data) {
        guard validRP(rpID),clientDataHash.count == 32,var passkey = item["passkey"] as? Record,passkey["rpId"] as? String == rpID,let encoded = passkey["privateKey"] as? String,let der = Data(base64Encoded:encoded) else {throw VaultError.invalid("Passkey relying party mismatch")}
        let key = try P256.Signing.PrivateKey(derRepresentation:der)
        let previous = passkey["signCount"] as? UInt32 ?? UInt32(passkey["signCount"] as? Int ?? 0)
        // Synced credentials use a zero signature counter, as permitted by WebAuthn.
        // Device-local counters could regress after concurrent sync and trigger false clone alerts.
        _ = previous
        let flags: UInt8 = (passkey["backedUp"] as? Bool ?? false) ? 0x1d : 0x0d
        let authenticator = Data(SHA256.hash(data:Data(rpID.utf8)))+Data([flags,0,0,0,0])
        let signature = try key.signature(for:authenticator+clientDataHash).derRepresentation
        passkey["signCount"] = 0;var updated = item;updated["passkey"] = passkey
        return (updated,authenticator,signature)
    }
    public static func validRP(_ rpID:String)->Bool { !rpID.isEmpty && rpID.count <= 253 && !rpID.contains(":") && !rpID.contains("/") && !rpID.contains("@") && rpID == rpID.lowercased() && rpID.split(separator:".").allSatisfy{part in !part.isEmpty && part.allSatisfy{$0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-")} } }
}
