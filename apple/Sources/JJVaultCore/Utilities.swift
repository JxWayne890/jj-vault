import Foundation
import CryptoKit
public enum VaultUtilities {
    public static func assistantForbidden(_ item:Record)->Bool {
        guard item["type"] as? String == "login" else{return true}
        let title = item["title"] as? String ?? ""
        if title.range(of:"\\bx\\s*money\\b",options:[.regularExpression,.caseInsensitive]) != nil{return true}
        return (item["urls"] as? [String] ?? []).contains{url in
            guard let host = URLComponents(string:url.contains("://") ? url:"https://"+url)?.host?.lowercased() else{return false}
            return host == "x.money" || host.hasSuffix(".x.money") || host == "money.x.com" || host.hasSuffix(".money.x.com")
        }
    }

    public static func matches(_ saved: String, _ page: String) -> Bool {
        guard let a = URLComponents(string: saved.contains("://") ? saved : "https://" + saved), let b = URLComponents(string: page), let ah = a.host?.lowercased(), let bh = b.host?.lowercased(), ["http","https"].contains(b.scheme ?? ""), ["http","https"].contains(a.scheme ?? "") else { return false }
        return ah == bh && a.port == b.port && !(a.scheme == "https" && b.scheme != "https")
    }
    public static func passphrase(words:Int = 6) throws -> String {
        guard words >= 4,words <= 20 else{throw VaultError.invalid("Choose 4 to 20 words")}
        var result:[String] = []
        let count = UInt32(VaultWords.all.count)
        let limit = UInt32.max - UInt32.max % count
        while result.count < words {
            let bytes = try VaultCrypto.random(4)
            let n = bytes.reduce(UInt32(0)){($0 << 8) | UInt32($1)}
            if n < limit {result.append(VaultWords.all[Int(n % count)])}
        }
        return result.joined(separator:" ")
    }
    public static func password(length: Int = 24, alphabet: String = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*") throws -> String {
        let chars = Array(alphabet); guard !chars.isEmpty, chars.count <= 256, length >= 4, length <= 256 else { throw VaultError.invalid("Invalid generator options") }
        var output = ""; let ceiling = 256 - (256 % chars.count)
        while output.count < length { for byte in try VaultCrypto.random(length) where Int(byte) < ceiling { output.append(chars[Int(byte) % chars.count]); if output.count == length { break } } }
        return output
    }
    public static func totp(_ source: String, time: TimeInterval = Date().timeIntervalSince1970) throws -> String {
        var secret = source, period = 30, digits = 6, algorithm = "SHA1"
        if source.hasPrefix("otpauth://") {
            guard let url = URLComponents(string: source), url.host == "totp" else { throw VaultError.invalid("Only TOTP QR codes are supported") }
            let query = url.queryItems ?? []; secret = query.first(where: {$0.name == "secret"})?.value ?? ""
            period = Int(query.first(where: {$0.name == "period"})?.value ?? "30") ?? 30; digits = Int(query.first(where: {$0.name == "digits"})?.value ?? "6") ?? 6; algorithm = (query.first(where: {$0.name == "algorithm"})?.value ?? "SHA1").uppercased()
        }
        guard period > 0, period <= 300, [6,8].contains(digits) else { throw VaultError.invalid("Invalid TOTP parameters") }
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"); var value: UInt64 = 0; var bits = 0; var key = Data()
        for c in secret.uppercased().filter({$0 != " " && $0 != "="}) {
            guard let n = alphabet.firstIndex(of: c) else { throw VaultError.invalid("Invalid TOTP secret") }
            value = (value << 5) | UInt64(n); bits += 5
            if bits >= 8 { bits -= 8; key.append(UInt8((value >> bits) & 255)) }
        }
        guard !key.isEmpty else { throw VaultError.invalid("Missing TOTP secret") }
        var counter = UInt64(time / Double(period)).bigEndian
        let message = withUnsafeBytes(of: &counter) { Data($0) }; let symmetric = SymmetricKey(data:key); let digest: Data
        switch algorithm {
        case "SHA1": digest = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetric))
        case "SHA256": digest = Data(HMAC<SHA256>.authenticationCode(for: message, using: symmetric))
        case "SHA512": digest = Data(HMAC<SHA512>.authenticationCode(for: message, using: symmetric))
        default: throw VaultError.invalid("Unsupported TOTP algorithm")
        }
        let offset = Int(digest.last! & 15); var truncated: UInt32 = 0
        for byte in digest[offset..<offset+4] { truncated = (truncated << 8) | UInt32(byte) }
        return String(format:"%0*u", digits, (truncated & 0x7fffffff) % UInt32(pow(10.0,Double(digits))))
    }
    public static func watchtower(_ items: [Record]) -> [(String,String)] {
        let active = items.filter { $0["deletedAt"] == nil && !($0["archived"] as? Bool ?? false) }; var found: [(String,String)] = []
        for i in active {
            let title = i["title"] as? String ?? "Untitled", p = i["password"] as? String ?? ""
            if !p.isEmpty && p.count < 14 { found.append((title,"Weak password")) }
            if !p.isEmpty && active.filter({$0["password"] as? String == p}).count > 1 { found.append((title,"Reused password")) }
            if i["type"] as? String == "login" && (i["totp"] as? String ?? "").isEmpty { found.append((title,"No stored two factor authentication")) }
            if (i["urls"] as? [String] ?? []).contains(where: {$0.lowercased().hasPrefix("http://")}) { found.append((title,"Unsecured HTTP website")) }
            if let date = i["expiresAt"] as? String, String(date.prefix(10)) <= String(ISO8601DateFormatter().string(from: Date().addingTimeInterval(30*86400)).prefix(10)) { found.append((title,"Expired or expires within 30 days")) }
        }; return found
    }
    public static func breached(_ password: String) async throws -> Int {
        let hash = Insecure.SHA1.hash(data: Data(password.utf8)).map{String(format:"%02X",$0)}.joined()
        let url = URL(string:"https://api.pwnedpasswords.com/range/" + hash.prefix(5))!
        var request = URLRequest(url:url); request.setValue("true",forHTTPHeaderField:"Add-Padding")
        let (data,response) = try await URLSession.shared.data(for:request)
        guard (response as? HTTPURLResponse)?.statusCode == 200, let text = String(data:data,encoding:.utf8) else { throw VaultError.invalid("Breach check unavailable") }
        for line in text.components(separatedBy:.newlines) { let parts = line.split(separator:":"); if parts.count == 2 && parts[0] == hash.dropFirst(5) { return Int(parts[1].trimmingCharacters(in:.whitespacesAndNewlines)) ?? 0 } }; return 0
    }
}
