import CryptoKit
import Foundation

private let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

public func base32Decode(_ input: String) throws -> [UInt8] {
    let clean = input
        .uppercased()
        .replacingOccurrences(of: "[\\s-]", with: "", options: .regularExpression)
        .replacingOccurrences(of: "=+$", with: "", options: .regularExpression)
    if clean.isEmpty {
        throw KeyholeError.validation("TOTP secret is empty.")
    }

    var bits = 0
    var value = 0
    var out: [UInt8] = []
    for char in clean {
        guard let index = base32Alphabet.firstIndex(of: char) else {
            throw KeyholeError.validation("TOTP secret is not valid base32.")
        }
        let idx = base32Alphabet.distance(from: base32Alphabet.startIndex, to: index)
        value = (value << 5) | idx
        bits += 5
        if bits >= 8 {
            bits -= 8
            out.append(UInt8((value >> bits) & 0xff))
        }
    }
    return out
}

public struct TotpOptions: Sendable {
    public var digits: Int
    public var periodSeconds: Int
    public var algorithm: TotpAlgorithm

    public init(digits: Int = 6, periodSeconds: Int = 30, algorithm: TotpAlgorithm = .sha1) {
        self.digits = digits
        self.periodSeconds = periodSeconds
        self.algorithm = algorithm
    }
}

public enum TotpAlgorithm: String, Codable, Sendable {
    case sha1 = "SHA-1"
    case sha256 = "SHA-256"
    case sha512 = "SHA-512"
}

public struct TotpCode: Sendable {
    public var code: String
    public var secondsRemaining: Int
    public var periodSeconds: Int

    public init(code: String, secondsRemaining: Int, periodSeconds: Int) {
        self.code = code
        self.secondsRemaining = secondsRemaining
        self.periodSeconds = periodSeconds
    }
}

public func generateTotp(
    base32Secret: String,
    options: TotpOptions = TotpOptions(),
    atMs: Double = Date().timeIntervalSince1970 * 1000
) throws -> TotpCode {
    let digits = options.digits
    let period = options.periodSeconds
    if digits < 6 || digits > 10 {
        throw KeyholeError.validation("TOTP digits must be between 6 and 10.")
    }
    if period < 1 {
        throw KeyholeError.validation("TOTP period must be positive.")
    }

    var secret = try base32Decode(base32Secret)
    defer { KeyholeCrypto.zeroize(&secret) }

    let counter = Int(floor(atMs / 1000.0 / Double(period)))
    var counterBytes = [UInt8](repeating: 0, count: 8)
    let high = UInt32(counter >> 32)
    let low = UInt32(truncatingIfNeeded: counter)
    counterBytes[0] = UInt8((high >> 24) & 0xff)
    counterBytes[1] = UInt8((high >> 16) & 0xff)
    counterBytes[2] = UInt8((high >> 8) & 0xff)
    counterBytes[3] = UInt8(high & 0xff)
    counterBytes[4] = UInt8((low >> 24) & 0xff)
    counterBytes[5] = UInt8((low >> 16) & 0xff)
    counterBytes[6] = UInt8((low >> 8) & 0xff)
    counterBytes[7] = UInt8(low & 0xff)

    let key = SymmetricKey(data: Data(secret))
    let macData: Data
    switch options.algorithm {
    case .sha1:
        macData = Data(HMAC<Insecure.SHA1>.authenticationCode(for: Data(counterBytes), using: key))
    case .sha256:
        macData = Data(HMAC<SHA256>.authenticationCode(for: Data(counterBytes), using: key))
    case .sha512:
        macData = Data(HMAC<SHA512>.authenticationCode(for: Data(counterBytes), using: key))
    }
    let mac = [UInt8](macData)

    let offset = Int(mac[mac.count - 1] & 0x0f)
    let binary =
        (Int(mac[offset] & 0x7f) << 24)
        | (Int(mac[offset + 1] & 0xff) << 16)
        | (Int(mac[offset + 2] & 0xff) << 8)
        | Int(mac[offset + 3] & 0xff)

    let modulus = Int(pow(10.0, Double(digits)))
    let codeNum = binary % modulus
    let code = String(format: "%0\(digits)d", codeNum)
    let secondsRemaining = period - (Int(floor(atMs / 1000.0)) % period)
    return TotpCode(code: code, secondsRemaining: secondsRemaining, periodSeconds: period)
}

public struct OtpAuthParsed: Sendable {
    public var secret: String
    public var options: TotpOptions
    public var label: String
}

public func parseOtpAuthUri(_ uri: String) -> OtpAuthParsed? {
    guard let url = URL(string: uri) else { return nil }
    guard url.scheme?.lowercased() == "otpauth", url.host?.lowercased() == "totp" else { return nil }
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
    let params = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item -> (String, String)? in
        guard let v = item.value else { return nil }
        return (item.name.lowercased(), v)
    })
    guard let secret = params["secret"] else { return nil }

    let digits = Int(params["digits"] ?? "6") ?? 6
    let period = Int(params["period"] ?? "30") ?? 30
    let rawAlg = (params["algorithm"] ?? "SHA1").uppercased()
    let algorithm: TotpAlgorithm =
        rawAlg == "SHA256" ? .sha256 : rawAlg == "SHA512" ? .sha512 : .sha1

    let label = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        .removingPercentEncoding ?? url.path

    return OtpAuthParsed(
        secret: secret,
        options: TotpOptions(digits: digits, periodSeconds: period, algorithm: algorithm),
        label: label
    )
}

/// Collapse TOTP options to `nil` when they match the generateTotp defaults, so
/// existing entries stay indistinguishable from "never set a config".
public func normalizeTotpConfig(_ options: TotpOptions?) -> TotpConfig? {
    guard let options else { return nil }
    if options.digits == 6 && options.periodSeconds == 30 && options.algorithm == .sha1 {
        return nil
    }
    return TotpConfig(
        digits: options.digits,
        periodSeconds: options.periodSeconds,
        algorithm: options.algorithm
    )
}

public func totpOptions(from config: TotpConfig?) -> TotpOptions {
    guard let config else { return TotpOptions() }
    return TotpOptions(
        digits: config.digits,
        periodSeconds: config.periodSeconds,
        algorithm: config.algorithm
    )
}
