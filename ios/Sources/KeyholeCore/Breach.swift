import CryptoKit
import Foundation

/// Have I Been Pwned k-anonymity helpers — pure, no I/O.
/// Surfaces fetch `https://api.pwnedpasswords.com/range/{prefix}` themselves
/// (with `Add-Padding: true`) and pass the body here.

public struct RangeQuery: Sendable, Equatable {
    /// First 5 hex characters of the SHA-1 digest (uppercase).
    public var prefix: String
    /// Remaining 35 hex characters (uppercase).
    public var suffix: String

    public init(prefix: String, suffix: String) {
        self.prefix = prefix
        self.suffix = suffix
    }
}

/// SHA-1 the password and split it for the HIBP range API.
public func hashForRangeQuery(_ password: String) -> RangeQuery {
    let digest = Insecure.SHA1.hash(data: Data(password.utf8))
    let hex = EncodingUtil.bytesToHex(Array(digest)).uppercased()
    return RangeQuery(prefix: String(hex.prefix(5)), suffix: String(hex.dropFirst(5)))
}

/**
 Count how many times `suffix` appears in a HIBP range response body.

 Each line is `SUFFIX:COUNT`. Matching is case-insensitive; a missing suffix
 is zero (not breached, or at least not in this dump).
 */
public func countFromRangeResponse(_ text: String, suffix: String) -> Int {
    let target = suffix.uppercased()
    for line in text.split(whereSeparator: \.isNewline) {
        if line.isEmpty { continue }
        guard let colon = line.firstIndex(of: ":") else { continue }
        let left = line[..<colon].uppercased()
        if left != target { continue }
        let countPart = line[line.index(after: colon)...]
        let count = Int(countPart) ?? 0
        return count >= 0 ? count : 0
    }
    return 0
}
