import Foundation

/// Secret Key and Recovery Code encoding.
///
/// Swift port of `core/src/secret-key.ts`. The encoding is a wire format shared with
/// the TypeScript core — a key printed on a Recovery Kit by the desktop app is typed
/// back in on iOS — so the alphabet, grouping, checksum polynomial and bit order here
/// are a compatibility contract, not implementation choices. `SecretKeyVectorTests`
/// pins them against the same vectors the TS suite uses.
///
/// See the TypeScript original for why a checksum exists at all (a mistyped Secret Key
/// is otherwise indistinguishable from a wrong master password), why the alphabet is
/// Crockford Base32, and why the two kit halves carry distinct prefixes.
public enum SecretKind: String, Sendable {
    case secretKey
    case recoveryCode

    var prefix: String {
        switch self {
        case .secretKey: return "KH2SK"
        case .recoveryCode: return "KH2RC"
        }
    }

    var label: String {
        switch self {
        case .secretKey: return "Secret Key"
        case .recoveryCode: return "Recovery Code"
        }
    }
}

public enum SecretKeyCoding {
    /// 128 bits, matching `SECRET_KEY_BYTES` in the TypeScript core.
    public static let secretKeyBytes = 16

    /// Crockford Base32: no I, L, O or U.
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// Confusable glyphs folded onto what the reader meant.
    private static let aliases: [Character: Character] = ["I": "1", "L": "1", "O": "0"]

    private static let group = 4
    private static let checkBits = 10
    private static let encodedChars = (secretKeyBytes * 8 + checkBits + 4) / 5

    private static let values: [Character: Int] = {
        var map: [Character: Int] = [:]
        for (index, char) in alphabet.enumerated() { map[char] = index }
        return map
    }()

    // MARK: Checksum

    /// CRC-16/CCITT-FALSE truncated to `checkBits`. Catches transpositions, which a
    /// plain sum does not.
    private static func crc16(_ bytes: [UInt8]) -> Int {
        var crc = 0xffff
        for byte in bytes {
            crc ^= Int(byte) << 8
            for _ in 0..<8 {
                crc = (crc & 0x8000) != 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff
            }
        }
        return crc & ((1 << checkBits) - 1)
    }

    // MARK: Generation

    /// Fresh random Secret Key / Recovery Code material. Caller must zeroize.
    public static func generateSecretKeyBytes() -> [UInt8] {
        KeyholeCrypto.randomBytes(secretKeyBytes)
    }

    // MARK: Encoding

    public static func formatSecret(_ kind: SecretKind, _ raw: [UInt8]) throws -> String {
        guard raw.count == secretKeyBytes else {
            throw KeyholeError.validation("Expected \(secretKeyBytes) bytes, got \(raw.count).")
        }

        var acc = 0
        var bits = 0
        var body = ""

        func push(_ value: Int, _ width: Int) {
            acc = (acc << width) | value
            bits += width
            while bits >= 5 {
                bits -= 5
                body.append(alphabet[(acc >> bits) & 31])
                acc &= (1 << bits) - 1
            }
        }

        for byte in raw { push(Int(byte), 8) }
        push(crc16(raw), checkBits)
        if bits > 0 { body.append(alphabet[(acc << (5 - bits)) & 31]) }

        var groups: [String] = []
        var index = body.startIndex
        while index < body.endIndex {
            let end = body.index(index, offsetBy: group, limitedBy: body.endIndex) ?? body.endIndex
            groups.append(String(body[index..<end]))
            index = end
        }
        return "\(kind.prefix)-\(groups.joined(separator: "-"))"
    }

    // MARK: Decoding

    /// Parse a Secret Key / Recovery Code back to bytes.
    ///
    /// Tolerant of transcription artefacts (case, dashes, whitespace, confusable
    /// glyphs) and strict about everything else. A checksum failure is reported as a
    /// typo, never as a wrong key — it is the only thing it actually proves.
    public static func parseSecret(_ kind: SecretKind, _ input: String) throws -> [UInt8] {
        let cleaned = input
            .replacingOccurrences(of: "[\\s-]", with: "", options: .regularExpression)
            .uppercased()
        guard !cleaned.isEmpty else {
            throw KeyholeError.validation("Enter your \(kind.label).")
        }

        // Check the other kind first so the common mix-up gets a name.
        for other in [SecretKind.secretKey, .recoveryCode] where other != kind {
            if cleaned.hasPrefix(other.prefix) {
                throw KeyholeError.validation("That looks like your \(other.label), not your \(kind.label).")
            }
        }
        guard cleaned.hasPrefix(kind.prefix) else {
            throw KeyholeError.validation("A \(kind.label) starts with \(kind.prefix)-.")
        }

        let body = Array(cleaned.dropFirst(kind.prefix.count))
        guard body.count == encodedChars else {
            throw KeyholeError.validation(
                "A \(kind.label) has \(encodedChars) characters after the prefix; this one has \(body.count)."
            )
        }

        var acc = 0
        var bits = 0
        var bytes: [UInt8] = []
        bytes.reserveCapacity(secretKeyBytes)

        for char in body {
            let symbol = aliases[char] ?? char
            guard let value = values[symbol] else {
                throw KeyholeError.validation("\"\(char)\" is not a character a \(kind.label) can contain.")
            }
            acc = (acc << 5) | value
            bits += 5
            while bits >= 8 && bytes.count < secretKeyBytes {
                bits -= 8
                bytes.append(UInt8((acc >> bits) & 0xff))
                acc &= (1 << bits) - 1
            }
        }

        let padBits = encodedChars * 5 - secretKeyBytes * 8 - checkBits
        let expectedCheck = (acc >> padBits) & ((1 << checkBits) - 1)
        let padding = acc & ((1 << padBits) - 1)

        guard padding == 0, expectedCheck == crc16(bytes) else {
            throw KeyholeError.validation("That \(kind.label) has a typo in it — check it against your Recovery Kit.")
        }

        return bytes
    }

    /// True when `input` parses cleanly. For live field validation, never for auth.
    public static func isWellFormedSecret(_ kind: SecretKind, _ input: String) -> Bool {
        (try? parseSecret(kind, input)) != nil
    }
}
