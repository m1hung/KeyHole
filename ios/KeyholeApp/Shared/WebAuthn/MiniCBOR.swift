import Foundation

/// Minimal CBOR encoder for WebAuthn attestation objects and COSE keys.
/// Only the encodings we need — no decoder, no full RFC 8949 surface.
enum MiniCBOR {
    static func encodeUnsigned(_ value: UInt64) -> [UInt8] {
        encodeMajor(0, value: value)
    }

    /// Encodes a negative integer (e.g. -7 for ES256).
    static func encodeNegative(_ value: Int) -> [UInt8] {
        precondition(value < 0)
        return encodeMajor(1, value: UInt64(-1 - value))
    }

    static func encodeBytes(_ data: Data) -> [UInt8] {
        var out = encodeMajor(2, value: UInt64(data.count))
        out.append(contentsOf: data)
        return out
    }

    static func encodeText(_ string: String) -> [UInt8] {
        let utf8 = Array(string.utf8)
        var out = encodeMajor(3, value: UInt64(utf8.count))
        out.append(contentsOf: utf8)
        return out
    }

    static func encodeEmptyMap() -> [UInt8] {
        [0xa0]
    }

    /// Ordered map with already-encoded key/value byte sequences.
    static func encodeMap(_ pairs: [(key: [UInt8], value: [UInt8])]) -> [UInt8] {
        var out = encodeMajor(5, value: UInt64(pairs.count))
        for pair in pairs {
            out.append(contentsOf: pair.key)
            out.append(contentsOf: pair.value)
        }
        return out
    }

    private static func encodeMajor(_ major: UInt8, value: UInt64) -> [UInt8] {
        let mt = major << 5
        if value < 24 {
            return [mt | UInt8(value)]
        }
        if value <= UInt64(UInt8.max) {
            return [mt | 24, UInt8(value)]
        }
        if value <= UInt64(UInt16.max) {
            return [mt | 25, UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
        }
        if value <= UInt64(UInt32.max) {
            return [
                mt | 26,
                UInt8((value >> 24) & 0xff),
                UInt8((value >> 16) & 0xff),
                UInt8((value >> 8) & 0xff),
                UInt8(value & 0xff),
            ]
        }
        return [
            mt | 27,
            UInt8((value >> 56) & 0xff),
            UInt8((value >> 48) & 0xff),
            UInt8((value >> 40) & 0xff),
            UInt8((value >> 32) & 0xff),
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff),
        ]
    }
}
