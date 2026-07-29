import Foundation

public enum EncodingUtil {
    public static func utf8ToBytes(_ text: String) -> [UInt8] {
        Array(text.utf8)
    }

    public static func bytesToUtf8(_ bytes: [UInt8]) -> String {
        String(decoding: bytes, as: UTF8.self)
    }

    public static func bytesToB64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
    }

    public static func b64ToBytes(_ b64: String) throws -> [UInt8] {
        guard let data = Data(base64Encoded: b64) else {
            throw KeyholeError.vaultFormat("Expected base64")
        }
        return Array(data)
    }

    public static func bytesToHex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    public static func timingSafeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[i] ^ b[i]
        }
        return diff == 0
    }
}
