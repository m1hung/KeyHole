import CryptoKit
import Foundation
import Security
import CArgon2

public enum CryptoConstants {
    public static let saltBytes = 16
    public static let ivBytes = 12
    public static let keyBytes = 32
    public static let tagBytes = 16
}

public enum KdfPresetName: String, Sendable {
    case interactive
    case hardened
}

public enum KdfPresets {
    public static let interactive = (memoryKiB: 64 * 1024, iterations: 3, parallelism: 1)
    public static let hardened = (memoryKiB: 256 * 1024, iterations: 4, parallelism: 1)
    public static let minimums = (memoryKiB: 16 * 1024, iterations: 2, parallelism: 1)
}

/// Thin wrapper around CryptoKit SymmetricKey for AES-GCM.
public struct SymmetricVaultKey: Sendable {
    public let symmetricKey: SymmetricKey

    public init(raw: [UInt8]) throws {
        guard raw.count == CryptoConstants.keyBytes else {
            throw KeyholeError.validation("Expected a \(CryptoConstants.keyBytes)-byte key, got \(raw.count).")
        }
        symmetricKey = SymmetricKey(data: Data(raw))
    }

    public init(symmetricKey: SymmetricKey) {
        self.symmetricKey = symmetricKey
    }
}

public enum KeyholeCrypto {
    private static let hkdfInfoSyncAuth = "keyhole/sync-auth/v1"

    // MARK: Randomness

    public static func randomBytes(_ length: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: length)
        out.withUnsafeMutableBytes { buf in
            guard let base = buf.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, length, base)
        }
        return out
    }

    public static func randomUuid() -> String {
        UUID().uuidString.lowercased()
    }

    public static func newSalt() -> [UInt8] {
        randomBytes(CryptoConstants.saltBytes)
    }

    public static func zeroize(_ buffers: inout [[UInt8]?]) {
        for i in buffers.indices {
            if var b = buffers[i] {
                for j in b.indices { b[j] = 0 }
                buffers[i] = b
            }
        }
    }

    public static func zeroize(_ buffer: inout [UInt8]) {
        for i in buffer.indices { buffer[i] = 0 }
    }

    // MARK: KDF

    public static func defaultKdfParams(preset: KdfPresetName = .interactive) -> KdfParams {
        let cost = preset == .interactive ? KdfPresets.interactive : KdfPresets.hardened
        return KdfParams(
            algorithm: "argon2id",
            memoryKiB: cost.memoryKiB,
            iterations: cost.iterations,
            parallelism: cost.parallelism,
            saltB64: EncodingUtil.bytesToB64(newSalt()),
            keyLength: CryptoConstants.keyBytes
        )
    }

    public static func assertKdfParamsAcceptable(_ params: KdfParams) throws {
        guard params.algorithm == "argon2id" else {
            throw KeyholeError.validation("Unsupported KDF: \(params.algorithm)")
        }
        guard params.keyLength == CryptoConstants.keyBytes else {
            throw KeyholeError.validation("Unsupported derived key length: \(params.keyLength).")
        }
        if params.memoryKiB < KdfPresets.minimums.memoryKiB
            || params.iterations < KdfPresets.minimums.iterations
            || params.parallelism < KdfPresets.minimums.parallelism
        {
            throw KeyholeError.validation("Vault KDF parameters are below the minimum accepted cost.")
        }
        let salt = try EncodingUtil.b64ToBytes(params.saltB64)
        guard salt.count >= CryptoConstants.saltBytes else {
            throw KeyholeError.validation("Vault salt is too short.")
        }
    }

    /// Run Argon2id. Caller MUST zeroize the result.
    public static func argon2Root(masterPassword: String, params: KdfParams) throws -> [UInt8] {
        try assertKdfParamsAcceptable(params)
        guard !masterPassword.isEmpty else {
            throw KeyholeError.validation("Master password must not be empty.")
        }

        var passwordBytes = EncodingUtil.utf8ToBytes(masterPassword)
        defer { zeroize(&passwordBytes) }
        let salt = try EncodingUtil.b64ToBytes(params.saltB64)

        var out = [UInt8](repeating: 0, count: params.keyLength)
        let rc = out.withUnsafeMutableBytes { outBuf -> Int32 in
            passwordBytes.withUnsafeBytes { pwBuf in
                salt.withUnsafeBytes { saltBuf -> Int32 in
                    argon2id_hash_raw(
                        UInt32(params.iterations),
                        UInt32(params.memoryKiB),
                        UInt32(params.parallelism),
                        pwBuf.baseAddress,
                        passwordBytes.count,
                        saltBuf.baseAddress,
                        salt.count,
                        outBuf.baseAddress,
                        params.keyLength
                    )
                }
            }
        }
        guard rc == 0 else {
            zeroize(&out)
            throw KeyholeError.validation("Argon2id failed with code \(rc).")
        }
        return out
    }

    public static func deriveMasterKey(masterPassword: String, params: KdfParams) throws -> SymmetricVaultKey {
        var derived = try argon2Root(masterPassword: masterPassword, params: params)
        defer { zeroize(&derived) }
        return try SymmetricVaultKey(raw: derived)
    }

    public static func deriveSyncAuthSecret(masterPassword: String, params: KdfParams) throws -> String {
        var root = try argon2Root(masterPassword: masterPassword, params: params)
        defer { zeroize(&root) }
        var secret = try hkdfSha256(
            root: root,
            salt: try EncodingUtil.b64ToBytes(params.saltB64),
            info: hkdfInfoSyncAuth,
            byteLength: CryptoConstants.keyBytes
        )
        defer { zeroize(&secret) }
        return EncodingUtil.bytesToB64(secret)
    }

    public static func deriveKeyMaterial(
        masterPassword: String,
        params: KdfParams
    ) throws -> (masterKey: SymmetricVaultKey, syncAuthSecretB64: String) {
        var root = try argon2Root(masterPassword: masterPassword, params: params)
        defer { zeroize(&root) }
        let masterKey = try SymmetricVaultKey(raw: root)
        var secret = try hkdfSha256(
            root: root,
            salt: try EncodingUtil.b64ToBytes(params.saltB64),
            info: hkdfInfoSyncAuth,
            byteLength: CryptoConstants.keyBytes
        )
        defer { zeroize(&secret) }
        return (masterKey, EncodingUtil.bytesToB64(secret))
    }

    public static func importAesKey(_ raw: [UInt8]) throws -> SymmetricVaultKey {
        try SymmetricVaultKey(raw: raw)
    }

    public static func generateVaultKeyBytes() -> [UInt8] {
        randomBytes(CryptoConstants.keyBytes)
    }

    // MARK: HKDF

    private static func hkdfSha256(root: [UInt8], salt: [UInt8], info: String, byteLength: Int) throws -> [UInt8] {
        let inputKey = SymmetricKey(data: Data(root))
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: Data(salt),
            info: Data(EncodingUtil.utf8ToBytes(info)),
            outputByteCount: byteLength
        )
        return derived.withUnsafeBytes { Array($0) }
    }

    // MARK: AEAD

    public static func encrypt(key: SymmetricVaultKey, plaintext: [UInt8], aad: [UInt8]) throws -> EncryptedBlob {
        let iv = randomBytes(CryptoConstants.ivBytes)
        let nonce = try AES.GCM.Nonce(data: Data(iv))
        let sealed = try AES.GCM.seal(
            Data(plaintext),
            using: key.symmetricKey,
            nonce: nonce,
            authenticating: Data(aad)
        )
        // WebCrypto layout: ciphertext || tag
        var ct = [UInt8](sealed.ciphertext)
        ct.append(contentsOf: sealed.tag)
        return EncryptedBlob(ivB64: EncodingUtil.bytesToB64(iv), ctB64: EncodingUtil.bytesToB64(ct))
    }

    public static func decrypt(key: SymmetricVaultKey, blob: EncryptedBlob, aad: [UInt8]) throws -> [UInt8] {
        do {
            let iv = try EncodingUtil.b64ToBytes(blob.ivB64)
            guard iv.count == CryptoConstants.ivBytes else { throw KeyholeError.decryptionFailed }
            let ct = try EncodingUtil.b64ToBytes(blob.ctB64)
            guard ct.count >= CryptoConstants.tagBytes else { throw KeyholeError.decryptionFailed }
            let tagStart = ct.count - CryptoConstants.tagBytes
            let ciphertext = Array(ct[..<tagStart])
            let tag = Array(ct[tagStart...])
            let sealed = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: Data(iv)),
                ciphertext: Data(ciphertext),
                tag: Data(tag)
            )
            let pt = try AES.GCM.open(sealed, using: key.symmetricKey, authenticating: Data(aad))
            return Array(pt)
        } catch is KeyholeError {
            throw KeyholeError.decryptionFailed
        } catch {
            throw KeyholeError.decryptionFailed
        }
    }

    // MARK: AAD

    public struct VaultHeader: Sendable {
        public var vaultId: String
        public var formatVersion: Int
        public var kdf: KdfParams

        public init(vaultId: String, formatVersion: Int, kdf: KdfParams) {
            self.vaultId = vaultId
            self.formatVersion = formatVersion
            self.kdf = kdf
        }
    }

    public static func wrappedKeyAad(_ header: VaultHeader) -> [UInt8] {
        let kdf = header.kdf
        let parts: [String] = [
            "keyhole.wrapkey.v1",
            header.vaultId,
            String(header.formatVersion),
            kdf.algorithm,
            String(kdf.memoryKiB),
            String(kdf.iterations),
            String(kdf.parallelism),
            String(kdf.keyLength),
            kdf.saltB64,
        ]
        return EncodingUtil.utf8ToBytes(parts.joined(separator: "|"))
    }

    public static func payloadAad(vaultId: String, formatVersion: Int) -> [UInt8] {
        EncodingUtil.utf8ToBytes(["keyhole.payload.v1", vaultId, String(formatVersion)].joined(separator: "|"))
    }
}
