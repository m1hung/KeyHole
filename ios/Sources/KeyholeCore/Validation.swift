import Foundation

enum Validation {
    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static let isoFormatterNoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    static func isIsoDate(_ s: String) -> Bool {
        isoFormatter.date(from: s) != nil || isoFormatterNoFrac.date(from: s) != nil || Date.parseLoose(s) != nil
    }

    static func isBase64(_ s: String) -> Bool {
        let pattern = #"^[A-Za-z0-9+/]*={0,2}$"#
        return s.range(of: pattern, options: .regularExpression) != nil
    }

    static func isUuid(_ s: String) -> Bool {
        UUID(uuidString: s) != nil
    }

    public static func parseVaultFile(_ input: Any) throws -> VaultFile {
        let data: Data
        if let d = input as? Data {
            data = d
        } else if let s = input as? String {
            guard let d = s.data(using: .utf8) else {
                throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: invalid UTF-8")
            }
            data = d
        } else if let dict = input as? [String: Any] {
            data = try JSONSerialization.data(withJSONObject: dict)
        } else if let file = input as? VaultFile {
            try validateVaultFile(file)
            return file
        } else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: unexpected type")
        }

        do {
            let file = try JSONDecoder().decode(VaultFile.self, from: data)
            try validateVaultFile(file)
            return file
        } catch let err as KeyholeError {
            throw err
        } catch {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: \(error.localizedDescription)")
        }
    }

    public static func parseVaultFileJSON(_ text: String) throws -> VaultFile {
        try parseVaultFile(text)
    }

    public static func parseVaultData(_ input: Any) throws -> VaultData {
        let data: Data
        if let d = input as? Data {
            data = d
        } else if let s = input as? String {
            guard let d = s.data(using: .utf8) else {
                throw KeyholeError.vaultFormat("Vault contents failed validation")
            }
            data = d
        } else if let dict = input as? [String: Any] {
            data = try JSONSerialization.data(withJSONObject: dict)
        } else if let vd = input as? VaultData {
            return vd
        } else {
            throw KeyholeError.vaultFormat("Vault contents failed validation at \"<root>\"")
        }

        do {
            var decoded = try JSONDecoder().decode(VaultData.self, from: data)
            try validateVaultData(&decoded)
            return decoded
        } catch let err as KeyholeError {
            throw err
        } catch {
            throw KeyholeError.vaultFormat("Vault contents failed validation: \(error.localizedDescription)")
        }
    }

    private static func validateVaultFile(_ file: VaultFile) throws {
        guard file.format == VAULT_FORMAT_ID else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad format id")
        }
        guard file.formatVersion >= 1 else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad formatVersion")
        }
        guard isUuid(file.vaultId) else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad vaultId")
        }
        guard isIsoDate(file.createdAt), isIsoDate(file.updatedAt) else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad timestamps")
        }
        try validateKdf(file.kdf)
        try validateBlob(file.wrappedKey)
        try validateBlob(file.payload)
        try assertEnvelopeShape(file)
    }

    /// Cross-field envelope rules, mirroring `assertEnvelopeShape` in the TypeScript
    /// core.
    ///
    /// Runs on parse so every reader gets them: a half-written Recovery Kit must be
    /// caught here rather than surfacing later as an unexplained decryption failure
    /// during recovery, which is the worst possible moment to discover it.
    public static func assertEnvelopeShape(_ file: VaultFile) throws {
        let hasKdf = file.recoveryKdf != nil
        let hasBlob = file.recoveryWrappedKey != nil

        guard hasKdf == hasBlob else {
            throw KeyholeError.vaultFormat(
                "Vault has an incomplete Recovery Kit: recoveryKdf and recoveryWrappedKey must both be present or both absent."
            )
        }
        if file.formatVersion < 2 && hasKdf {
            throw KeyholeError.vaultFormat("A format-\(file.formatVersion) vault cannot carry a Recovery Kit.")
        }
        if let recoveryKdf = file.recoveryKdf {
            try validateKdf(recoveryKdf)
        }
        if let recoveryWrappedKey = file.recoveryWrappedKey {
            try validateBlob(recoveryWrappedKey)
        }
    }

    private static func validateKdf(_ kdf: KdfParams) throws {
        guard kdf.algorithm == "argon2id" else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad KDF algorithm")
        }
        guard kdf.memoryKiB >= 1024, kdf.memoryKiB <= (1 << 21) else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad memoryKiB")
        }
        guard kdf.iterations >= 1, kdf.iterations <= 64 else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad iterations")
        }
        guard kdf.parallelism >= 1, kdf.parallelism <= 16 else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad parallelism")
        }
        guard isBase64(kdf.saltB64), kdf.saltB64.count >= 16 else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad salt")
        }
        guard kdf.keyLength == 32 else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad keyLength")
        }
    }

    private static func validateBlob(_ blob: EncryptedBlob) throws {
        guard isBase64(blob.ivB64), !blob.ivB64.isEmpty,
              isBase64(blob.ctB64), !blob.ctB64.isEmpty
        else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: bad encrypted blob")
        }
    }

    private static func validateVaultData(_ data: inout VaultData) throws {
        guard data.schemaVersion >= 1 else {
            throw KeyholeError.vaultFormat("Vault contents failed validation at \"schemaVersion\"")
        }
        guard isIsoDate(data.updatedAt) else {
            throw KeyholeError.vaultFormat("Vault contents failed validation at \"updatedAt\"")
        }
        for entry in data.entries {
            guard isUuid(entry.id) else {
                throw KeyholeError.vaultFormat("Vault contents failed validation at \"entries.id\"")
            }
        }
    }
}

private extension Date {
    static func parseLoose(_ s: String) -> Date? {
        // Accept JS-style ISO strings that Date.parse would accept.
        let f1 = ISO8601DateFormatter()
        f1.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f1.date(from: s) { return d }
        let f2 = ISO8601DateFormatter()
        f2.formatOptions = [.withInternetDateTime]
        return f2.date(from: s)
    }
}

/// Public wrappers matching `@keyhole/core` names.
public func parseVaultFile(_ input: Any) throws -> VaultFile {
    try Validation.parseVaultFile(input)
}

public func parseVaultData(_ input: Any) throws -> VaultData {
    try Validation.parseVaultData(input)
}
