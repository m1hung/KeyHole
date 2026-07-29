import Foundation

public enum KeyholeError: Error, LocalizedError, Sendable {
    case decryption(String)
    case vaultFormat(String)
    case unsupportedVersion(String)
    case vaultLocked(String)
    case validation(String)

    public var errorDescription: String? {
        switch self {
        case .decryption(let m),
             .vaultFormat(let m),
             .unsupportedVersion(let m),
             .vaultLocked(let m),
             .validation(let m):
            return m
        }
    }

    public static var decryptionFailed: KeyholeError {
        .decryption("Decryption failed: wrong master password or corrupted vault.")
    }

    public static var vaultIsLocked: KeyholeError {
        .vaultLocked("Vault is locked.")
    }
}
