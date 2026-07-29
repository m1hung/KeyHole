import Foundation
import KeyholeCore

public enum VaultFileNames {
    public static let vault = "keyhole-vault.keyhole.json"
    public static let backup = "keyhole-vault.keyhole.json.bak"
    public static let fileExtension = ".keyhole.json"
}

/// Atomic sealed-envelope persistence under Application Support.
/// Never writes master password, MK, VEK, or sync auth secrets.
@MainActor
public final class VaultStore {
    public static let shared = VaultStore()

    private let directory: URL
    private let vaultURL: URL
    private let backupURL: URL

    public init(directory: URL? = nil) {
        let dir: URL
        if let directory {
            dir = directory
        } else {
            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? FileManager.default.temporaryDirectory
            dir = base.appendingPathComponent("Keyhole", isDirectory: true)
        }
        self.directory = dir
        self.vaultURL = dir.appendingPathComponent(VaultFileNames.vault)
        self.backupURL = dir.appendingPathComponent(VaultFileNames.backup)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    public var vaultFileURL: URL { vaultURL }

    public func load() -> VaultFile? {
        guard FileManager.default.fileExists(atPath: vaultURL.path) else { return nil }
        do {
            let text = try String(contentsOf: vaultURL, encoding: .utf8)
            return try parseVaultFile(text)
        } catch {
            // Try backup
            if FileManager.default.fileExists(atPath: backupURL.path) {
                do {
                    let text = try String(contentsOf: backupURL, encoding: .utf8)
                    return try parseVaultFile(text)
                } catch {
                    return nil
                }
            }
            return nil
        }
    }

    public func save(_ file: VaultFile) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(file)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        if FileManager.default.fileExists(atPath: vaultURL.path) {
            try? FileManager.default.removeItem(at: backupURL)
            try? FileManager.default.copyItem(at: vaultURL, to: backupURL)
        }

        let temp = directory.appendingPathComponent(".\(VaultFileNames.vault).tmp")
        try data.write(to: temp, options: .atomic)
        if FileManager.default.fileExists(atPath: vaultURL.path) {
            try FileManager.default.removeItem(at: vaultURL)
        }
        try FileManager.default.moveItem(at: temp, to: vaultURL)
    }

    public func clear() throws {
        try? FileManager.default.removeItem(at: vaultURL)
        try? FileManager.default.removeItem(at: backupURL)
    }

    public func exportJSON(_ file: VaultFile) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(file)
    }

    public func importJSON(_ data: Data) throws -> VaultFile {
        guard let text = String(data: data, encoding: .utf8) else {
            throw KeyholeError.vaultFormat("Not a valid Keyhole vault file: invalid UTF-8")
        }
        return try parseVaultFile(text)
    }
}
