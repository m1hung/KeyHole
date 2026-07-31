/// Shared sealed-vault loader/saver for the AutoFill extension.
import Foundation
import KeyholeCore

enum VaultFileNames {
    static let vault = "keyhole-vault.keyhole.json"
    static let backup = "keyhole-vault.keyhole.json.bak"
}

enum VaultStoreLoadError: LocalizedError {
    case appGroupUnavailable
    case noVault

    var errorDescription: String? {
        switch self {
        case .appGroupUnavailable:
            return "AutoFill isn’t set up on this install. Open Keyhole and try again."
        case .noVault:
            return "No vault found. Open Keyhole once, then try again."
        }
    }
}

@MainActor
enum VaultStore {
    private static var directoryURL: URL? {
        AppGroup.containerURL?.appendingPathComponent("Keyhole", isDirectory: true)
    }

    private static var vaultURL: URL? {
        directoryURL?.appendingPathComponent(VaultFileNames.vault)
    }

    private static var backupURL: URL? {
        directoryURL?.appendingPathComponent(VaultFileNames.backup)
    }

    static func load() throws -> VaultFile {
        guard let vaultURL, let backupURL else {
            throw VaultStoreLoadError.appGroupUnavailable
        }
        if let file = read(vaultURL) { return file }
        if let file = read(backupURL) { return file }
        throw VaultStoreLoadError.noVault
    }

    static func save(_ file: VaultFile) throws {
        guard let directoryURL, let vaultURL, let backupURL else {
            throw VaultStoreLoadError.appGroupUnavailable
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(file)
        let fm = FileManager.default
        try fm.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        if fm.fileExists(atPath: vaultURL.path) {
            try? fm.removeItem(at: backupURL)
            try? fm.copyItem(at: vaultURL, to: backupURL)
        }
        let temp = directoryURL.appendingPathComponent(".\(VaultFileNames.vault).tmp-\(UUID().uuidString)")
        try data.write(to: temp, options: .atomic)
        if fm.fileExists(atPath: vaultURL.path) {
            try fm.removeItem(at: vaultURL)
        }
        try fm.moveItem(at: temp, to: vaultURL)
    }

    private static func read(_ url: URL) -> VaultFile? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            return try parseVaultFile(text)
        } catch {
            return nil
        }
    }
}
