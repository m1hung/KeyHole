/// Shared sealed-vault loader for the AutoFill extension.
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
            return """
            AutoFill cannot reach the shared vault (App Group missing). \
            In Xcode, enable App Groups on both KeyholeApp and KeyholeAutoFill \
            for group.app.keyhole.vault, rebuild, then open Keyhole once.
            """
        case .noVault:
            return """
            No vault found for AutoFill. Open the Keyhole app once so it can \
            publish the sealed vault into the shared App Group, then try again.
            """
        }
    }
}

@MainActor
enum VaultStore {
    static func load() throws -> VaultFile {
        guard let group = AppGroup.containerURL else {
            throw VaultStoreLoadError.appGroupUnavailable
        }
        let dir = group.appendingPathComponent("Keyhole", isDirectory: true)
        let vaultURL = dir.appendingPathComponent(VaultFileNames.vault)
        let backupURL = dir.appendingPathComponent(VaultFileNames.backup)

        if let file = read(vaultURL) { return file }
        if let file = read(backupURL) { return file }
        throw VaultStoreLoadError.noVault
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
