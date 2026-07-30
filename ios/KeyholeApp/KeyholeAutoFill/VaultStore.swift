/// Shared store helpers for the AutoFill extension (mirrors the app VaultStore layout).
import Foundation
import KeyholeCore

enum VaultFileNames {
    static let vault = "keyhole-vault.keyhole.json"
    static let backup = "keyhole-vault.keyhole.json.bak"
}

enum AppGroup {
    static let id = "group.app.keyhole.vault"
}

@MainActor
enum VaultStore {
    static var shared: VaultStoreLoader { VaultStoreLoader() }
}

@MainActor
struct VaultStoreLoader {
    private var vaultURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppGroup.id)?
            .appendingPathComponent("Keyhole", isDirectory: true)
            .appendingPathComponent(VaultFileNames.vault)
    }

    func load() -> VaultFile? {
        guard let vaultURL, FileManager.default.fileExists(atPath: vaultURL.path) else { return nil }
        do {
            let text = try String(contentsOf: vaultURL, encoding: .utf8)
            return try parseVaultFile(text)
        } catch {
            return nil
        }
    }
}
