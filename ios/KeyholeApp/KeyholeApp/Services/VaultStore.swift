import Foundation
import KeyholeCore

public enum VaultFileNames {
    public static let vault = "keyhole-vault.keyhole.json"
    public static let backup = "keyhole-vault.keyhole.json.bak"
    public static let fileExtension = ".keyhole.json"
}

public enum VaultLoadResult: Sendable {
    case missing
    case loaded(VaultFile)
    /// Present on disk but unreadable (and backup also failed).
    case damaged
}

/// Atomic sealed-envelope persistence.
///
/// Writes prefer the App Group container so the AutoFill extension can read the
/// same sealed file. Falls back to Application Support when the group is not
/// provisioned, and mirrors into the group whenever it becomes available.
@MainActor
public final class VaultStore {
    public static let shared = VaultStore()

    private let directory: URL
    private let vaultURL: URL
    private let backupURL: URL
    private let legacyDirectory: URL

    public init(directory: URL? = nil) {
        let legacyBase = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let legacyDir = legacyBase.appendingPathComponent("Keyhole", isDirectory: true)
        self.legacyDirectory = legacyDir

        let dir: URL
        if let directory {
            dir = directory
        } else if let group = AppGroup.containerURL {
            dir = group.appendingPathComponent("Keyhole", isDirectory: true)
        } else {
            dir = legacyDir
        }
        self.directory = dir
        self.vaultURL = dir.appendingPathComponent(VaultFileNames.vault)
        self.backupURL = dir.appendingPathComponent(VaultFileNames.backup)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        syncSharedVaultIfNeeded()
    }

    public var vaultFileURL: URL { vaultURL }

    public var vaultFileExists: Bool {
        FileManager.default.fileExists(atPath: vaultURL.path)
            || FileManager.default.fileExists(atPath: backupURL.path)
    }

    /// Whether AutoFill can see this store (App Group is live).
    public var isSharedWithAutoFill: Bool {
        AppGroup.isAvailable && directory.path.hasPrefix(AppGroup.containerURL?.path ?? "\0")
    }

    /// Ensure the sealed vault lives in the App Group when possible.
    public func syncSharedVaultIfNeeded() {
        let fm = FileManager.default
        let legacyVault = legacyDirectory.appendingPathComponent(VaultFileNames.vault)
        let legacyBackup = legacyDirectory.appendingPathComponent(VaultFileNames.backup)

        guard let groupRoot = AppGroup.containerURL else { return }
        let sharedDir = groupRoot.appendingPathComponent("Keyhole", isDirectory: true)
        let sharedVault = sharedDir.appendingPathComponent(VaultFileNames.vault)
        let sharedBackup = sharedDir.appendingPathComponent(VaultFileNames.backup)
        try? fm.createDirectory(at: sharedDir, withIntermediateDirectories: true)

        if !fm.fileExists(atPath: sharedVault.path), fm.fileExists(atPath: legacyVault.path) {
            try? fm.copyItem(at: legacyVault, to: sharedVault)
            if fm.fileExists(atPath: legacyBackup.path), !fm.fileExists(atPath: sharedBackup.path) {
                try? fm.copyItem(at: legacyBackup, to: sharedBackup)
            }
        }

        if directory.path == legacyDirectory.path,
           fm.fileExists(atPath: vaultURL.path),
           !fm.fileExists(atPath: sharedVault.path) {
            try? fm.copyItem(at: vaultURL, to: sharedVault)
        }
    }

    public func load() -> VaultFile? {
        if case .loaded(let file) = loadResult() { return file }
        return nil
    }

    public func loadResult() -> VaultLoadResult {
        syncSharedVaultIfNeeded()

        let primaryExists = FileManager.default.fileExists(atPath: vaultURL.path)
        let backupExists = FileManager.default.fileExists(atPath: backupURL.path)

        if let file = try? readVaultThrowing(at: vaultURL) {
            return .loaded(file)
        }
        if let file = try? readVaultThrowing(at: backupURL) {
            // Repair primary from backup when possible.
            try? save(file)
            return .loaded(file)
        }

        let legacyVault = legacyDirectory.appendingPathComponent(VaultFileNames.vault)
        let legacyBackup = legacyDirectory.appendingPathComponent(VaultFileNames.backup)
        if vaultURL.path != legacyVault.path {
            if let file = try? readVaultThrowing(at: legacyVault) {
                try? save(file)
                return .loaded(file)
            }
            if let file = try? readVaultThrowing(at: legacyBackup) {
                try? save(file)
                return .loaded(file)
            }
            if FileManager.default.fileExists(atPath: legacyVault.path)
                || FileManager.default.fileExists(atPath: legacyBackup.path)
            {
                return .damaged
            }
        }

        if primaryExists || backupExists {
            return .damaged
        }
        return .missing
    }

    private func readVaultThrowing(at url: URL) throws -> VaultFile {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw KeyholeError.vaultFormat("Missing vault file.")
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        return try parseVaultFile(text)
    }

    public func save(_ file: VaultFile) throws {
        let encoder = JSONEncoder()
        // Compact on-disk form for production I/O; export still pretty-prints.
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(file)
        try writeAtomically(data, to: vaultURL, backup: backupURL, directory: directory)

        if let group = AppGroup.containerURL {
            let sharedDir = group.appendingPathComponent("Keyhole", isDirectory: true)
            let sharedVault = sharedDir.appendingPathComponent(VaultFileNames.vault)
            let sharedBackup = sharedDir.appendingPathComponent(VaultFileNames.backup)
            if sharedVault.path != vaultURL.path {
                try writeAtomically(data, to: sharedVault, backup: sharedBackup, directory: sharedDir)
            }
        }
        let legacyVault = legacyDirectory.appendingPathComponent(VaultFileNames.vault)
        let legacyBackup = legacyDirectory.appendingPathComponent(VaultFileNames.backup)
        if legacyVault.path != vaultURL.path {
            try? writeAtomically(data, to: legacyVault, backup: legacyBackup, directory: legacyDirectory)
        }
    }

    private func writeAtomically(_ data: Data, to vaultURL: URL, backup backupURL: URL, directory: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        if fm.fileExists(atPath: vaultURL.path) {
            try? fm.removeItem(at: backupURL)
            try? fm.copyItem(at: vaultURL, to: backupURL)
        }
        let temp = directory.appendingPathComponent(".\(VaultFileNames.vault).tmp-\(UUID().uuidString)")
        try data.write(to: temp, options: .atomic)
        if fm.fileExists(atPath: vaultURL.path) {
            try fm.removeItem(at: vaultURL)
        }
        try fm.moveItem(at: temp, to: vaultURL)
    }

    public func clear() throws {
        let fm = FileManager.default
        try? fm.removeItem(at: vaultURL)
        try? fm.removeItem(at: backupURL)
        if let group = AppGroup.containerURL {
            let sharedDir = group.appendingPathComponent("Keyhole", isDirectory: true)
            try? fm.removeItem(at: sharedDir.appendingPathComponent(VaultFileNames.vault))
            try? fm.removeItem(at: sharedDir.appendingPathComponent(VaultFileNames.backup))
        }
        try? fm.removeItem(at: legacyDirectory.appendingPathComponent(VaultFileNames.vault))
        try? fm.removeItem(at: legacyDirectory.appendingPathComponent(VaultFileNames.backup))
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

    public struct AutoFillShareStatus: Equatable {
        public var appGroupAvailable: Bool
        public var sharedVaultExists: Bool
        public var sharedVaultBytes: Int?
    }

    public func autoFillShareStatus() -> AutoFillShareStatus {
        guard let group = AppGroup.containerURL else {
            return AutoFillShareStatus(
                appGroupAvailable: false,
                sharedVaultExists: false,
                sharedVaultBytes: nil
            )
        }
        let sharedVault = group
            .appendingPathComponent("Keyhole", isDirectory: true)
            .appendingPathComponent(VaultFileNames.vault)
        var bytes: Int?
        if FileManager.default.fileExists(atPath: sharedVault.path),
           let attrs = try? FileManager.default.attributesOfItem(atPath: sharedVault.path),
           let size = attrs[.size] as? NSNumber
        {
            bytes = size.intValue
        }
        return AutoFillShareStatus(
            appGroupAvailable: true,
            sharedVaultExists: FileManager.default.fileExists(atPath: sharedVault.path),
            sharedVaultBytes: bytes
        )
    }
}
