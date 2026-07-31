import Foundation
import KeyholeCore
import Observation

public enum VaultStatus: String, Sendable {
    case loading
    case noVault = "no-vault"
    case locked
    case unlocked
    case damaged
}

@MainActor
@Observable
public final class AppVaultSession {
    public var status: VaultStatus = .loading
    public var data: VaultData?
    public var errorMessage: String?
    public var busy = false
    public var secondsUntilLock: Int?

    /// Vault format when a newer Keyhole wrote this vault, else nil.
    ///
    /// Derived from `data` rather than tracked separately: `migrateVaultData` leaves
    /// a newer payload's version in place, so this cannot drift out of step the way
    /// a stored copy set at each unlock could.
    public var foreignSchemaVersion: Int? {
        guard let version = data?.schemaVersion, version > SCHEMA_VERSION else { return nil }
        return version
    }

    public private(set) var file: VaultFile?
    private var session: VaultSession?
    private var syncAuthSecretB64: String?
    private var lastActivity = Date()
    private var autoLockTimer: Timer?

    private let store: VaultStore
    public var syncConfig: SyncConfigPrefs?

    public init(store: VaultStore = .shared) {
        self.store = store
        self.syncConfig = SyncConfigPrefs.load()
    }

    public func bootstrap() {
        store.syncSharedVaultIfNeeded()
        switch store.loadResult() {
        case .missing:
            file = nil
            status = .noVault
        case .loaded(let vault):
            file = vault
            status = .locked
        case .damaged:
            file = nil
            status = .damaged
            errorMessage = "Your vault file can’t be read. Import a backup, or delete it and create a new vault."
        }
    }

    public var isUnlocked: Bool { status == .unlocked }

    public func clearError() { errorMessage = nil }

    public func registerActivity() {
        lastActivity = Date()
        refreshAutoLockCountdown()
    }

    public func createVault(masterPassword: String, preset: KdfPresetName = .interactive) async {
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try KeyholeCore.createVault(
                    masterPassword: masterPassword,
                    options: CreateVaultOptions(kdfPreset: preset)
                )
            }.value
            session = result.session
            file = result.file
            try store.save(result.file)
            data = result.session.data
            status = .unlocked
            if BiometricUnlockStore.isEnabled {
                do {
                    try BiometricUnlockStore.enable(storing: masterPassword)
                } catch {
                    BiometricUnlockStore.disable()
                }
            }
            registerActivity()
            startAutoLockTimer()
            await publishQuickTypeIdentities()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func unlock(masterPassword: String) async {
        busy = true
        errorMessage = nil
        defer { busy = false }
        guard let file else {
            status = store.vaultFileExists ? .damaged : .noVault
            return
        }
        do {
            var unlocked = try await Task.detached(priority: .userInitiated) {
                try unlockVault(file: file, masterPassword: masterPassword)
            }.value
            // Sweep expired trash here, not in unlockVault: core stays pure, and a
            // read that silently rewrites the vault would surprise every caller.
            let swept = purgeExpiredTrash(data: unlocked.data)
            if swept != unlocked.data {
                unlocked.data = swept
                let previous = file
                let saved = try await Task.detached(priority: .userInitiated) {
                    var session = unlocked
                    return try saveVault(session: &session, previous: previous)
                }.value
                try store.save(saved)
                self.file = saved
            }
            session = unlocked
            data = unlocked.data
            status = .unlocked
            if let cfg = syncConfig {
                syncAuthSecretB64 = try? await Task.detached(priority: .userInitiated) {
                    try KeyholeCrypto.deriveSyncAuthSecret(masterPassword: masterPassword, params: file.kdf)
                }.value
                _ = cfg
            }
            if BiometricUnlockStore.isEnabled {
                do {
                    try BiometricUnlockStore.enable(storing: masterPassword)
                } catch {
                    BiometricUnlockStore.disable()
                }
            }
            registerActivity()
            startAutoLockTimer()
            await publishQuickTypeIdentities()
        } catch {
            session = nil
            data = nil
            syncAuthSecretB64 = nil
            status = .locked
            errorMessage = error.localizedDescription
        }
    }

    /// Unlock via Face ID / Touch ID when biometric unlock is enabled.
    public func unlockWithBiometrics() async {
        errorMessage = nil
        do {
            let password = try await BiometricUnlockStore.unlockMasterPassword()
            await unlock(masterPassword: password)
        } catch {
            if case BiometricUnlockError.cancelled = error {
                errorMessage = nil
            } else {
                errorMessage = error.localizedDescription
            }
        }
    }

    public func lock() {
        session = nil
        data = nil
        syncAuthSecretB64 = nil
        secondsUntilLock = nil
        autoLockTimer?.invalidate()
        autoLockTimer = nil
        if file != nil {
            status = .locked
            return
        }
        switch store.loadResult() {
        case .missing:
            status = .noVault
        case .loaded(let vault):
            file = vault
            status = .locked
        case .damaged:
            status = .damaged
        }
    }

    /// Fingerprint of login usernames/URLs/passkeys for QuickType republish decisions.
    private func loginIdentityFingerprint(_ data: VaultData) -> String {
        liveEntries(data)
            .filter { $0.kind == .login || !$0.passkeys.isEmpty }
            .map {
                let pks = $0.passkeys.map(\.credentialIdB64).sorted().joined(separator: ",")
                return "\($0.id)|\($0.username)|\($0.urls.joined(separator: ","))|\(pks)"
            }
            .sorted()
            .joined(separator: "\n")
    }

    public func mutate(_ recipe: (VaultData) throws -> VaultData) async {
        guard var sess = session, let previous = file else {
            errorMessage = KeyholeError.vaultIsLocked.localizedDescription
            return
        }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            let beforeIds = loginIdentityFingerprint(sess.data)
            sess.data = try recipe(sess.data)
            let afterIds = loginIdentityFingerprint(sess.data)
            let saved = try await Task.detached(priority: .userInitiated) {
                var session = sess
                return try saveVault(session: &session, previous: previous)
            }.value
            try store.save(saved)
            session = sess
            file = saved
            data = sess.data
            registerActivity()
            if beforeIds != afterIds {
                await publishQuickTypeIdentities()
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func changeMasterPassword(current: String, next: String) async {
        guard let file else { return }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try KeyholeCore.changeMasterPassword(
                    file: file,
                    currentPassword: current,
                    newPassword: next
                )
            }.value
            session = result.session
            self.file = result.file
            try store.save(result.file)
            data = result.session.data
            syncAuthSecretB64 = nil
            if BiometricUnlockStore.isEnabled {
                do {
                    try BiometricUnlockStore.updateStoredPassword(next)
                } catch {
                    BiometricUnlockStore.disable()
                    errorMessage = "Password changed, but Face ID needs to be turned on again in Settings."
                }
            }
            registerActivity()
            await publishQuickTypeIdentities()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func importVault(_ imported: VaultFile) async {
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            try store.save(imported)
            file = imported
            BiometricUnlockStore.disable()
            await QuickTypeCredentialStore.clear()
            lock()
            status = .locked
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func exportVault() -> VaultFile? { file }

    public func deleteVault() async {
        busy = true
        defer { busy = false }
        do {
            try store.clear()
            session = nil
            file = nil
            data = nil
            syncAuthSecretB64 = nil
            BiometricUnlockStore.disable()
            await QuickTypeCredentialStore.clear()
            status = .noVault
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    public func getSyncAuthSecret() -> String? { syncAuthSecretB64 }

    public func setSyncAuthSecret(_ secret: String?) {
        syncAuthSecretB64 = secret
    }

    public func ensureSyncAuth(masterPassword: String) async throws -> String {
        if let existing = syncAuthSecretB64 { return existing }
        guard let file else { throw KeyholeError.vaultIsLocked }
        let secret = try await Task.detached(priority: .userInitiated) {
            try KeyholeCrypto.deriveSyncAuthSecret(masterPassword: masterPassword, params: file.kdf)
        }.value
        syncAuthSecretB64 = secret
        return secret
    }

    public func applySynced(file: VaultFile, session: VaultSession) async throws {
        try store.save(file)
        self.file = file
        self.session = session
        self.data = session.data
        registerActivity()
        await publishQuickTypeIdentities()
    }

    public func syncNow(
        baseUrl: String,
        accountId: String,
        syncAuthSecretB64: String? = nil,
        masterPassword: String?
    ) async throws -> String {
        guard let sess = session, let localFile = file else {
            throw KeyholeError.vaultIsLocked
        }

        // Auth secret must come from the *account's* KDF (prelogin), not necessarily
        // this device's local salt — same as desktop/extension.
        var secret = syncAuthSecretB64 ?? self.syncAuthSecretB64
        if let masterPassword, !masterPassword.isEmpty {
            let accountKdf = try await SyncClient.fetchPrelogin(baseUrl: baseUrl, accountId: accountId)
            secret = try await Task.detached(priority: .userInitiated) {
                try KeyholeCrypto.deriveSyncAuthSecret(masterPassword: masterPassword, params: accountKdf)
            }.value
            self.syncAuthSecretB64 = secret
        }
        guard let secret else {
            throw SyncClientError("Enter your master password once this session to enable sync.", status: 401)
        }

        let result = try await RunSync.performSync(
            baseUrl: baseUrl,
            accountId: accountId,
            syncAuthSecretB64: secret,
            masterPassword: masterPassword,
            localFile: localFile,
            session: sess
        )
        try store.save(result.file)
        file = result.file
        session = result.session
        data = result.session.data
        registerActivity()
        await publishQuickTypeIdentities()
        return result.message
    }

    public func adoptRemote(
        baseUrl: String,
        accountId: String,
        masterPassword: String
    ) async throws -> String {
        guard status == .unlocked else { throw KeyholeError.vaultIsLocked }
        let result = try await RunSync.adoptRemote(
            baseUrl: baseUrl,
            accountId: accountId,
            masterPassword: masterPassword
        )
        try store.save(result.file)
        file = result.file
        session = result.session
        data = result.session.data
        syncAuthSecretB64 = result.syncAuthSecretB64
        let cfg = SyncConfigPrefs(baseUrl: baseUrl, accountId: accountId)
        cfg.save()
        syncConfig = cfg
        registerActivity()
        await publishQuickTypeIdentities()
        return result.message
    }

    public func overwriteRemote(
        baseUrl: String,
        accountId: String,
        masterPassword: String
    ) async throws -> String {
        guard let localFile = file, status == .unlocked else { throw KeyholeError.vaultIsLocked }
        let result = try await RunSync.overwriteRemote(
            baseUrl: baseUrl,
            accountId: accountId,
            masterPassword: masterPassword,
            localFile: localFile
        )
        syncAuthSecretB64 = result.syncAuthSecretB64
        let cfg = SyncConfigPrefs(baseUrl: baseUrl, accountId: accountId)
        cfg.save()
        syncConfig = cfg
        registerActivity()
        return result.message
    }

    public func handleScenePhase(_ phase: ScenePhaseCompat) {
        guard status == .unlocked, let settings = data?.settings else { return }
        if phase == .background || phase == .inactive {
            if settings.lockOnHide {
                lock()
            }
        }
    }

    private func startAutoLockTimer() {
        autoLockTimer?.invalidate()
        autoLockTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.tickAutoLock()
            }
        }
    }

    private func tickAutoLock() {
        guard status == .unlocked, let minutes = data?.settings.autoLockMinutes, minutes > 0 else {
            secondsUntilLock = nil
            return
        }
        let limit = minutes * 60
        let elapsed = Date().timeIntervalSince(lastActivity)
        let remaining = Int(limit - elapsed)
        if remaining <= 0 {
            lock()
        } else {
            secondsUntilLock = remaining
        }
    }

    private func refreshAutoLockCountdown() {
        tickAutoLock()
    }

    /// Push username/site identities into the system QuickType store (no passwords).
    @discardableResult
    func publishQuickTypeIdentities() async -> QuickTypeCredentialStore.PublishResult {
        guard let data else {
            return QuickTypeCredentialStore.PublishResult(
                enabled: false,
                count: 0,
                errorMessage: "Unlock to refresh keyboard suggestions."
            )
        }
        return await QuickTypeCredentialStore.publish(from: data)
    }

    /// Status of AutoFill readiness (local only — not the sync server).
    public func autoFillSyncStatus() async -> String {
        store.syncSharedVaultIfNeeded()
        let shared = store.autoFillShareStatus()
        var lines: [String] = []
        if shared.appGroupAvailable {
            if shared.sharedVaultExists {
                lines.append("AutoFill is up to date.")
            } else if let file {
                do {
                    try store.save(file)
                    lines.append("AutoFill is up to date.")
                } catch {
                    lines.append("Couldn’t update AutoFill.")
                }
            } else {
                lines.append("No vault yet.")
            }
        } else {
            lines.append("AutoFill isn’t available on this install.")
        }

        if data != nil {
            let quick = await publishQuickTypeIdentities()
            if let err = quick.errorMessage {
                lines.append(err)
            } else {
                lines.append("\(quick.count) keyboard suggestion\(quick.count == 1 ? "" : "s").")
            }
        } else {
            lines.append("Unlock to refresh keyboard suggestions.")
        }
        return lines.joined(separator: " ")
    }
}

public enum ScenePhaseCompat {
    case active
    case inactive
    case background
}

public struct SyncConfigPrefs: Codable, Equatable, Sendable {
    public var baseUrl: String
    public var accountId: String

    public init(baseUrl: String, accountId: String) {
        self.baseUrl = baseUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .replacingOccurrences(of: "/+$", with: "", options: .regularExpression)
        self.accountId = accountId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static let key = "keyhole.sync.v1"

    public static func load() -> SyncConfigPrefs? {
        guard let data = UserDefaults.standard.data(forKey: key),
              let parsed = try? JSONDecoder().decode(SyncConfigPrefs.self, from: data),
              !parsed.baseUrl.isEmpty,
              !parsed.accountId.isEmpty
        else { return nil }
        return parsed
    }

    public func save() {
        if let data = try? JSONEncoder().encode(self) {
            UserDefaults.standard.set(data, forKey: Self.key)
        }
    }

    public static func clear() {
        UserDefaults.standard.removeObject(forKey: key)
    }
}
