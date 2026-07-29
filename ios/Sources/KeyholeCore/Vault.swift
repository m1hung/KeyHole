import Foundation

public let MIN_MASTER_PASSWORD_LENGTH = 12

public let DEFAULT_SETTINGS = Settings(
    autoLockMinutes: 15,
    clipboardClearSeconds: 30,
    generator: DEFAULT_GENERATOR_OPTIONS,
    theme: .system,
    lockOnHide: false
)

public struct CreateVaultOptions: Sendable {
    public var kdfPreset: KdfPresetName
    public var initialData: VaultData?

    public init(kdfPreset: KdfPresetName = .interactive, initialData: VaultData? = nil) {
        self.kdfPreset = kdfPreset
        self.initialData = initialData
    }
}

public struct EntryInput: Sendable {
    public var title: String
    public var kind: EntryKind?
    public var username: String?
    public var password: String?
    public var urls: [String]?
    public var notes: String?
    public var tags: [String]?
    public var folderId: String?
    public var totpSecret: String?

    public init(
        title: String,
        kind: EntryKind? = nil,
        username: String? = nil,
        password: String? = nil,
        urls: [String]? = nil,
        notes: String? = nil,
        tags: [String]? = nil,
        folderId: String? = nil,
        totpSecret: String? = nil
    ) {
        self.title = title
        self.kind = kind
        self.username = username
        self.password = password
        self.urls = urls
        self.notes = notes
        self.tags = tags
        self.folderId = folderId
        self.totpSecret = totpSecret
    }
}

enum VaultJSON {
    /// Compact JSON for vault payloads (property declaration order).
    static func stringifyPayload(_ data: VaultData) throws -> String {
        let e = JSONEncoder()
        let bytes = try e.encode(data)
        guard let s = String(data: bytes, encoding: .utf8) else {
            throw KeyholeError.vaultFormat("Failed to encode vault payload.")
        }
        return s
    }

    static func canonicalString<T: Encodable>(_ value: T) throws -> String {
        let e = JSONEncoder()
        let bytes = try e.encode(value)
        guard let s = String(data: bytes, encoding: .utf8) else {
            throw KeyholeError.validation("Failed to encode value for comparison.")
        }
        return s
    }
}

private func nowISO() -> String {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.string(from: Date())
}

public func assertMasterPasswordAcceptable(_ password: String) throws {
    if password.count < MIN_MASTER_PASSWORD_LENGTH {
        throw KeyholeError.validation("Master password must be at least \(MIN_MASTER_PASSWORD_LENGTH) characters.")
    }
}

public func emptyVaultData() -> VaultData {
    VaultData(
        schemaVersion: SCHEMA_VERSION,
        entries: [],
        folders: [],
        tombstones: [],
        settings: DEFAULT_SETTINGS,
        updatedAt: nowISO()
    )
}

public func createVault(
    masterPassword: String,
    options: CreateVaultOptions = CreateVaultOptions()
) throws -> (file: VaultFile, session: VaultSession) {
    try assertMasterPasswordAcceptable(masterPassword)

    let vaultId = KeyholeCrypto.randomUuid()
    let kdf = KeyholeCrypto.defaultKdfParams(preset: options.kdfPreset)
    let header = KeyholeCrypto.VaultHeader(vaultId: vaultId, formatVersion: FORMAT_VERSION, kdf: kdf)

    let masterKey = try KeyholeCrypto.deriveMasterKey(masterPassword: masterPassword, params: kdf)
    var vekBytes = KeyholeCrypto.generateVaultKeyBytes()
    defer { KeyholeCrypto.zeroize(&vekBytes) }

    let wrappedKey = try KeyholeCrypto.encrypt(
        key: masterKey,
        plaintext: vekBytes,
        aad: KeyholeCrypto.wrappedKeyAad(header)
    )
    let vaultKey = try KeyholeCrypto.importAesKey(vekBytes)

    let data = options.initialData ?? emptyVaultData()
    let payloadJSON = try VaultJSON.stringifyPayload(data)
    let payload = try KeyholeCrypto.encrypt(
        key: vaultKey,
        plaintext: EncodingUtil.utf8ToBytes(payloadJSON),
        aad: KeyholeCrypto.payloadAad(vaultId: vaultId, formatVersion: FORMAT_VERSION)
    )

    let timestamp = nowISO()
    let file = VaultFile(
        format: VAULT_FORMAT_ID,
        formatVersion: FORMAT_VERSION,
        vaultId: vaultId,
        createdAt: timestamp,
        updatedAt: timestamp,
        kdf: kdf,
        wrappedKey: wrappedKey,
        payload: payload
    )
    let session = VaultSession(
        vaultId: vaultId,
        key: vaultKey,
        data: data,
        unlockedAt: Date().timeIntervalSince1970 * 1000
    )
    return (file, session)
}

public func unlockVault(file input: Any, masterPassword: String) throws -> VaultSession {
    let parsed = try parseVaultFile(input)
    if parsed.formatVersion > FORMAT_VERSION {
        throw KeyholeError.unsupportedVersion(
            "This vault was written by a newer version of Keyhole (format \(parsed.formatVersion)). Please update."
        )
    }

    let header = KeyholeCrypto.VaultHeader(
        vaultId: parsed.vaultId,
        formatVersion: parsed.formatVersion,
        kdf: parsed.kdf
    )
    let masterKey = try KeyholeCrypto.deriveMasterKey(masterPassword: masterPassword, params: parsed.kdf)

    var vekBytes = try KeyholeCrypto.decrypt(
        key: masterKey,
        blob: parsed.wrappedKey,
        aad: KeyholeCrypto.wrappedKeyAad(header)
    )
    let vaultKey: SymmetricVaultKey
    do {
        vaultKey = try KeyholeCrypto.importAesKey(vekBytes)
    }
    KeyholeCrypto.zeroize(&vekBytes)

    var plaintext = try KeyholeCrypto.decrypt(
        key: vaultKey,
        blob: parsed.payload,
        aad: KeyholeCrypto.payloadAad(vaultId: parsed.vaultId, formatVersion: parsed.formatVersion)
    )
    defer { KeyholeCrypto.zeroize(&plaintext) }

    let json = EncodingUtil.bytesToUtf8(plaintext)
    let data: VaultData
    do {
        data = try parseVaultData(json)
    } catch {
        if error is DecodingError {
            throw KeyholeError.vaultFormat("Vault payload is not valid JSON.")
        }
        throw error
    }

    return VaultSession(
        vaultId: parsed.vaultId,
        key: vaultKey,
        data: try migrateVaultData(data),
        unlockedAt: Date().timeIntervalSince1970 * 1000
    )
}

public func openVaultWithKey(file input: Any, vaultKey: SymmetricVaultKey) throws -> VaultData {
    let parsed = try parseVaultFile(input)
    if parsed.formatVersion > FORMAT_VERSION {
        throw KeyholeError.unsupportedVersion(
            "This vault was written by a newer version of Keyhole (format \(parsed.formatVersion)). Please update."
        )
    }
    var plaintext = try KeyholeCrypto.decrypt(
        key: vaultKey,
        blob: parsed.payload,
        aad: KeyholeCrypto.payloadAad(vaultId: parsed.vaultId, formatVersion: parsed.formatVersion)
    )
    defer { KeyholeCrypto.zeroize(&plaintext) }
    do {
        return try migrateVaultData(try parseVaultData(EncodingUtil.bytesToUtf8(plaintext)))
    } catch {
        if error is DecodingError {
            throw KeyholeError.vaultFormat("Vault payload is not valid JSON.")
        }
        throw error
    }
}

public func saveVault(session: inout VaultSession, previous: VaultFile) throws -> VaultFile {
    guard previous.vaultId == session.vaultId else {
        throw KeyholeError.validation("Session does not belong to this vault file.")
    }
    var data = session.data
    data.updatedAt = nowISO()
    let payload = try KeyholeCrypto.encrypt(
        key: session.key,
        plaintext: EncodingUtil.utf8ToBytes(try VaultJSON.stringifyPayload(data)),
        aad: KeyholeCrypto.payloadAad(vaultId: previous.vaultId, formatVersion: previous.formatVersion)
    )
    session.data = data
    var next = previous
    next.payload = payload
    next.updatedAt = data.updatedAt
    return next
}

public func changeMasterPassword(
    file: VaultFile,
    currentPassword: String,
    newPassword: String,
    kdfPreset: KdfPresetName = .interactive
) throws -> (file: VaultFile, session: VaultSession) {
    try assertMasterPasswordAcceptable(newPassword)
    let current = try unlockVault(file: file, masterPassword: currentPassword)

    let kdf = KeyholeCrypto.defaultKdfParams(preset: kdfPreset)
    let header = KeyholeCrypto.VaultHeader(vaultId: file.vaultId, formatVersion: FORMAT_VERSION, kdf: kdf)
    let newMasterKey = try KeyholeCrypto.deriveMasterKey(masterPassword: newPassword, params: kdf)

    var vekBytes = KeyholeCrypto.generateVaultKeyBytes()
    defer { KeyholeCrypto.zeroize(&vekBytes) }

    let wrappedKey = try KeyholeCrypto.encrypt(
        key: newMasterKey,
        plaintext: vekBytes,
        aad: KeyholeCrypto.wrappedKeyAad(header)
    )
    let newVaultKey = try KeyholeCrypto.importAesKey(vekBytes)

    var data = current.data
    data.updatedAt = nowISO()
    let payload = try KeyholeCrypto.encrypt(
        key: newVaultKey,
        plaintext: EncodingUtil.utf8ToBytes(try VaultJSON.stringifyPayload(data)),
        aad: KeyholeCrypto.payloadAad(vaultId: file.vaultId, formatVersion: FORMAT_VERSION)
    )

    var next = file
    next.formatVersion = FORMAT_VERSION
    next.kdf = kdf
    next.wrappedKey = wrappedKey
    next.payload = payload
    next.updatedAt = data.updatedAt

    return (
        next,
        VaultSession(
            vaultId: file.vaultId,
            key: newVaultKey,
            data: data,
            unlockedAt: Date().timeIntervalSince1970 * 1000
        )
    )
}

public func lockSession(_ session: inout VaultSession) {
    session.data = emptyVaultData()
    session.unlockedAt = 0
}

public func migrateVaultData(_ data: VaultData) throws -> VaultData {
    if data.schemaVersion > SCHEMA_VERSION {
        throw KeyholeError.unsupportedVersion(
            "Vault schema \(data.schemaVersion) is newer than this build supports."
        )
    }
    var out = data
    out.tombstones = data.tombstones
    out.schemaVersion = SCHEMA_VERSION
    return out
}

// MARK: - CRUD

public func createEntry(data: VaultData, input: EntryInput) throws -> (data: VaultData, entry: Entry) {
    if input.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        throw KeyholeError.validation("Entry title must not be empty.")
    }
    let timestamp = nowISO()
    let entry = Entry(
        id: KeyholeCrypto.randomUuid(),
        kind: input.kind ?? .login,
        title: input.title.trimmingCharacters(in: .whitespacesAndNewlines),
        username: input.username ?? "",
        password: input.password ?? "",
        urls: input.urls ?? [],
        notes: input.notes ?? "",
        tags: input.tags ?? [],
        folderId: input.folderId,
        totpSecret: input.totpSecret,
        createdAt: timestamp,
        updatedAt: timestamp,
        passwordUpdatedAt: timestamp
    )
    var next = data
    next.entries.append(entry)
    return (next, entry)
}

public struct UpdateEntryPatch: Sendable {
    public var title: String?
    public var kind: EntryKind?
    public var username: String?
    public var password: String?
    public var urls: [String]?
    public var notes: String?
    public var tags: [String]?
    public var folderId: String??
    public var totpSecret: String??

    public init(
        title: String? = nil,
        kind: EntryKind? = nil,
        username: String? = nil,
        password: String? = nil,
        urls: [String]? = nil,
        notes: String? = nil,
        tags: [String]? = nil,
        folderId: String?? = nil,
        totpSecret: String?? = nil
    ) {
        self.title = title
        self.kind = kind
        self.username = username
        self.password = password
        self.urls = urls
        self.notes = notes
        self.tags = tags
        self.folderId = folderId
        self.totpSecret = totpSecret
    }
}

public func updateEntry(data: VaultData, id: String, patch: UpdateEntryPatch) throws -> VaultData {
    guard let index = data.entries.firstIndex(where: { $0.id == id }) else {
        throw KeyholeError.validation("No entry with id \(id).")
    }
    var existing = data.entries[index]
    let passwordChanged = patch.password != nil && patch.password != existing.password

    if let kind = patch.kind { existing.kind = kind }
    if let title = patch.title {
        existing.title = title.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    if let username = patch.username { existing.username = username }
    if let password = patch.password { existing.password = password }
    if let urls = patch.urls { existing.urls = urls }
    if let notes = patch.notes { existing.notes = notes }
    if let tags = patch.tags { existing.tags = tags }
    if let folderId = patch.folderId { existing.folderId = folderId }
    if let totpSecret = patch.totpSecret { existing.totpSecret = totpSecret }
    existing.updatedAt = nowISO()
    if passwordChanged { existing.passwordUpdatedAt = nowISO() }
    if existing.title.isEmpty {
        throw KeyholeError.validation("Entry title must not be empty.")
    }

    var next = data
    next.entries[index] = existing
    return next
}

public func deleteEntry(data: VaultData, id: String) throws -> VaultData {
    guard data.entries.contains(where: { $0.id == id }) else {
        throw KeyholeError.validation("No entry with id \(id).")
    }
    var next = data
    next.entries = data.entries.filter { $0.id != id }
    next.tombstones = recordTombstone(
        existing: data.tombstones,
        next: Tombstone(id: id, kind: .entry, deletedAt: nowISO())
    )
    return next
}

private func recordTombstone(existing: [Tombstone], next: Tombstone) -> [Tombstone] {
    existing.filter { !($0.id == next.id && $0.kind == next.kind) } + [next]
}

public func getEntry(data: VaultData, id: String) -> Entry? {
    data.entries.first { $0.id == id }
}

public func createFolder(data: VaultData, name: String) throws -> (data: VaultData, folder: Folder) {
    let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty {
        throw KeyholeError.validation("Folder name must not be empty.")
    }
    let folder = Folder(id: KeyholeCrypto.randomUuid(), name: trimmed, createdAt: nowISO())
    var next = data
    next.folders.append(folder)
    return (next, folder)
}

public func deleteFolder(data: VaultData, id: String) -> VaultData {
    var next = data
    next.folders = data.folders.filter { $0.id != id }
    next.entries = data.entries.map { e in
        var copy = e
        if copy.folderId == id { copy.folderId = nil }
        return copy
    }
    next.tombstones = recordTombstone(
        existing: data.tombstones,
        next: Tombstone(id: id, kind: .folder, deletedAt: nowISO())
    )
    return next
}

public func updateSettings(data: VaultData, patch: Settings) -> VaultData {
    var next = data
    next.settings = patch
    return next
}

public func updateSettings(data: VaultData, mutate: (inout Settings) -> Void) -> VaultData {
    var next = data
    mutate(&next.settings)
    return next
}

public func searchEntries(data: VaultData, query: String) -> [Entry] {
    let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    let sorted = { (a: Entry, b: Entry) -> Bool in
        a.title.localizedCaseInsensitiveCompare(b.title) == .orderedAscending
    }
    if q.isEmpty {
        return data.entries.sorted(by: sorted)
    }
    return data.entries.filter { e in
        e.title.lowercased().contains(q)
            || e.username.lowercased().contains(q)
            || e.tags.contains(where: { $0.lowercased().contains(q) })
            || e.urls.contains(where: { $0.lowercased().contains(q) })
            || (e.kind == .note && e.notes.lowercased().contains(q))
    }.sorted(by: sorted)
}
