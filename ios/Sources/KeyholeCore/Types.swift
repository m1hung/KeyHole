import Foundation

/// Current version of the decrypted vault model. Bump when `VaultData` changes shape.
public let SCHEMA_VERSION = 5

/// Per-file ceiling for attachments inside the encrypted payload.
public let MAX_ATTACHMENT_BYTES = 1 * 1024 * 1024

/// Total attachment payload across the whole vault.
public let MAX_ATTACHMENTS_VAULT_BYTES = 5 * 1024 * 1024

/// Current version of the on-disk envelope. Bump when `VaultFile` changes shape.
/// Highest envelope version this build can *read*.
///
///  1 — master password alone.
///  2 — master password + a device-held Secret Key, with an optional Recovery Kit.
public let FORMAT_VERSION = 2

/// Envelope version `createVault` writes by default.
///
/// Deliberately trailing `FORMAT_VERSION`, and matching `DEFAULT_NEW_VAULT_FORMAT_VERSION`
/// in the TypeScript core: a format-2 vault is unopenable without its Secret Key, so
/// minting one from a surface that cannot yet store that key or show the Recovery Kit
/// would lock the user out of the vault they just created.
public let DEFAULT_NEW_VAULT_FORMAT_VERSION = 1

/// Envelope versions that bind derivation to a Secret Key.
public let SECRET_KEY_FORMAT_VERSION = 2

/// Magic string identifying a Keyhole vault envelope.
public let VAULT_FORMAT_ID = "keyhole.vault"

/// Superseded passwords kept per entry, newest first. Mirrors core/src/types.ts.
public let PASSWORD_HISTORY_LIMIT = 20

/// How long a soft-deleted entry stays restorable before it is purged for real.
public let TRASH_RETENTION_DAYS = 30

// MARK: - Decrypted model

public enum EntryKind: String, Codable, Sendable, Equatable {
    case login
    case note
}

/// A superseded password, kept so a failed rotation is recoverable.
/// Mirrors `PasswordHistoryEntry` in core/src/types.ts.
public struct PasswordHistoryEntry: Codable, Sendable, Equatable {
    public var password: String
    /// When it stopped being current. Also the merge key — see core/src/sync.ts.
    public var changedAt: String

    public init(password: String, changedAt: String) {
        self.password = password
        self.changedAt = changedAt
    }
}

/// Non-default TOTP parameters. `null` on the entry means the usual defaults
/// (6 digits, 30 s, SHA-1).
public struct TotpConfig: Codable, Sendable, Equatable {
    public var digits: Int
    public var periodSeconds: Int
    public var algorithm: TotpAlgorithm

    public init(digits: Int, periodSeconds: Int, algorithm: TotpAlgorithm) {
        self.digits = digits
        self.periodSeconds = periodSeconds
        self.algorithm = algorithm
    }
}

/// Free-form field on an entry. `secret: true` masks the value like a password.
public struct CustomField: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var label: String
    public var value: String
    public var secret: Bool

    public init(id: String, label: String, value: String, secret: Bool) {
        self.id = id
        self.label = label
        self.value = value
        self.secret = secret
    }
}

/// File stored inside the encrypted payload.
public struct Attachment: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var mimeType: String
    public var sizeBytes: Int
    public var dataB64: String

    public init(id: String, name: String, mimeType: String, sizeBytes: Int, dataB64: String) {
        self.id = id
        self.name = name
        self.mimeType = mimeType
        self.sizeBytes = sizeBytes
        self.dataB64 = dataB64
    }
}

/// WebAuthn passkey sealed with the entry (P-256 private key + RP metadata).
/// Created via AutoFill registration; used for assertion on matching sites.
public struct PasskeyRecord: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    /// Credential ID as standard Base64 (not Base64URL).
    public var credentialIdB64: String
    public var relyingPartyId: String
    public var relyingPartyName: String
    public var userName: String
    public var userDisplayName: String
    /// User handle as standard Base64.
    public var userHandleB64: String
    /// CryptoKit `P256.Signing.PrivateKey.rawRepresentation` as standard Base64.
    public var privateKeyB64: String
    public var signCount: UInt32
    public var createdAt: String
    public var lastUsedAt: String?

    public init(
        id: String,
        credentialIdB64: String,
        relyingPartyId: String,
        relyingPartyName: String,
        userName: String,
        userDisplayName: String,
        userHandleB64: String,
        privateKeyB64: String,
        signCount: UInt32 = 0,
        createdAt: String,
        lastUsedAt: String? = nil
    ) {
        self.id = id
        self.credentialIdB64 = credentialIdB64
        self.relyingPartyId = relyingPartyId
        self.relyingPartyName = relyingPartyName
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.userHandleB64 = userHandleB64
        self.privateKeyB64 = privateKeyB64
        self.signCount = signCount
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
    }
}

public struct Entry: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var kind: EntryKind
    public var title: String
    public var username: String
    public var password: String
    public var urls: [String]
    public var notes: String
    public var tags: [String]
    public var folderId: String?
    public var totpSecret: String?
    /// Digits / period / algorithm when they differ from the defaults. Null keeps
    /// existing entries generating the same codes they always have.
    public var totpConfig: TotpConfig?
    /// User-defined fields. Searchable by label, never by value.
    public var customFields: [CustomField]
    /// Files sealed with the entry.
    public var attachments: [Attachment]
    /// Passkeys for this login (schema 5). Empty on older entries.
    public var passkeys: [PasskeyRecord]
    public var createdAt: String
    public var updatedAt: String
    public var passwordUpdatedAt: String
    /// Previous passwords, newest first. Capped by the writer, not here.
    public var history: [PasswordHistoryEntry]
    /// When this entry was trashed, or nil while it is live.
    public var deletedAt: String?

    /// Fields written by a newer Keyhole, carried through untouched. See JSONValue.swift.
    public var extras: [String: JSONValue]

    /// Declared rather than synthesised so `knownKeys` below can enumerate it —
    /// anything not listed here is an unrecognised field to be preserved, so this
    /// list must stay in step with the stored properties above.
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case id, kind, title, username, password, urls, notes, tags
        case folderId, totpSecret, totpConfig, customFields, attachments, passkeys
        case createdAt, updatedAt, passwordUpdatedAt
        case history, deletedAt
    }

    public init(
        id: String,
        kind: EntryKind = .login,
        title: String,
        username: String = "",
        password: String = "",
        urls: [String] = [],
        notes: String = "",
        tags: [String] = [],
        folderId: String? = nil,
        totpSecret: String? = nil,
        totpConfig: TotpConfig? = nil,
        customFields: [CustomField] = [],
        attachments: [Attachment] = [],
        passkeys: [PasskeyRecord] = [],
        createdAt: String,
        updatedAt: String,
        passwordUpdatedAt: String,
        history: [PasswordHistoryEntry] = [],
        deletedAt: String? = nil,
        extras: [String: JSONValue] = [:]
    ) {
        self.id = id
        self.kind = kind
        self.title = title
        self.username = username
        self.password = password
        self.urls = urls
        self.notes = notes
        self.tags = tags
        self.folderId = folderId
        self.totpSecret = totpSecret
        self.totpConfig = totpConfig
        self.customFields = customFields
        self.attachments = attachments
        self.passkeys = passkeys
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.passwordUpdatedAt = passwordUpdatedAt
        self.history = history
        self.deletedAt = deletedAt
        self.extras = extras
    }

    private static let knownKeys: Set<String> = Set(CodingKeys.allCases.map { $0.stringValue })

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        kind = try c.decodeIfPresent(EntryKind.self, forKey: .kind) ?? .login
        title = try c.decode(String.self, forKey: .title)
        username = try c.decode(String.self, forKey: .username)
        password = try c.decode(String.self, forKey: .password)
        urls = try c.decode([String].self, forKey: .urls)
        notes = try c.decode(String.self, forKey: .notes)
        tags = try c.decode([String].self, forKey: .tags)
        folderId = try c.decodeIfPresent(String.self, forKey: .folderId)
        totpSecret = try c.decodeIfPresent(String.self, forKey: .totpSecret)
        totpConfig = try c.decodeIfPresent(TotpConfig.self, forKey: .totpConfig)
        customFields = try c.decodeIfPresent([CustomField].self, forKey: .customFields) ?? []
        attachments = try c.decodeIfPresent([Attachment].self, forKey: .attachments) ?? []
        passkeys = try c.decodeIfPresent([PasskeyRecord].self, forKey: .passkeys) ?? []
        createdAt = try c.decode(String.self, forKey: .createdAt)
        updatedAt = try c.decode(String.self, forKey: .updatedAt)
        passwordUpdatedAt = try c.decode(String.self, forKey: .passwordUpdatedAt)
        // Absent on a schema-2 vault, exactly like `kind` before them.
        history = try c.decodeIfPresent([PasswordHistoryEntry].self, forKey: .history) ?? []
        deletedAt = try c.decodeIfPresent(String.self, forKey: .deletedAt)
        extras = try decoder.unknownKeys(besides: Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: AnyCodingKey.self)
        try c.encode(id, forKey: AnyCodingKey(stringValue: CodingKeys.id.stringValue))
        try c.encode(kind, forKey: AnyCodingKey(stringValue: CodingKeys.kind.stringValue))
        try c.encode(title, forKey: AnyCodingKey(stringValue: CodingKeys.title.stringValue))
        try c.encode(username, forKey: AnyCodingKey(stringValue: CodingKeys.username.stringValue))
        try c.encode(password, forKey: AnyCodingKey(stringValue: CodingKeys.password.stringValue))
        try c.encode(urls, forKey: AnyCodingKey(stringValue: CodingKeys.urls.stringValue))
        try c.encode(notes, forKey: AnyCodingKey(stringValue: CodingKeys.notes.stringValue))
        try c.encode(tags, forKey: AnyCodingKey(stringValue: CodingKeys.tags.stringValue))
        // Explicit nulls, matching the TypeScript model where these are `T | null`
        // rather than optional keys.
        try c.encode(folderId, forKey: AnyCodingKey(stringValue: CodingKeys.folderId.stringValue))
        try c.encode(totpSecret, forKey: AnyCodingKey(stringValue: CodingKeys.totpSecret.stringValue))
        try c.encode(totpConfig, forKey: AnyCodingKey(stringValue: CodingKeys.totpConfig.stringValue))
        try c.encode(customFields, forKey: AnyCodingKey(stringValue: CodingKeys.customFields.stringValue))
        try c.encode(attachments, forKey: AnyCodingKey(stringValue: CodingKeys.attachments.stringValue))
        try c.encode(passkeys, forKey: AnyCodingKey(stringValue: CodingKeys.passkeys.stringValue))
        try c.encode(createdAt, forKey: AnyCodingKey(stringValue: CodingKeys.createdAt.stringValue))
        try c.encode(updatedAt, forKey: AnyCodingKey(stringValue: CodingKeys.updatedAt.stringValue))
        try c.encode(
            passwordUpdatedAt,
            forKey: AnyCodingKey(stringValue: CodingKeys.passwordUpdatedAt.stringValue)
        )
        try c.encode(history, forKey: AnyCodingKey(stringValue: CodingKeys.history.stringValue))
        try c.encode(deletedAt, forKey: AnyCodingKey(stringValue: CodingKeys.deletedAt.stringValue))
        try c.encodeExtras(extras)
    }
}

/// Folder, Tombstone, Settings and GeneratorOptions do NOT preserve unknown keys,
/// while `Entry` and `VaultData` do. The TypeScript schemas tolerate extra keys on
/// all of them, so this side is deliberately narrower: entries are where the data
/// lives, and hand-writing four more coders for fields nobody has added yet is cost
/// without benefit. If a future release adds a *setting*, extend this the same way
/// `Entry` was extended — otherwise saving from an older iPhone drops it.
public struct Folder: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var createdAt: String

    public init(id: String, name: String, createdAt: String) {
        self.id = id
        self.name = name
        self.createdAt = createdAt
    }
}

public struct Tombstone: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case entry
        case folder
    }

    public var id: String
    public var kind: Kind
    public var deletedAt: String

    public init(id: String, kind: Kind, deletedAt: String) {
        self.id = id
        self.kind = kind
        self.deletedAt = deletedAt
    }
}

public struct GeneratorOptions: Codable, Sendable, Equatable {
    public var length: Int
    public var lowercase: Bool
    public var uppercase: Bool
    public var digits: Bool
    public var symbols: Bool
    public var excludeAmbiguous: Bool

    public init(
        length: Int = 20,
        lowercase: Bool = true,
        uppercase: Bool = true,
        digits: Bool = true,
        symbols: Bool = true,
        excludeAmbiguous: Bool = false
    ) {
        self.length = length
        self.lowercase = lowercase
        self.uppercase = uppercase
        self.digits = digits
        self.symbols = symbols
        self.excludeAmbiguous = excludeAmbiguous
    }
}

public enum ThemePreference: String, Codable, Sendable {
    case light
    case dark
    case system
}

public struct Settings: Codable, Sendable, Equatable {
    public var autoLockMinutes: Double
    public var clipboardClearSeconds: Double
    public var generator: GeneratorOptions
    public var theme: ThemePreference
    public var lockOnHide: Bool
    /// Opt-in Have I Been Pwned range checks. Off by default.
    public var breachCheckEnabled: Bool

    private enum CodingKeys: String, CodingKey {
        case autoLockMinutes, clipboardClearSeconds, generator, theme, lockOnHide, breachCheckEnabled
    }

    public init(
        autoLockMinutes: Double = 15,
        clipboardClearSeconds: Double = 30,
        generator: GeneratorOptions = GeneratorOptions(),
        theme: ThemePreference = .system,
        lockOnHide: Bool = false,
        breachCheckEnabled: Bool = false
    ) {
        self.autoLockMinutes = autoLockMinutes
        self.clipboardClearSeconds = clipboardClearSeconds
        self.generator = generator
        self.theme = theme
        self.lockOnHide = lockOnHide
        self.breachCheckEnabled = breachCheckEnabled
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        autoLockMinutes = try c.decode(Double.self, forKey: .autoLockMinutes)
        clipboardClearSeconds = try c.decode(Double.self, forKey: .clipboardClearSeconds)
        generator = try c.decode(GeneratorOptions.self, forKey: .generator)
        theme = try c.decode(ThemePreference.self, forKey: .theme)
        lockOnHide = try c.decode(Bool.self, forKey: .lockOnHide)
        breachCheckEnabled = try c.decodeIfPresent(Bool.self, forKey: .breachCheckEnabled) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(autoLockMinutes, forKey: .autoLockMinutes)
        try c.encode(clipboardClearSeconds, forKey: .clipboardClearSeconds)
        try c.encode(generator, forKey: .generator)
        try c.encode(theme, forKey: .theme)
        try c.encode(lockOnHide, forKey: .lockOnHide)
        try c.encode(breachCheckEnabled, forKey: .breachCheckEnabled)
    }
}

public struct VaultData: Codable, Sendable, Equatable {
    public var schemaVersion: Int
    public var entries: [Entry]
    public var folders: [Folder]
    public var tombstones: [Tombstone]
    public var settings: Settings
    public var updatedAt: String

    /// Top-level fields written by a newer Keyhole, carried through untouched.
    public var extras: [String: JSONValue]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, entries, folders, tombstones, settings, updatedAt
    }

    public init(
        schemaVersion: Int = SCHEMA_VERSION,
        entries: [Entry] = [],
        folders: [Folder] = [],
        tombstones: [Tombstone] = [],
        settings: Settings = Settings(),
        updatedAt: String,
        extras: [String: JSONValue] = [:]
    ) {
        self.schemaVersion = schemaVersion
        self.entries = entries
        self.folders = folders
        self.tombstones = tombstones
        self.settings = settings
        self.updatedAt = updatedAt
        self.extras = extras
    }

    private static let knownKeys: Set<String> = Set(CodingKeys.allCases.map { $0.stringValue })

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decode(Int.self, forKey: .schemaVersion)
        entries = try c.decode([Entry].self, forKey: .entries)
        folders = try c.decode([Folder].self, forKey: .folders)
        tombstones = try c.decodeIfPresent([Tombstone].self, forKey: .tombstones) ?? []
        settings = try c.decode(Settings.self, forKey: .settings)
        updatedAt = try c.decode(String.self, forKey: .updatedAt)
        extras = try decoder.unknownKeys(besides: Self.knownKeys)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: AnyCodingKey.self)
        try c.encode(schemaVersion, forKey: AnyCodingKey(stringValue: CodingKeys.schemaVersion.stringValue))
        try c.encode(entries, forKey: AnyCodingKey(stringValue: CodingKeys.entries.stringValue))
        try c.encode(folders, forKey: AnyCodingKey(stringValue: CodingKeys.folders.stringValue))
        try c.encode(tombstones, forKey: AnyCodingKey(stringValue: CodingKeys.tombstones.stringValue))
        try c.encode(settings, forKey: AnyCodingKey(stringValue: CodingKeys.settings.stringValue))
        try c.encode(updatedAt, forKey: AnyCodingKey(stringValue: CodingKeys.updatedAt.stringValue))
        try c.encodeExtras(extras)
    }
}

// MARK: - Encrypted envelope

public struct KdfParams: Codable, Sendable, Equatable {
    public var algorithm: String
    public var memoryKiB: Int
    public var iterations: Int
    public var parallelism: Int
    public var saltB64: String
    public var keyLength: Int

    public init(
        algorithm: String = "argon2id",
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        saltB64: String,
        keyLength: Int
    ) {
        self.algorithm = algorithm
        self.memoryKiB = memoryKiB
        self.iterations = iterations
        self.parallelism = parallelism
        self.saltB64 = saltB64
        self.keyLength = keyLength
    }
}

/// AES-256-GCM output. `ctB64` is ciphertext with the 128-bit auth tag appended
/// (WebCrypto layout).
public struct EncryptedBlob: Codable, Sendable, Equatable {
    public var ivB64: String
    public var ctB64: String

    public init(ivB64: String, ctB64: String) {
        self.ivB64 = ivB64
        self.ctB64 = ctB64
    }
}

public struct VaultFile: Codable, Sendable, Equatable {
    public var format: String
    public var formatVersion: Int
    public var vaultId: String
    public var createdAt: String
    public var updatedAt: String
    public var kdf: KdfParams
    public var wrappedKey: EncryptedBlob
    public var payload: EncryptedBlob
    /// KDF parameters for the Recovery Code. Format 2+, present iff a Recovery Kit
    /// has been issued. Nil encodes as an absent key, matching the TypeScript core.
    public var recoveryKdf: KdfParams?
    /// The *same* vault encryption key, wrapped a second time under the Recovery Code.
    ///
    /// CRITICAL INVARIANT: it wraps the VEK, so anything that rotates the VEK must
    /// re-wrap or clear it. See `changeMasterPassword`.
    public var recoveryWrappedKey: EncryptedBlob?

    public init(
        format: String = VAULT_FORMAT_ID,
        formatVersion: Int = DEFAULT_NEW_VAULT_FORMAT_VERSION,
        vaultId: String,
        createdAt: String,
        updatedAt: String,
        kdf: KdfParams,
        wrappedKey: EncryptedBlob,
        payload: EncryptedBlob,
        recoveryKdf: KdfParams? = nil,
        recoveryWrappedKey: EncryptedBlob? = nil
    ) {
        self.format = format
        self.formatVersion = formatVersion
        self.vaultId = vaultId
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.kdf = kdf
        self.wrappedKey = wrappedKey
        self.payload = payload
        self.recoveryKdf = recoveryKdf
        self.recoveryWrappedKey = recoveryWrappedKey
    }
}

// MARK: - Session

/// Unlocked vault session. `key` is the VEK held only in memory.
public struct VaultSession: Sendable {
    public var vaultId: String
    public var key: SymmetricVaultKey
    public var data: VaultData
    public var unlockedAt: TimeInterval

    /// Schema version of the payload when a newer Keyhole wrote it, else nil. The
    /// vault is usable and unknown fields survive a save, but this build will not
    /// show or maintain them — so the UI should say so.
    public var foreignSchemaVersion: Int?

    public init(
        vaultId: String,
        key: SymmetricVaultKey,
        data: VaultData,
        unlockedAt: TimeInterval,
        foreignSchemaVersion: Int? = nil
    ) {
        self.vaultId = vaultId
        self.key = key
        self.data = data
        self.unlockedAt = unlockedAt
        self.foreignSchemaVersion = foreignSchemaVersion
    }
}

public enum LockState: String, Sendable {
    case locked
    case unlocked
    case noVault = "no-vault"
}
