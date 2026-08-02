import Foundation

public let MIN_MASTER_PASSWORD_LENGTH = 12

public let DEFAULT_SETTINGS = Settings(
    autoLockMinutes: 15,
    clipboardClearSeconds: 30,
    generator: DEFAULT_GENERATOR_OPTIONS,
    theme: .system,
    lockOnHide: false,
    breachCheckEnabled: false
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
    public var totpConfig: TotpConfig?
    public var customFields: [CustomField]?
    public var attachments: [Attachment]?

    public init(
        title: String,
        kind: EntryKind? = nil,
        username: String? = nil,
        password: String? = nil,
        urls: [String]? = nil,
        notes: String? = nil,
        tags: [String]? = nil,
        folderId: String? = nil,
        totpSecret: String? = nil,
        totpConfig: TotpConfig? = nil,
        customFields: [CustomField]? = nil,
        attachments: [Attachment]? = nil
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
        self.totpConfig = totpConfig
        self.customFields = customFields
        self.attachments = attachments
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

public func nowISO() -> String {
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
    let formatVersion = DEFAULT_NEW_VAULT_FORMAT_VERSION
    let header = KeyholeCrypto.VaultHeader(vaultId: vaultId, formatVersion: formatVersion, kdf: kdf)

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
        aad: KeyholeCrypto.payloadAad(vaultId: vaultId, formatVersion: formatVersion)
    )

    let timestamp = nowISO()
    let file = VaultFile(
        format: VAULT_FORMAT_ID,
        formatVersion: formatVersion,
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

/// The two halves of a printed Recovery Kit.
///
/// Returned exactly once, at the moment they are minted, and never recoverable from
/// the envelope afterwards. A caller that drops this has thrown away the user's only
/// recovery path — surfaces must render it before persisting anything.
public struct RecoveryKit: Sendable, Equatable {
    /// Formatted Secret Key. Stored on each device *and* printed.
    public let secretKey: String
    /// Formatted Recovery Code. Printed only — Keyhole never stores this anywhere.
    public let recoveryCode: String

    public init(secretKey: String, recoveryCode: String) {
        self.secretKey = secretKey
        self.recoveryCode = recoveryCode
    }
}

/// True when this envelope cannot be unlocked without a Secret Key.
public func vaultRequiresSecretKey(_ file: VaultFile) -> Bool {
    file.formatVersion >= SECRET_KEY_FORMAT_VERSION
}

/// True when a Recovery Kit was issued for this envelope and can still open it.
public func vaultHasRecoveryKit(_ file: VaultFile) -> Bool {
    file.recoveryWrappedKey != nil
}

/// Wrap the VEK a second time under a Recovery Code. See the TypeScript original for
/// why Argon2id is used over a uniformly random 128-bit code.
private func wrapForRecovery(
    vekBytes: [UInt8],
    recoveryCodeBytes: [UInt8],
    vaultId: String,
    formatVersion: Int,
    kdfPreset: KdfPresetName
) throws -> (recoveryKdf: KdfParams, recoveryWrappedKey: EncryptedBlob) {
    let recoveryKdf = KeyholeCrypto.defaultKdfParams(preset: kdfPreset)
    let recoveryKey = try KeyholeCrypto.deriveMasterKey(
        masterPassword: try SecretKeyCoding.formatSecret(.recoveryCode, recoveryCodeBytes),
        params: recoveryKdf
    )
    let blob = try KeyholeCrypto.encrypt(
        key: recoveryKey,
        plaintext: vekBytes,
        aad: KeyholeCrypto.recoveryAad(vaultId: vaultId, formatVersion: formatVersion, recoveryKdf: recoveryKdf)
    )
    return (recoveryKdf, blob)
}

/// Create a format-2 vault: bound to a fresh Secret Key, carrying a Recovery Kit.
///
/// Separate from `createVault` rather than a flag on it, so the obligation is in the
/// type: you cannot mint a Secret Key-bound vault without receiving the kit that is
/// the only way back into it. (The TypeScript core folds this into `createVault` with
/// a nullable `kit`; the ports pin the *format*, not the ergonomics.)
public func createVaultWithRecoveryKit(
    masterPassword: String,
    options: CreateVaultOptions = CreateVaultOptions()
) throws -> (file: VaultFile, session: VaultSession, kit: RecoveryKit) {
    try assertMasterPasswordAcceptable(masterPassword)

    let vaultId = KeyholeCrypto.randomUuid()
    let kdf = KeyholeCrypto.defaultKdfParams(preset: options.kdfPreset)
    let formatVersion = SECRET_KEY_FORMAT_VERSION
    let header = KeyholeCrypto.VaultHeader(vaultId: vaultId, formatVersion: formatVersion, kdf: kdf)

    var secretKeyBytes = SecretKeyCoding.generateSecretKeyBytes()
    var recoveryCodeBytes = SecretKeyCoding.generateSecretKeyBytes()
    var vekBytes = KeyholeCrypto.generateVaultKeyBytes()
    defer {
        KeyholeCrypto.zeroize(&secretKeyBytes)
        KeyholeCrypto.zeroize(&recoveryCodeBytes)
        KeyholeCrypto.zeroize(&vekBytes)
    }

    let masterKey = try KeyholeCrypto.deriveMasterKey(
        masterPassword: masterPassword,
        params: kdf,
        secretKey: secretKeyBytes
    )
    let wrappedKey = try KeyholeCrypto.encrypt(
        key: masterKey,
        plaintext: vekBytes,
        aad: KeyholeCrypto.wrappedKeyAad(header)
    )
    let vaultKey = try KeyholeCrypto.importAesKey(vekBytes)

    let data = options.initialData ?? emptyVaultData()
    let payload = try KeyholeCrypto.encrypt(
        key: vaultKey,
        plaintext: EncodingUtil.utf8ToBytes(try VaultJSON.stringifyPayload(data)),
        aad: KeyholeCrypto.payloadAad(vaultId: vaultId, formatVersion: formatVersion)
    )
    let recovery = try wrapForRecovery(
        vekBytes: vekBytes,
        recoveryCodeBytes: recoveryCodeBytes,
        vaultId: vaultId,
        formatVersion: formatVersion,
        kdfPreset: options.kdfPreset
    )

    let timestamp = nowISO()
    let file = VaultFile(
        format: VAULT_FORMAT_ID,
        formatVersion: formatVersion,
        vaultId: vaultId,
        createdAt: timestamp,
        updatedAt: timestamp,
        kdf: kdf,
        wrappedKey: wrappedKey,
        payload: payload,
        recoveryKdf: recovery.recoveryKdf,
        recoveryWrappedKey: recovery.recoveryWrappedKey
    )
    let session = VaultSession(
        vaultId: vaultId,
        key: vaultKey,
        data: data,
        unlockedAt: Date().timeIntervalSince1970 * 1000
    )
    return (
        file,
        session,
        RecoveryKit(
            secretKey: try SecretKeyCoding.formatSecret(.secretKey, secretKeyBytes),
            recoveryCode: try SecretKeyCoding.formatSecret(.recoveryCode, recoveryCodeBytes)
        )
    )
}

public func unlockVault(
    file input: Any,
    masterPassword: String,
    secretKey: String? = nil
) throws -> VaultSession {
    let parsed = try parseVaultFile(input)
    if parsed.formatVersion > FORMAT_VERSION {
        throw KeyholeError.unsupportedVersion(
            "This vault was written by a newer version of Keyhole (format \(parsed.formatVersion)). Please update."
        )
    }

    // Checked before the KDF runs so the two "you gave us the wrong thing" cases are
    // named, rather than both surfacing 105 ms later as an indistinguishable bad tag.
    if vaultRequiresSecretKey(parsed) && secretKey == nil {
        throw KeyholeError.validation("This vault needs its Secret Key as well as the master password.")
    }
    if !vaultRequiresSecretKey(parsed) && secretKey != nil {
        throw KeyholeError.validation("This vault does not use a Secret Key.")
    }

    let header = KeyholeCrypto.VaultHeader(
        vaultId: parsed.vaultId,
        formatVersion: parsed.formatVersion,
        kdf: parsed.kdf
    )
    var secretKeyBytes = try secretKey.map { try SecretKeyCoding.parseSecret(.secretKey, $0) }
    defer { if secretKeyBytes != nil { KeyholeCrypto.zeroize(&secretKeyBytes!) } }

    let masterKey = try KeyholeCrypto.deriveMasterKey(
        masterPassword: masterPassword,
        params: parsed.kdf,
        secretKey: secretKeyBytes
    )

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
        unlockedAt: Date().timeIntervalSince1970 * 1000,
        foreignSchemaVersion: foreignSchemaVersion(data)
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
    kdfPreset: KdfPresetName = .interactive,
    secretKey: String? = nil
) throws -> (file: VaultFile, session: VaultSession, kit: RecoveryKit?) {
    try assertMasterPasswordAcceptable(newPassword)
    let current = try unlockVault(file: file, masterPassword: currentPassword, secretKey: secretKey)

    // The envelope version never changes here. It previously hardcoded
    // FORMAT_VERSION, which was harmless while that was 1 and would now silently
    // convert a format-1 vault into one demanding a Secret Key nobody has.
    let formatVersion = file.formatVersion
    let kdf = KeyholeCrypto.defaultKdfParams(preset: kdfPreset)
    let header = KeyholeCrypto.VaultHeader(vaultId: file.vaultId, formatVersion: formatVersion, kdf: kdf)

    var secretKeyBytes = try secretKey.map { try SecretKeyCoding.parseSecret(.secretKey, $0) }
    var vekBytes = KeyholeCrypto.generateVaultKeyBytes()
    // Reissued rather than preserved — see below.
    var recoveryCodeBytes = vaultHasRecoveryKit(file) ? SecretKeyCoding.generateSecretKeyBytes() : nil
    defer {
        if secretKeyBytes != nil { KeyholeCrypto.zeroize(&secretKeyBytes!) }
        if recoveryCodeBytes != nil { KeyholeCrypto.zeroize(&recoveryCodeBytes!) }
        KeyholeCrypto.zeroize(&vekBytes)
    }

    let newMasterKey = try KeyholeCrypto.deriveMasterKey(
        masterPassword: newPassword,
        params: kdf,
        secretKey: secretKeyBytes
    )
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
        aad: KeyholeCrypto.payloadAad(vaultId: file.vaultId, formatVersion: formatVersion)
    )

    var next = file
    next.formatVersion = formatVersion
    next.kdf = kdf
    next.wrappedKey = wrappedKey
    next.payload = payload
    next.updatedAt = data.updatedAt

    /*
     * THE RECOVERY BLOB MUST NOT SURVIVE THIS UNTOUCHED.
     *
     * `var next = file` copies every field, and until format 2 that was exactly
     * right. It no longer is: `recoveryWrappedKey` wraps the VEK, this function
     * rotates the VEK, and a carried-over blob therefore decrypts to a key that no
     * longer opens anything. The vault would keep working perfectly and only the
     * Recovery Kit would be dead — discovered by someone who has already forgotten
     * their password and has nothing else left to try.
     *
     * The existing code cannot be re-wrapped: it lives only on the user's printout,
     * by design. So the kit is reissued and the caller is handed a new one it is
     * obliged to show.
     */
    var kit: RecoveryKit?
    if let recoveryCodeBytes, let secretKeyBytes {
        let recovery = try wrapForRecovery(
            vekBytes: vekBytes,
            recoveryCodeBytes: recoveryCodeBytes,
            vaultId: file.vaultId,
            formatVersion: formatVersion,
            kdfPreset: kdfPreset
        )
        next.recoveryKdf = recovery.recoveryKdf
        next.recoveryWrappedKey = recovery.recoveryWrappedKey
        kit = RecoveryKit(
            // Unchanged: the Secret Key is a device factor, independent of the
            // password. The reprinted kit must still carry it, since the two halves
            // are useless apart.
            secretKey: try SecretKeyCoding.formatSecret(.secretKey, secretKeyBytes),
            recoveryCode: try SecretKeyCoding.formatSecret(.recoveryCode, recoveryCodeBytes)
        )
    }

    return (
        next,
        VaultSession(
            vaultId: file.vaultId,
            key: newVaultKey,
            data: data,
            unlockedAt: Date().timeIntervalSince1970 * 1000,
            foreignSchemaVersion: current.foreignSchemaVersion
        ),
        kit
    )
}

/// Upgrade a format-1 vault to format 2: bind it to a fresh Secret Key and issue a
/// Recovery Kit.
///
/// The VEK is rotated, not reused: otherwise the pre-upgrade envelope — attackable
/// with the password alone by anyone who copied it — would still hold a key that
/// decrypts everything written after the upgrade.
public func upgradeToV2(
    file: VaultFile,
    masterPassword: String,
    kdfPreset: KdfPresetName = .interactive
) throws -> (file: VaultFile, session: VaultSession, kit: RecoveryKit) {
    guard file.formatVersion < SECRET_KEY_FORMAT_VERSION else {
        throw KeyholeError.validation("This vault already uses a Secret Key.")
    }
    let current = try unlockVault(file: file, masterPassword: masterPassword)

    let formatVersion = SECRET_KEY_FORMAT_VERSION
    let kdf = KeyholeCrypto.defaultKdfParams(preset: kdfPreset)
    let header = KeyholeCrypto.VaultHeader(vaultId: file.vaultId, formatVersion: formatVersion, kdf: kdf)

    var secretKeyBytes = SecretKeyCoding.generateSecretKeyBytes()
    var recoveryCodeBytes = SecretKeyCoding.generateSecretKeyBytes()
    var vekBytes = KeyholeCrypto.generateVaultKeyBytes()
    defer {
        KeyholeCrypto.zeroize(&secretKeyBytes)
        KeyholeCrypto.zeroize(&recoveryCodeBytes)
        KeyholeCrypto.zeroize(&vekBytes)
    }

    let masterKey = try KeyholeCrypto.deriveMasterKey(
        masterPassword: masterPassword,
        params: kdf,
        secretKey: secretKeyBytes
    )
    let wrappedKey = try KeyholeCrypto.encrypt(
        key: masterKey,
        plaintext: vekBytes,
        aad: KeyholeCrypto.wrappedKeyAad(header)
    )
    let vaultKey = try KeyholeCrypto.importAesKey(vekBytes)

    var data = current.data
    data.updatedAt = nowISO()
    let payload = try KeyholeCrypto.encrypt(
        key: vaultKey,
        plaintext: EncodingUtil.utf8ToBytes(try VaultJSON.stringifyPayload(data)),
        aad: KeyholeCrypto.payloadAad(vaultId: file.vaultId, formatVersion: formatVersion)
    )
    let recovery = try wrapForRecovery(
        vekBytes: vekBytes,
        recoveryCodeBytes: recoveryCodeBytes,
        vaultId: file.vaultId,
        formatVersion: formatVersion,
        kdfPreset: kdfPreset
    )

    var next = file
    next.formatVersion = formatVersion
    next.kdf = kdf
    next.wrappedKey = wrappedKey
    next.payload = payload
    next.updatedAt = data.updatedAt
    next.recoveryKdf = recovery.recoveryKdf
    next.recoveryWrappedKey = recovery.recoveryWrappedKey

    return (
        next,
        VaultSession(
            vaultId: file.vaultId,
            key: vaultKey,
            data: data,
            unlockedAt: Date().timeIntervalSince1970 * 1000,
            foreignSchemaVersion: current.foreignSchemaVersion
        ),
        RecoveryKit(
            secretKey: try SecretKeyCoding.formatSecret(.secretKey, secretKeyBytes),
            recoveryCode: try SecretKeyCoding.formatSecret(.recoveryCode, recoveryCodeBytes)
        )
    )
}

/// Open a vault with the Recovery Code alone — no master password, no Secret Key.
///
/// Read access only. Note what this implies, and say it plainly wherever a kit is
/// printed: the Recovery Code is on its own equivalent to the vault. The printout is
/// not a hint or a backup password — it is the vault, on paper.
public func unlockWithRecoveryCode(file input: Any, recoveryCode: String) throws -> VaultSession {
    let parsed = try parseVaultFile(input)
    if parsed.formatVersion > FORMAT_VERSION {
        throw KeyholeError.unsupportedVersion(
            "This vault was written by a newer version of Keyhole (format \(parsed.formatVersion)). Please update."
        )
    }
    guard let recoveryKdf = parsed.recoveryKdf, let recoveryWrappedKey = parsed.recoveryWrappedKey else {
        throw KeyholeError.validation("No Recovery Kit was issued for this vault.")
    }

    var codeBytes = try SecretKeyCoding.parseSecret(.recoveryCode, recoveryCode)
    defer { KeyholeCrypto.zeroize(&codeBytes) }

    let recoveryKey = try KeyholeCrypto.deriveMasterKey(
        masterPassword: try SecretKeyCoding.formatSecret(.recoveryCode, codeBytes),
        params: recoveryKdf
    )
    var vekBytes = try KeyholeCrypto.decrypt(
        key: recoveryKey,
        blob: recoveryWrappedKey,
        aad: KeyholeCrypto.recoveryAad(
            vaultId: parsed.vaultId,
            formatVersion: parsed.formatVersion,
            recoveryKdf: recoveryKdf
        )
    )
    let vaultKey = try KeyholeCrypto.importAesKey(vekBytes)
    KeyholeCrypto.zeroize(&vekBytes)

    var plaintext = try KeyholeCrypto.decrypt(
        key: vaultKey,
        blob: parsed.payload,
        aad: KeyholeCrypto.payloadAad(vaultId: parsed.vaultId, formatVersion: parsed.formatVersion)
    )
    defer { KeyholeCrypto.zeroize(&plaintext) }

    let data: VaultData
    do {
        data = try parseVaultData(EncodingUtil.bytesToUtf8(plaintext))
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
        unlockedAt: Date().timeIntervalSince1970 * 1000,
        foreignSchemaVersion: foreignSchemaVersion(data)
    )
}

/// The full recovery flow: open with the Recovery Code, set a new master password,
/// and issue a replacement kit.
///
/// A fresh Secret Key is minted rather than the old one carried across. The user is
/// re-establishing this vault everywhere anyway, and requiring the old Secret Key
/// would mean asking for a second thing from someone who has just proved they lost
/// track of the first.
public func recoverWithKit(
    file: VaultFile,
    recoveryCode: String,
    newPassword: String,
    kdfPreset: KdfPresetName = .interactive
) throws -> (file: VaultFile, session: VaultSession, kit: RecoveryKit) {
    try assertMasterPasswordAcceptable(newPassword)
    let current = try unlockWithRecoveryCode(file: file, recoveryCode: recoveryCode)

    let formatVersion = max(file.formatVersion, SECRET_KEY_FORMAT_VERSION)
    let kdf = KeyholeCrypto.defaultKdfParams(preset: kdfPreset)
    let header = KeyholeCrypto.VaultHeader(vaultId: file.vaultId, formatVersion: formatVersion, kdf: kdf)

    var secretKeyBytes = SecretKeyCoding.generateSecretKeyBytes()
    var recoveryCodeBytes = SecretKeyCoding.generateSecretKeyBytes()
    var vekBytes = KeyholeCrypto.generateVaultKeyBytes()
    defer {
        KeyholeCrypto.zeroize(&secretKeyBytes)
        KeyholeCrypto.zeroize(&recoveryCodeBytes)
        KeyholeCrypto.zeroize(&vekBytes)
    }

    let masterKey = try KeyholeCrypto.deriveMasterKey(
        masterPassword: newPassword,
        params: kdf,
        secretKey: secretKeyBytes
    )
    let wrappedKey = try KeyholeCrypto.encrypt(
        key: masterKey,
        plaintext: vekBytes,
        aad: KeyholeCrypto.wrappedKeyAad(header)
    )
    let vaultKey = try KeyholeCrypto.importAesKey(vekBytes)

    var data = current.data
    data.updatedAt = nowISO()
    let payload = try KeyholeCrypto.encrypt(
        key: vaultKey,
        plaintext: EncodingUtil.utf8ToBytes(try VaultJSON.stringifyPayload(data)),
        aad: KeyholeCrypto.payloadAad(vaultId: file.vaultId, formatVersion: formatVersion)
    )
    let recovery = try wrapForRecovery(
        vekBytes: vekBytes,
        recoveryCodeBytes: recoveryCodeBytes,
        vaultId: file.vaultId,
        formatVersion: formatVersion,
        kdfPreset: kdfPreset
    )

    var next = file
    next.formatVersion = formatVersion
    next.kdf = kdf
    next.wrappedKey = wrappedKey
    next.payload = payload
    next.updatedAt = data.updatedAt
    next.recoveryKdf = recovery.recoveryKdf
    next.recoveryWrappedKey = recovery.recoveryWrappedKey

    return (
        next,
        VaultSession(
            vaultId: file.vaultId,
            key: vaultKey,
            data: data,
            unlockedAt: Date().timeIntervalSince1970 * 1000,
            foreignSchemaVersion: current.foreignSchemaVersion
        ),
        RecoveryKit(
            secretKey: try SecretKeyCoding.formatSecret(.secretKey, secretKeyBytes),
            recoveryCode: try SecretKeyCoding.formatSecret(.recoveryCode, recoveryCodeBytes)
        )
    )
}

public func lockSession(_ session: inout VaultSession) {
    session.data = emptyVaultData()
    session.unlockedAt = 0
}

/// Bring a decrypted payload up to the model this build understands.
///
/// A NEWER PAYLOAD IS NOT AN ERROR — same contract as `migrate()` in
/// core/src/vault.ts. This used to throw, which meant a vault written by an
/// updated desktop or extension could not be opened on this phone at all. Since
/// `Entry`/`VaultData` now carry unrecognised fields through (see JSONValue.swift),
/// a newer payload whose known fields decode is usable: read what we understand,
/// preserve the rest verbatim. A genuinely malformed payload still throws, from
/// decoding and `validateVaultData`.
public func migrateVaultData(_ data: VaultData) throws -> VaultData {
    var out = data
    out.tombstones = data.tombstones
    // Never stamp our own version onto a payload written by a newer build: the
    // fields we cannot see are still in there, and relabelling it as ours would
    // tell the next reader they are gone.
    out.schemaVersion = max(data.schemaVersion, SCHEMA_VERSION)
    return out
}

/// How far ahead of this build a payload is, or nil when it is one we know.
public func foreignSchemaVersion(_ data: VaultData) -> Int? {
    data.schemaVersion > SCHEMA_VERSION ? data.schemaVersion : nil
}

// MARK: - CRUD

/// Bytes used by attachments across the vault (pre-base64).
public func vaultAttachmentBytes(_ data: VaultData) -> Int {
    data.entries.reduce(0) { sum, entry in
        sum + entry.attachments.reduce(0) { $0 + $1.sizeBytes }
    }
}

private func assertAttachmentsWithinBudget(_ data: VaultData) throws {
    for entry in data.entries {
        for att in entry.attachments {
            if att.sizeBytes > MAX_ATTACHMENT_BYTES {
                throw KeyholeError.validation(
                    "Attachment \"\(att.name)\" is too large (max \(MAX_ATTACHMENT_BYTES) bytes per file)."
                )
            }
        }
    }
    if vaultAttachmentBytes(data) > MAX_ATTACHMENTS_VAULT_BYTES {
        throw KeyholeError.validation(
            "Attachments would exceed the vault budget of \(MAX_ATTACHMENTS_VAULT_BYTES) bytes."
        )
    }
}

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
        totpConfig: input.totpConfig,
        customFields: input.customFields ?? [],
        attachments: input.attachments ?? [],
        passkeys: [],
        createdAt: timestamp,
        updatedAt: timestamp,
        passwordUpdatedAt: timestamp,
        history: [],
        deletedAt: nil
    )
    var next = data
    next.entries.append(entry)
    try assertAttachmentsWithinBudget(next)
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
    public var totpConfig: TotpConfig??
    public var customFields: [CustomField]?
    public var attachments: [Attachment]?

    public init(
        title: String? = nil,
        kind: EntryKind? = nil,
        username: String? = nil,
        password: String? = nil,
        urls: [String]? = nil,
        notes: String? = nil,
        tags: [String]? = nil,
        folderId: String?? = nil,
        totpSecret: String?? = nil,
        totpConfig: TotpConfig?? = nil,
        customFields: [CustomField]? = nil,
        attachments: [Attachment]? = nil
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
        self.totpConfig = totpConfig
        self.customFields = customFields
        self.attachments = attachments
    }
}

public func updateEntry(data: VaultData, id: String, patch: UpdateEntryPatch) throws -> VaultData {
    guard let index = data.entries.firstIndex(where: { $0.id == id }) else {
        throw KeyholeError.validation("No entry with id \(id).")
    }
    var existing = data.entries[index]
    let passwordChanged = patch.password != nil && patch.password != existing.password
    let changedAt = nowISO()
    if passwordChanged {
        existing.history = rememberPassword(
            history: existing.history,
            previousPassword: existing.password,
            changedAt: changedAt
        )
    }

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
    if let totpConfig = patch.totpConfig { existing.totpConfig = totpConfig }
    if let customFields = patch.customFields { existing.customFields = customFields }
    if let attachments = patch.attachments { existing.attachments = attachments }
    existing.updatedAt = changedAt
    if passwordChanged { existing.passwordUpdatedAt = changedAt }
    if existing.title.isEmpty {
        throw KeyholeError.validation("Entry title must not be empty.")
    }

    var next = data
    next.entries[index] = existing
    try assertAttachmentsWithinBudget(next)
    return next
}

/// Cap and dedupe rule mirrored from `rememberPassword` in core/src/vault.ts.
/// Keyed on (changedAt, password) — the same key the merge uses, so two devices
/// cannot end up with different histories for the same entry.
private func rememberPassword(
    history: [PasswordHistoryEntry],
    previousPassword: String,
    changedAt: String
) -> [PasswordHistoryEntry] {
    if previousPassword.isEmpty { return history }
    let withoutDuplicate = history.filter {
        !($0.changedAt == changedAt && $0.password == previousPassword)
    }
    let next = [PasswordHistoryEntry(password: previousPassword, changedAt: changedAt)] + withoutDuplicate
    return Array(next.prefix(PASSWORD_HISTORY_LIMIT))
}

// MARK: - Passkeys

/// Live passkeys whose relying party matches `rpId` (exact, case-insensitive).
public func findPasskeys(forRelyingParty rpId: String, in data: VaultData) -> [(entry: Entry, passkey: PasskeyRecord)] {
    let needle = rpId.lowercased()
    var out: [(Entry, PasskeyRecord)] = []
    for entry in liveEntries(data) {
        for pk in entry.passkeys where pk.relyingPartyId.lowercased() == needle {
            out.append((entry, pk))
        }
    }
    return out
}

/// Locate a passkey by credential ID bytes (Base64 comparison).
public func findPasskey(
    credentialId: Data,
    in data: VaultData
) -> (entry: Entry, passkey: PasskeyRecord)? {
    let b64 = credentialId.base64EncodedString()
    for entry in liveEntries(data) {
        if let pk = entry.passkeys.first(where: { $0.credentialIdB64 == b64 }) {
            return (entry, pk)
        }
    }
    return nil
}

/// Append a passkey to an existing login, or create a new login for the RP.
public func storePasskey(
    data: VaultData,
    record: PasskeyRecord,
    preferredEntryId: String? = nil
) throws -> (data: VaultData, entry: Entry) {
    let rp = record.relyingPartyId.lowercased()
    let timestamp = nowISO()

    if let preferredEntryId,
       let index = data.entries.firstIndex(where: { $0.id == preferredEntryId && $0.deletedAt == nil })
    {
        var next = data
        var entry = next.entries[index]
        entry.passkeys.append(record)
        entry.updatedAt = timestamp
        next.entries[index] = entry
        return (next, entry)
    }

    if let index = data.entries.firstIndex(where: { entry in
        entry.deletedAt == nil
            && entry.kind == .login
            && (
                entry.passkeys.contains { $0.relyingPartyId.lowercased() == rp }
                    || entry.urls.contains { url in
                        let withScheme = url.contains("://") ? url : "https://\(url)"
                        guard let host = URL(string: withScheme)?.host?.lowercased() else { return false }
                        return host == rp || host.hasSuffix(".\(rp)") || host == "www.\(rp)"
                    }
            )
    }) {
        var next = data
        var entry = next.entries[index]
        entry.passkeys.append(record)
        if entry.username.isEmpty, !record.userName.isEmpty {
            entry.username = record.userName
        }
        entry.updatedAt = timestamp
        next.entries[index] = entry
        return (next, entry)
    }

    let title = record.userDisplayName.isEmpty
        ? (record.userName.isEmpty ? record.relyingPartyId : record.userName)
        : record.userDisplayName
    let created = try createEntry(
        data: data,
        input: EntryInput(
            title: title,
            kind: .login,
            username: record.userName,
            urls: ["https://\(record.relyingPartyId)"]
        )
    )
    var next = created.data
    guard let index = next.entries.firstIndex(where: { $0.id == created.entry.id }) else {
        return created
    }
    var entry = next.entries[index]
    entry.passkeys = [record]
    entry.updatedAt = timestamp
    next.entries[index] = entry
    return (next, entry)
}

public func updatePasskeySignCount(
    data: VaultData,
    entryId: String,
    passkeyId: String,
    signCount: UInt32,
    lastUsedAt: String
) throws -> VaultData {
    guard let index = data.entries.firstIndex(where: { $0.id == entryId }) else {
        throw KeyholeError.validation("No entry with id \(entryId).")
    }
    var next = data
    var entry = next.entries[index]
    guard let pkIndex = entry.passkeys.firstIndex(where: { $0.id == passkeyId }) else {
        throw KeyholeError.validation("No passkey with id \(passkeyId).")
    }
    entry.passkeys[pkIndex].signCount = signCount
    entry.passkeys[pkIndex].lastUsedAt = lastUsedAt
    entry.updatedAt = lastUsedAt
    next.entries[index] = entry
    return next
}

public func removePasskey(data: VaultData, entryId: String, passkeyId: String) throws -> VaultData {
    guard let index = data.entries.firstIndex(where: { $0.id == entryId }) else {
        throw KeyholeError.validation("No entry with id \(entryId).")
    }
    var next = data
    var entry = next.entries[index]
    let before = entry.passkeys.count
    entry.passkeys.removeAll { $0.id == passkeyId }
    guard entry.passkeys.count < before else {
        throw KeyholeError.validation("No passkey with id \(passkeyId).")
    }
    entry.updatedAt = nowISO()
    next.entries[index] = entry
    return next
}

/// Move an entry to the trash. Reversible with `restoreEntry`; mirrors
/// `deleteEntry` in core/src/vault.ts, which stopped destroying entries because a
/// hard delete propagated to every synced device with no way back.
public func deleteEntry(data: VaultData, id: String) throws -> VaultData {
    guard let index = data.entries.firstIndex(where: { $0.id == id }) else {
        throw KeyholeError.validation("No entry with id \(id).")
    }
    if data.entries[index].deletedAt != nil { return data }

    let timestamp = nowISO()
    var next = data
    next.entries[index].deletedAt = timestamp
    next.entries[index].updatedAt = timestamp
    return next
}

/// Move several entries to the trash in one edit. Mirrors `deleteEntries` in
/// core/src/vault.ts — used for bulk actions (e.g. clearing every health
/// finding at once) so the mutation is a single save, not one per entry.
public func deleteEntries(data: VaultData, ids: [String]) -> VaultData {
    let wanted = Set(ids)
    guard !wanted.isEmpty else { return data }
    guard data.entries.contains(where: { wanted.contains($0.id) && $0.deletedAt == nil }) else { return data }

    let timestamp = nowISO()
    var next = data
    for index in next.entries.indices where wanted.contains(next.entries[index].id) && next.entries[index].deletedAt == nil {
        next.entries[index].deletedAt = timestamp
        next.entries[index].updatedAt = timestamp
    }
    return next
}

/// Take an entry back out of the trash.
public func restoreEntry(data: VaultData, id: String) throws -> VaultData {
    guard let index = data.entries.firstIndex(where: { $0.id == id }) else {
        throw KeyholeError.validation("No entry with id \(id).")
    }
    if data.entries[index].deletedAt == nil { return data }

    var next = data
    next.entries[index].deletedAt = nil
    next.entries[index].updatedAt = nowISO()
    return next
}

/// Destroy an entry for good, on every device. The old `deleteEntry`.
public func purgeEntry(data: VaultData, id: String) throws -> VaultData {
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

/// Purge anything that has sat in the trash past `TRASH_RETENTION_DAYS`.
public func purgeExpiredTrash(data: VaultData, now: Date = Date()) -> VaultData {
    let cutoff = now.timeIntervalSince1970 - Double(TRASH_RETENTION_DAYS) * 24 * 60 * 60
    let expired = data.entries.filter { entry in
        guard let deletedAt = entry.deletedAt,
              let parsed = parseTrashDate(deletedAt) else { return false }
        return parsed.timeIntervalSince1970 < cutoff
    }
    if expired.isEmpty { return data }

    let timestamp = nowISO()
    var next = data
    let expiredIds = Set(expired.map(\.id))
    next.entries = data.entries.filter { !expiredIds.contains($0.id) }
    next.tombstones = expired.reduce(data.tombstones) { acc, entry in
        recordTombstone(existing: acc, next: Tombstone(id: entry.id, kind: .entry, deletedAt: timestamp))
    }
    return next
}

private func parseTrashDate(_ iso: String) -> Date? {
    let withFraction = ISO8601DateFormatter()
    withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = withFraction.date(from: iso) { return date }
    let plain = ISO8601DateFormatter()
    plain.formatOptions = [.withInternetDateTime]
    return plain.date(from: iso)
}

/// Live entries only — the trash is reached through `trashedEntries`.
public func liveEntries(_ data: VaultData) -> [Entry] {
    data.entries.filter { $0.deletedAt == nil }
}

/// What is currently in the trash, most recently deleted first.
public func trashedEntries(_ data: VaultData) -> [Entry] {
    data.entries
        .filter { $0.deletedAt != nil }
        .sorted { ($0.deletedAt ?? "") > ($1.deletedAt ?? "") }
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
    let live = liveEntries(data)
    if q.isEmpty {
        return live.sorted(by: sorted)
    }
    return live.filter { e in
        e.title.lowercased().contains(q)
            || e.username.lowercased().contains(q)
            || e.tags.contains(where: { $0.lowercased().contains(q) })
            || e.urls.contains(where: { $0.lowercased().contains(q) })
            || e.customFields.contains(where: { $0.label.lowercased().contains(q) })
            || (e.kind == .note && e.notes.lowercased().contains(q))
    }.sorted(by: sorted)
}
