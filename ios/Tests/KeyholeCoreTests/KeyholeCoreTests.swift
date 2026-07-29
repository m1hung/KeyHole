import XCTest
@testable import KeyholeCore

final class DemoVaultTests: XCTestCase {
    private let demoPassword = "demo-master-passphrase-2026"

    private func loadDemoVault() throws -> VaultFile {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "demo-vault.keyhole", withExtension: "json", subdirectory: "Fixtures")
                ?? Bundle.module.url(forResource: "demo-vault.keyhole", withExtension: "json")
        )
        let text = try String(contentsOf: url, encoding: .utf8)
        return try parseVaultFile(text)
    }

    func testUnlockDemoVault() throws {
        let file = try loadDemoVault()
        let session = try unlockVault(file: file, masterPassword: demoPassword)
        XCTAssertEqual(session.vaultId, file.vaultId)
        XCTAssertFalse(session.data.entries.isEmpty)
        XCTAssertEqual(session.data.schemaVersion, SCHEMA_VERSION)
    }

    func testWrongPasswordFails() throws {
        let file = try loadDemoVault()
        XCTAssertThrowsError(try unlockVault(file: file, masterPassword: "wrong-password-xx")) { err in
            guard case KeyholeError.decryption = err as? KeyholeError else {
                return XCTFail("Expected decryption error, got \(err)")
            }
        }
    }

    func testCreateUnlockRoundTrip() throws {
        let password = "test-master-pass-roundtrip"
        let (file, created) = try createVault(masterPassword: password)
        var (data, _) = try createEntry(data: created.data, input: EntryInput(
            title: "Example",
            username: "user@example.com",
            password: "s3cret!",
            urls: ["https://example.com"]
        ))
        var session = VaultSession(
            vaultId: created.vaultId,
            key: created.key,
            data: data,
            unlockedAt: created.unlockedAt
        )
        let saved = try saveVault(session: &session, previous: file)
        let unlocked = try unlockVault(file: saved, masterPassword: password)
        XCTAssertEqual(unlocked.data.entries.count, 1)
        XCTAssertEqual(unlocked.data.entries[0].title, "Example")
        XCTAssertEqual(unlocked.data.entries[0].password, "s3cret!")
    }

    func testAadTemplates() {
        let kdf = KdfParams(
            memoryKiB: 65536,
            iterations: 3,
            parallelism: 1,
            saltB64: "AAAAAAAAAAAAAAAAAAAAAA==",
            keyLength: 32
        )
        let header = KeyholeCrypto.VaultHeader(vaultId: "00000000-0000-4000-8000-000000000001", formatVersion: 1, kdf: kdf)
        let wrap = EncodingUtil.bytesToUtf8(KeyholeCrypto.wrappedKeyAad(header))
        XCTAssertTrue(wrap.hasPrefix("keyhole.wrapkey.v1|"))
        XCTAssertTrue(wrap.contains("|argon2id|65536|3|1|32|"))
        let payload = EncodingUtil.bytesToUtf8(KeyholeCrypto.payloadAad(vaultId: header.vaultId, formatVersion: 1))
        XCTAssertEqual(payload, "keyhole.payload.v1|\(header.vaultId)|1")
    }
}

final class SyncMergeTests: XCTestCase {
    private func withTimes(_ data: VaultData, id: String, updatedAt: String) -> VaultData {
        var next = data
        next.entries = data.entries.map { e in
            var c = e
            if c.id == id { c.updatedAt = updatedAt }
            return c
        }
        return next
    }

    private func titles(_ d: VaultData) -> [String] {
        d.entries.map(\.title).sorted()
    }

    func testUnionsEntries() throws {
        let a = try createEntry(data: emptyVaultData(), input: EntryInput(title: "Only on A")).data
        let b = try createEntry(data: emptyVaultData(), input: EntryInput(title: "Only on B")).data
        XCTAssertEqual(titles(mergeVaultData(a, b).data), ["Only on A", "Only on B"])
    }

    func testKeepsNewerEdit() throws {
        let created = try createEntry(data: emptyVaultData(), input: EntryInput(title: "Bank", password: "old"))
        let older = withTimes(
            try updateEntry(data: created.data, id: created.entry.id, patch: UpdateEntryPatch(password: "from-a")),
            id: created.entry.id,
            updatedAt: "2026-01-01T00:00:00.000Z"
        )
        let newer = withTimes(
            try updateEntry(data: created.data, id: created.entry.id, patch: UpdateEntryPatch(password: "from-b")),
            id: created.entry.id,
            updatedAt: "2026-06-01T00:00:00.000Z"
        )
        XCTAssertEqual(mergeVaultData(older, newer).data.entries[0].password, "from-b")
        XCTAssertEqual(mergeVaultData(newer, older).data.entries[0].password, "from-b")
    }

    func testPropagatesDeletion() throws {
        let created = try createEntry(data: emptyVaultData(), input: EntryInput(title: "Retired"))
        let deleted = try deleteEntry(data: created.data, id: created.entry.id)
        XCTAssertEqual(mergeVaultData(deleted, created.data).data.entries.count, 0)
        XCTAssertEqual(mergeVaultData(created.data, deleted).data.entries.count, 0)
    }

    func testEditAfterDeleteWins() throws {
        let created = try createEntry(data: emptyVaultData(), input: EntryInput(title: "Contested"))
        let deleted = try deleteEntry(data: created.data, id: created.entry.id)
        let edited = withTimes(
            try updateEntry(data: created.data, id: created.entry.id, patch: UpdateEntryPatch(password: "still wanted")),
            id: created.entry.id,
            updatedAt: "2099-01-01T00:00:00.000Z"
        )
        let merged = mergeVaultData(deleted, edited).data
        XCTAssertEqual(merged.entries.count, 1)
        XCTAssertEqual(merged.entries[0].password, "still wanted")
    }

    func testFolderDeleteUnfilesEntries() throws {
        let withFolder = try createFolder(data: emptyVaultData(), name: "Work")
        let base = try createEntry(
            data: withFolder.data,
            input: EntryInput(title: "Filed", folderId: withFolder.folder.id)
        ).data
        let removed = deleteFolder(data: base, id: withFolder.folder.id)
        let merged = mergeVaultData(removed, base).data
        XCTAssertEqual(merged.folders.count, 0)
        XCTAssertEqual(merged.entries.count, 1)
        XCTAssertNil(merged.entries[0].folderId)
    }

    func testTombstoneExpiry() throws {
        let created = try createEntry(data: emptyVaultData(), input: EntryInput(title: "Ancient"))
        let deleted = try deleteEntry(data: created.data, id: created.entry.id)
        let dayMs = 24.0 * 60 * 60 * 1000
        let wayLater = Date().timeIntervalSince1970 * 1000 + Double(TOMBSTONE_TTL_DAYS + 1) * dayMs
        let merged = mergeVaultData(deleted, deleted, nowMs: wayLater).data
        XCTAssertEqual(merged.tombstones.count, 0)
    }

    func testSymmetricConvergence() throws {
        let seed = try createEntry(data: emptyVaultData(), input: EntryInput(title: "Shared"))
        let seeded = try createEntry(data: seed.data, input: EntryInput(title: "Doomed"))
        let deviceA = try createEntry(
            data: withTimes(seeded.data, id: seed.entry.id, updatedAt: "2026-03-01T00:00:00.000Z"),
            input: EntryInput(title: "A only")
        ).data
        let deviceB = try deleteEntry(
            data: try createEntry(data: seeded.data, input: EntryInput(title: "B only")).data,
            id: seeded.entry.id
        )
        let ab = mergeVaultData(deviceA, deviceB).data
        let ba = mergeVaultData(deviceB, deviceA).data
        let abJSON = try VaultJSON.canonicalString(ab)
        let baJSON = try VaultJSON.canonicalString(ba)
        XCTAssertEqual(abJSON, baJSON)
        XCTAssertEqual(titles(ab), ["A only", "B only", "Shared"])
    }

    func testSettingsFromNewerVault() {
        var a = emptyVaultData()
        a.updatedAt = "2026-01-01T00:00:00.000Z"
        a.settings.autoLockMinutes = 5
        var b = emptyVaultData()
        b.updatedAt = "2026-09-09T00:00:00.000Z"
        b.settings.autoLockMinutes = 42
        XCTAssertEqual(mergeVaultData(a, b).data.settings.autoLockMinutes, 42)
        XCTAssertEqual(mergeVaultData(b, a).data.settings.autoLockMinutes, 42)
    }

    func testSchemaVersionStamped() {
        XCTAssertEqual(mergeVaultData(emptyVaultData(), emptyVaultData()).data.schemaVersion, SCHEMA_VERSION)
    }
}

final class GeneratorAndTotpTests: XCTestCase {
    func testGeneratePasswordLength() throws {
        let pw = try generatePassword(DEFAULT_GENERATOR_OPTIONS)
        XCTAssertEqual(pw.count, DEFAULT_GENERATOR_OPTIONS.length)
    }

    func testTotpKnownVector() throws {
        // RFC 6238 SHA-1 vector: ASCII "12345678901234567890" → base32 GEZDGNBVGY3TQOJQ
        let code = try generateTotp(
            base32Secret: "GEZDGNBVGY3TQOJQ",
            options: TotpOptions(digits: 8, periodSeconds: 30, algorithm: .sha1),
            atMs: 59_000
        )
        XCTAssertEqual(code.code, "94287082")
    }

    func testWordlistLoaded() {
        XCTAssertEqual(PassphraseWordlist.words.count, 2048)
    }
}
