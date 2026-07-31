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
            guard let kh = err as? KeyholeError, case .decryption = kh else {
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
        let deleted = try purgeEntry(data: created.data, id: created.entry.id)
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
        let deleted = try purgeEntry(data: created.data, id: created.entry.id)
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
        let deviceB = try purgeEntry(
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

    func testNormalizeTotpConfigCollapsesDefaults() {
        XCTAssertNil(normalizeTotpConfig(TotpOptions()))
        XCTAssertNil(normalizeTotpConfig(nil))
        let custom = normalizeTotpConfig(TotpOptions(digits: 8, periodSeconds: 30, algorithm: .sha1))
        XCTAssertEqual(custom?.digits, 8)
    }

    func testSearchMatchesCustomFieldLabelsNotValues() throws {
        let field = CustomField(
            id: "22222222-2222-4222-8222-222222222222",
            label: "PIN code",
            value: "secret-pin",
            secret: true
        )
        var data = try createEntry(data: emptyVaultData(), input: EntryInput(title: "Bank")).data
        let id = data.entries[0].id
        data = try updateEntry(
            data: data,
            id: id,
            patch: UpdateEntryPatch(customFields: [field])
        )
        XCTAssertEqual(searchEntries(data: data, query: "PIN").count, 1)
        XCTAssertEqual(searchEntries(data: data, query: "secret-pin").count, 0)
    }

    func testWordlistLoaded() {
        XCTAssertEqual(PassphraseWordlist.words.count, 2048)
    }
}

/// Interop with the TypeScript surfaces, which read and write the same payload.
///
/// These are the rules that cannot be checked from the TS side: what *this*
/// implementation puts on the wire.
final class PayloadInteropTests: XCTestCase {
    private func encodedEntryJSON(_ entry: Entry) throws -> [String: Any] {
        let data = try JSONEncoder().encode(entry)
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func sampleEntry(extras: [String: JSONValue] = [:]) -> Entry {
        Entry(
            id: "11111111-1111-4111-8111-111111111111",
            title: "Example",
            username: "someone",
            password: "secret",
            urls: ["https://example.com"],
            createdAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
            passwordUpdatedAt: "2026-01-01T00:00:00.000Z",
            extras: extras
        )
    }

    /// The TS schema declares `folderId` / `totpSecret` / `totpConfig` nullable, not optional. A
    /// synthesised Swift encoder would `encodeIfPresent` and omit them, which made
    /// every vault this app saved unreadable on desktop — almost no entry has a TOTP
    /// secret. The keys must be present and null.
    func testNullValuedKeysAreWrittenExplicitly() throws {
        let json = try encodedEntryJSON(sampleEntry())
        XCTAssertTrue(json.keys.contains("folderId"), "folderId must be present, not omitted")
        XCTAssertTrue(json.keys.contains("totpSecret"), "totpSecret must be present, not omitted")
        XCTAssertTrue(json.keys.contains("totpConfig"), "totpConfig must be present, not omitted")
        XCTAssertTrue(json["folderId"] is NSNull)
        XCTAssertTrue(json["totpSecret"] is NSNull)
        XCTAssertTrue(json["totpConfig"] is NSNull)
    }

    /// Schema-3 entries omit the new fields; they must decode with the TS defaults.
    func testSchema3EntryDefaultsNewFields() throws {
        let json = """
        {
          "id": "11111111-1111-4111-8111-111111111111",
          "kind": "login",
          "title": "Legacy",
          "username": "",
          "password": "",
          "urls": [],
          "notes": "",
          "tags": [],
          "folderId": null,
          "totpSecret": null,
          "createdAt": "2026-01-01T00:00:00.000Z",
          "updatedAt": "2026-01-01T00:00:00.000Z",
          "passwordUpdatedAt": "2026-01-01T00:00:00.000Z",
          "history": [],
          "deletedAt": null
        }
        """
        let data = try XCTUnwrap(json.data(using: .utf8))
        let entry = try JSONDecoder().decode(Entry.self, from: data)
        XCTAssertNil(entry.totpConfig)
        XCTAssertEqual(entry.customFields, [])
        XCTAssertEqual(entry.attachments, [])
    }

    func testSchema3SettingsDefaultsBreachCheckOff() throws {
        let json = """
        {
          "autoLockMinutes": 15,
          "clipboardClearSeconds": 30,
          "generator": {
            "length": 20,
            "lowercase": true,
            "uppercase": true,
            "digits": true,
            "symbols": true,
            "excludeAmbiguous": false
          },
          "theme": "system",
          "lockOnHide": false
        }
        """
        let data = try XCTUnwrap(json.data(using: .utf8))
        let settings = try JSONDecoder().decode(Settings.self, from: data)
        XCTAssertFalse(settings.breachCheckEnabled)
    }

    /// Fields written by a newer Keyhole must survive being read and re-saved here,
    /// or syncing through this device destroys what another surface wrote.
    func testUnknownEntryFieldsSurviveARoundTrip() throws {
        let extras: [String: JSONValue] = [
            "futureField": .string("keep-me"),
            "someCount": .int(7),
        ]
        let encoded = try JSONEncoder().encode(sampleEntry(extras: extras))
        let decoded = try JSONDecoder().decode(Entry.self, from: encoded)

        XCTAssertEqual(decoded.extras, extras)
        XCTAssertEqual(decoded.title, "Example")

        // And again, to prove re-encoding does not drop them.
        let reEncoded = try JSONEncoder().encode(decoded)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: reEncoded) as? [String: Any])
        XCTAssertEqual(json["futureField"] as? String, "keep-me")
        XCTAssertEqual(json["someCount"] as? Int, 7, "an integer must not come back as 7.0")
    }

    func testUnknownTopLevelFieldsSurviveARoundTrip() throws {
        var data = emptyVaultData()
        data.extras = ["futureTopLevelKey": .object(["anything": .bool(true)])]
        let decoded = try JSONDecoder().decode(VaultData.self, from: try JSONEncoder().encode(data))
        XCTAssertEqual(decoded.extras, data.extras)
    }

    /// A payload from a newer build opens rather than throwing — refusing it locked
    /// this device out of a vault the desktop had merely updated.
    func testNewerSchemaOpensAndReportsItself() throws {
        var data = emptyVaultData()
        data.schemaVersion = 42
        let migrated = try migrateVaultData(data)
        XCTAssertEqual(migrated.schemaVersion, 42, "must not be relabelled as ours")
        XCTAssertEqual(foreignSchemaVersion(data), 42)
        XCTAssertNil(foreignSchemaVersion(emptyVaultData()))
    }
}

/// The health port must agree with `core/src/health.ts`. Two surfaces disagreeing
/// about what counts as a weak or reused password would be worse than either rule
/// on its own, so these mirror the TypeScript tests.
final class HealthTests: XCTestCase {
    /// Username defaults to a real one so the password-finding tests below stay
    /// about passwords — a blank username is its own finding now.
    private func login(
        _ title: String,
        password: String,
        username: String = "me@example.test",
        passwordUpdatedAt: String = "2026-07-01T00:00:00.000Z"
    ) -> Entry {
        Entry(
            id: UUID().uuidString.lowercased(),
            title: title,
            username: username,
            password: password,
            createdAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
            passwordUpdatedAt: passwordUpdatedAt
        )
    }

    private func vault(_ entries: [Entry]) -> VaultData {
        var data = emptyVaultData()
        data.entries = entries
        return data
    }

    func testFlagsReuseAcrossEntries() {
        let shared = "correct-horse-battery-staple-42"
        let report = analyzeVaultHealth(vault([
            login("A", password: shared),
            login("B", password: shared),
            login("C", password: "an-entirely-different-one-99"),
        ]))
        let reused = report.issues.filter { $0.kind == .reused }
        XCTAssertEqual(reused.count, 2)
        XCTAssertEqual(report.loginCount, 3)
        // Wording matters: it is shown verbatim next to the entry.
        XCTAssertEqual(reused.first?.detail, "Same password as 1 other login.")
    }

    func testFlagsEmptyAndWeak() {
        let report = analyzeVaultHealth(vault([
            login("Empty", password: ""),
            login("Weak", password: "abc"),
        ]))
        XCTAssertTrue(report.issues.contains { $0.kind == .empty && $0.title == "Empty" })
        XCTAssertTrue(report.issues.contains { $0.kind == .weak && $0.title == "Weak" })
        // An entry with no password is not also counted as weak or reused.
        XCTAssertFalse(report.issues.contains { $0.kind == .weak && $0.title == "Empty" })
    }

    func testEmptyFindingNamesTheUsernameToo() {
        let report = analyzeVaultHealth(vault([login("Stub", password: "", username: "")]))
        // Saying only "No password stored." over a blank username reads as a wrong
        // diagnosis, and it must not be reported twice either.
        XCTAssertEqual(report.issues.map(\.kind), [.empty])
        XCTAssertEqual(report.issues.first?.detail, "No username or password stored.")
    }

    func testFlagsAMissingUsernameOnItsOwn() {
        let report = analyzeVaultHealth(vault([
            login("Token", password: "9x!Kq2vTn4Lm8Zr6Wb3Y", username: "")
        ]))
        XCTAssertEqual(report.issues.map(\.kind), [.noUsername])
        XCTAssertEqual(report.issues.first?.detail, "No username stored.")
    }

    func testFlagsStalePasswords() {
        let twoYearsAgo = Date().addingTimeInterval(-2 * 365 * 24 * 60 * 60)
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let report = analyzeVaultHealth(vault([
            login("Old", password: "a-long-enough-unique-password-1", passwordUpdatedAt: formatter.string(from: twoYearsAgo))
        ]))
        XCTAssertTrue(report.issues.contains { $0.kind == .stale })
    }

    func testCleanVaultHasNoIssues() {
        let report = analyzeVaultHealth(vault([
            login("A", password: "9x!Kq2vTn4Lm8Zr6Wb3Y"),
            login("B", password: "Qw7#Rt2$Yu5^Ip9&Ka3*"),
        ]))
        XCTAssertEqual(report.issues, [])
        XCTAssertEqual(report.loginCount, 2)
    }

    /// Notes have no password to audit, so they must not appear at all.
    func testIgnoresNotes() {
        var note = login("A note", password: "")
        note.kind = .note
        let report = analyzeVaultHealth(vault([note]))
        XCTAssertEqual(report.issues, [])
        XCTAssertEqual(report.loginCount, 0)
    }
}

/// Password history and the trash, mirroring core/test/vault.test.ts. Two
/// implementations of one vault format have to agree on these or syncing between
/// a phone and a desktop silently loses data.
final class HistoryAndTrashTests: XCTestCase {
    private func vaultWithLogin(password: String = "first") throws -> (data: VaultData, id: String) {
        let result = try createEntry(
            data: emptyVaultData(),
            input: EntryInput(title: "Bank", password: password)
        )
        return (result.data, result.entry.id)
    }

    func testRotationKeepsTheSupersededPassword() throws {
        let (data, id) = try vaultWithLogin()
        XCTAssertEqual(getEntry(data: data, id: id)?.history.count, 0)

        let rotated = try updateEntry(data: data, id: id, patch: UpdateEntryPatch(password: "second"))
        let entry = try XCTUnwrap(getEntry(data: rotated, id: id))
        XCTAssertEqual(entry.password, "second")
        XCTAssertEqual(entry.history.map(\.password), ["first"])
    }

    func testUnchangedPasswordRecordsNothing() throws {
        let (data, id) = try vaultWithLogin()
        let renamed = try updateEntry(data: data, id: id, patch: UpdateEntryPatch(title: "Bank renamed"))
        XCTAssertEqual(getEntry(data: renamed, id: id)?.history.count, 0)

        let rewritten = try updateEntry(data: data, id: id, patch: UpdateEntryPatch(password: "first"))
        XCTAssertEqual(getEntry(data: rewritten, id: id)?.history.count, 0)
    }

    func testHistoryIsCapped() throws {
        var (data, id) = try vaultWithLogin(password: "pw-0")
        for i in 1...(PASSWORD_HISTORY_LIMIT + 5) {
            data = try updateEntry(data: data, id: id, patch: UpdateEntryPatch(password: "pw-\(i)"))
        }
        let history = try XCTUnwrap(getEntry(data: data, id: id)?.history)
        XCTAssertEqual(history.count, PASSWORD_HISTORY_LIMIT)
        XCTAssertFalse(history.contains { $0.password == "pw-0" })
    }

    /// The whole point of the trash: deleting stopped destroying anything.
    func testDeleteIsReversible() throws {
        let (data, id) = try vaultWithLogin()
        let trashed = try deleteEntry(data: data, id: id)

        XCTAssertEqual(trashed.entries.count, 1)
        XCTAssertNotNil(getEntry(data: trashed, id: id)?.deletedAt)
        XCTAssertEqual(searchEntries(data: trashed, query: "").count, 0, "trashed entries must not appear in the list")
        XCTAssertEqual(trashedEntries(trashed).map(\.id), [id])
        XCTAssertTrue(trashed.tombstones.isEmpty, "a soft delete must not propagate a deletion")

        let restored = try restoreEntry(data: trashed, id: id)
        XCTAssertNil(getEntry(data: restored, id: id)?.deletedAt)
        XCTAssertEqual(searchEntries(data: restored, query: "").count, 1)
    }

    func testPurgeDestroysAndTombstones() throws {
        let (data, id) = try vaultWithLogin()
        let purged = try purgeEntry(data: try deleteEntry(data: data, id: id), id: id)
        XCTAssertTrue(purged.entries.isEmpty)
        XCTAssertEqual(purged.tombstones.map(\.id), [id])
    }

    func testExpiredTrashIsSweptButFreshTrashIsNot() throws {
        let (data, id) = try vaultWithLogin()
        let trashed = try deleteEntry(data: data, id: id)
        let deletedAt = try XCTUnwrap(getEntry(data: trashed, id: id)?.deletedAt)
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let deletedDate = try XCTUnwrap(formatter.date(from: deletedAt))
        let day: TimeInterval = 24 * 60 * 60

        let early = purgeExpiredTrash(
            data: trashed,
            now: deletedDate.addingTimeInterval(Double(TRASH_RETENTION_DAYS - 1) * day)
        )
        XCTAssertEqual(early.entries.count, 1)

        let swept = purgeExpiredTrash(
            data: trashed,
            now: deletedDate.addingTimeInterval(Double(TRASH_RETENTION_DAYS + 1) * day)
        )
        XCTAssertTrue(swept.entries.isEmpty)
        XCTAssertEqual(swept.tombstones.map(\.id), [id])
    }

    /// The merge trap: whole-entry last-write-wins would drop one device's row.
    func testMergeKeepsBothDevicesHistory() throws {
        let (base, id) = try vaultWithLogin(password: "original")
        let onPhone = try updateEntry(data: base, id: id, patch: UpdateEntryPatch(password: "from-the-phone"))
        let onDesktop = try updateEntry(data: base, id: id, patch: UpdateEntryPatch(password: "from-the-desktop"))

        let merged = mergeVaultData(onPhone, onDesktop).data
        let passwords = try XCTUnwrap(merged.entries.first?.history.map(\.password))
        XCTAssertTrue(passwords.contains("original"))
        XCTAssertEqual(Set(passwords).count, passwords.count, "no duplicated rows")

        // Symmetric, like every other merge rule.
        let ab = try VaultJSON.canonicalString(mergeVaultData(onPhone, onDesktop).data)
        let ba = try VaultJSON.canonicalString(mergeVaultData(onDesktop, onPhone).data)
        XCTAssertEqual(ab, ba)
    }
}

final class BreachTests: XCTestCase {
    func testHashForRangeQuerySplitsSha1() {
        // Known SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let query = hashForRangeQuery("password")
        XCTAssertEqual(query.prefix, "5BAA6")
        XCTAssertEqual(query.suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
        XCTAssertEqual(query.prefix.count, 5)
        XCTAssertEqual(query.suffix.count, 35)
    }

    func testCountFromRangeResponse() {
        let body = [
            "0018A45C4D1DEF81644B54AB7F969B88D65:1",
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493",
            "00D4F6E8DA3F211726AA4D1F4656FA666B0:2",
        ].joined(separator: "\n")
        XCTAssertEqual(countFromRangeResponse(body, suffix: "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 3_861_493)
        XCTAssertEqual(countFromRangeResponse(body, suffix: "1e4c9b93f3f0682250b6cf8331b7ee68fd8"), 3_861_493)
        XCTAssertEqual(countFromRangeResponse(body, suffix: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0)
    }
}

final class UrlMatchTests: XCTestCase {
    func testHostMatchAndLookalikeRejected() throws {
        let data = try createEntry(
            data: emptyVaultData(),
            input: EntryInput(title: "GitHub", username: "u", password: "p", urls: ["https://github.com"])
        ).data
        let hits = matchEntriesForAutofill(data: data, pageUrl: "https://github.com/login", mode: .host)
        XCTAssertEqual(hits.count, 1)
        XCTAssertEqual(matchUrl(entryUrl: "https://github.com", pageUrl: "https://github.com.evil.com", mode: .host), .none)
        XCTAssertEqual(matchUrl(entryUrl: "https://github.com", pageUrl: "https://gist.github.com", mode: .subdomain), .subdomain)
    }

    func testWWWAndApexAreEquivalent() {
        XCTAssertEqual(
            matchUrl(entryUrl: "https://reddit.com", pageUrl: "https://www.reddit.com/login", mode: .host),
            .host
        )
        XCTAssertEqual(
            matchUrl(entryUrl: "https://www.reddit.com", pageUrl: "https://reddit.com", mode: .host),
            .host
        )
    }

    func testSubdomainBelowSavedHost() {
        XCTAssertEqual(
            matchUrl(entryUrl: "https://reddit.com", pageUrl: "https://old.reddit.com", mode: .subdomain),
            .subdomain
        )
        XCTAssertEqual(
            matchUrl(entryUrl: "https://old.reddit.com", pageUrl: "https://reddit.com", mode: .subdomain),
            .none
        )
    }

    func testAppBundleIdDoesNotParseAsWebHost() {
        XCTAssertNil(parseTarget("com.reddit.Reddit"))
        XCTAssertEqual(
            matchUrl(entryUrl: "https://reddit.com", pageUrl: "com.reddit.Reddit", mode: .subdomain),
            .none
        )
    }

    func testTrashedNotOffered() throws {
        var data = try createEntry(
            data: emptyVaultData(),
            input: EntryInput(title: "Bank", password: "x", urls: ["https://bank.example"])
        ).data
        let id = data.entries[0].id
        data = try deleteEntry(data: data, id: id)
        XCTAssertTrue(matchEntriesForAutofill(data: data, pageUrl: "https://bank.example").isEmpty)
    }
}
