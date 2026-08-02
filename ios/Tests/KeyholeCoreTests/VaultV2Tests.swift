import XCTest
@testable import KeyholeCore

/// Format-2 vaults on the Swift side, and the cross-implementation vectors.
///
/// The invariant defended here is not "the crypto works" — it is "nobody is ever
/// locked out of a vault they still hold the credentials for", and, additionally,
/// "a vault written on one platform opens on the other". The second is why
/// `CrossImplementationVectorTests` exists: `core/` and this package are independent
/// implementations of one format, and nothing in either build system would notice
/// them drifting apart.

private let password = "correct horse battery staple"
private let newPassword = "a different sufficiently long password"

private func makeV2() throws -> (file: VaultFile, kit: RecoveryKit) {
    var created = try createVaultWithRecoveryKit(masterPassword: password)
    let entry = try createEntry(data: created.session.data, input: EntryInput(title: "GitHub", password: "hunter2"))
    created.session.data = entry.data
    let file = try saveVault(session: &created.session, previous: created.file)
    return (file, created.kit)
}

// ---------------------------------------------------------------------------

final class SecretKeyCodingTests: XCTestCase {
    func testRoundTripsEveryByteValue() throws {
        for _ in 0..<100 {
            let raw = SecretKeyCoding.generateSecretKeyBytes()
            let formatted = try SecretKeyCoding.formatSecret(.secretKey, raw)
            XCTAssertEqual(try SecretKeyCoding.parseSecret(.secretKey, formatted), raw)
        }
    }

    func testRoundTripsExtremes() throws {
        for raw in [[UInt8](repeating: 0, count: 16), [UInt8](repeating: 0xff, count: 16)] {
            let formatted = try SecretKeyCoding.formatSecret(.recoveryCode, raw)
            XCTAssertEqual(try SecretKeyCoding.parseSecret(.recoveryCode, formatted), raw)
        }
    }

    func testGroupedPrefixedRendering() throws {
        let formatted = try SecretKeyCoding.formatSecret(.secretKey, [UInt8](repeating: 7, count: 16))
        XCTAssertTrue(formatted.hasPrefix("KH2SK-"))
        XCTAssertEqual(formatted.split(separator: "-").count, 8) // prefix + 7 groups
    }

    func testToleratesTranscriptionArtefacts() throws {
        let raw = SecretKeyCoding.generateSecretKeyBytes()
        let formatted = try SecretKeyCoding.formatSecret(.secretKey, raw)
        for variant in [
            formatted.lowercased(),
            formatted.replacingOccurrences(of: "-", with: ""),
            "  \(formatted)\n",
        ] {
            XCTAssertEqual(try SecretKeyCoding.parseSecret(.secretKey, variant), raw)
        }
    }

    func testFoldsConfusableGlyphs() throws {
        let raw = [UInt8](repeating: 0, count: 16)
        let canonical = try SecretKeyCoding.formatSecret(.secretKey, raw)
        let confused = canonical.replacingOccurrences(of: "0", with: "O")
        XCTAssertNotEqual(confused, canonical)
        XCTAssertEqual(try SecretKeyCoding.parseSecret(.secretKey, confused), raw)
    }

    func testNamesTheSwappedKitHalves() throws {
        let raw = SecretKeyCoding.generateSecretKeyBytes()
        let recovery = try SecretKeyCoding.formatSecret(.recoveryCode, raw)
        XCTAssertThrowsError(try SecretKeyCoding.parseSecret(.secretKey, recovery)) { err in
            XCTAssertTrue("\(err)".contains("Recovery Code"), "got \(err)")
        }
    }

    func testReportsATypoAsATypo() throws {
        // The whole point of the checksum: otherwise this is indistinguishable from a
        // wrong master password.
        let formatted = try SecretKeyCoding.formatSecret(.secretKey, SecretKeyCoding.generateSecretKeyBytes())
        let last = formatted.last!
        let mutated = formatted.dropLast() + (last == "0" ? "9" : "0")
        XCTAssertThrowsError(try SecretKeyCoding.parseSecret(.secretKey, String(mutated))) { err in
            XCTAssertTrue("\(err)".contains("typo"), "got \(err)")
        }
    }
}

// ---------------------------------------------------------------------------

final class VaultV2UnlockTests: XCTestCase {
    func testFormatOneStillOpensWithPasswordAlone() throws {
        let created = try createVault(masterPassword: password)
        XCTAssertEqual(created.file.formatVersion, 1)
        XCTAssertFalse(vaultRequiresSecretKey(created.file))
        XCTAssertNoThrow(try unlockVault(file: created.file, masterPassword: password))
    }

    func testRefusesASecretKeyItHasNoUseFor() throws {
        let created = try createVault(masterPassword: password)
        let v2 = try makeV2()
        XCTAssertThrowsError(
            try unlockVault(file: created.file, masterPassword: password, secretKey: v2.kit.secretKey)
        ) { err in
            XCTAssertTrue("\(err)".contains("does not use a Secret Key"), "got \(err)")
        }
    }

    func testOpensWithPasswordAndSecretKey() throws {
        let v2 = try makeV2()
        XCTAssertEqual(v2.file.formatVersion, 2)
        XCTAssertTrue(vaultHasRecoveryKit(v2.file))
        let session = try unlockVault(file: v2.file, masterPassword: password, secretKey: v2.kit.secretKey)
        XCTAssertEqual(session.data.entries.first?.password, "hunter2")
    }

    func testNamesTheMissingSecretKeyRatherThanBlamingThePassword() throws {
        let v2 = try makeV2()
        XCTAssertThrowsError(try unlockVault(file: v2.file, masterPassword: password)) { err in
            XCTAssertTrue("\(err)".contains("needs its Secret Key"), "got \(err)")
        }
    }

    func testRefusesTheWrongSecretKey() throws {
        let v2 = try makeV2()
        let other = try makeV2()
        XCTAssertThrowsError(
            try unlockVault(file: v2.file, masterPassword: password, secretKey: other.kit.secretKey)
        ) { err in
            guard let kh = err as? KeyholeError, case .decryption = kh else {
                return XCTFail("Expected decryption error, got \(err)")
            }
        }
    }

    func testRefusesTheWrongPassword() throws {
        let v2 = try makeV2()
        XCTAssertThrowsError(
            try unlockVault(file: v2.file, masterPassword: "not the master password", secretKey: v2.kit.secretKey)
        ) { err in
            guard let kh = err as? KeyholeError, case .decryption = kh else {
                return XCTFail("Expected decryption error, got \(err)")
            }
        }
    }
}

// ---------------------------------------------------------------------------

final class VaultV2RecoveryTests: XCTestCase {
    func testOpensWithTheRecoveryCodeAlone() throws {
        let v2 = try makeV2()
        let session = try unlockWithRecoveryCode(file: v2.file, recoveryCode: v2.kit.recoveryCode)
        XCTAssertEqual(session.data.entries.first?.password, "hunter2")
    }

    func testRefusesARecoveryCodeFromAnotherVault() throws {
        let v2 = try makeV2()
        let other = try makeV2()
        XCTAssertThrowsError(
            try unlockWithRecoveryCode(file: v2.file, recoveryCode: other.kit.recoveryCode)
        ) { err in
            guard let kh = err as? KeyholeError, case .decryption = kh else {
                return XCTFail("Expected decryption error, got \(err)")
            }
        }
    }

    func testRestoresAVaultWhoseMasterPasswordIsGone() throws {
        let v2 = try makeV2()
        let recovered = try recoverWithKit(file: v2.file, recoveryCode: v2.kit.recoveryCode, newPassword: newPassword)

        XCTAssertEqual(recovered.session.data.entries.first?.password, "hunter2")
        XCTAssertNoThrow(
            try unlockVault(file: recovered.file, masterPassword: newPassword, secretKey: recovered.kit.secretKey)
        )
        XCTAssertNotEqual(recovered.kit.secretKey, v2.kit.secretKey)
        XCTAssertThrowsError(try unlockWithRecoveryCode(file: recovered.file, recoveryCode: v2.kit.recoveryCode))
    }
}

// ---------------------------------------------------------------------------

/// The bug guarded against here is silent: the vault keeps working perfectly and only
/// the recovery path is dead, so nothing surfaces it until the one moment the user has
/// nothing else left to try.
final class VaultV2PasswordChangeTests: XCTestCase {
    func testReissuesTheKitAndRetiresTheOldOne() throws {
        let original = try makeV2()
        let changed = try changeMasterPassword(
            file: original.file,
            currentPassword: password,
            newPassword: newPassword,
            secretKey: original.kit.secretKey
        )

        let kit = try XCTUnwrap(changed.kit)
        XCTAssertNotEqual(kit.recoveryCode, original.kit.recoveryCode)

        // The replacement opens the vault...
        let session = try unlockWithRecoveryCode(file: changed.file, recoveryCode: kit.recoveryCode)
        XCTAssertEqual(session.data.entries.first?.password, "hunter2")

        // ...and the printout it replaced does not.
        XCTAssertThrowsError(try unlockWithRecoveryCode(file: changed.file, recoveryCode: original.kit.recoveryCode))
    }

    func testKeepsTheSecretKeyAndTheEnvelopeVersion() throws {
        let original = try makeV2()
        let changed = try changeMasterPassword(
            file: original.file,
            currentPassword: password,
            newPassword: newPassword,
            secretKey: original.kit.secretKey
        )
        XCTAssertEqual(try XCTUnwrap(changed.kit).secretKey, original.kit.secretKey)
        XCTAssertEqual(changed.file.formatVersion, 2)
    }

    func testDoesNotSilentlyUpgradeAFormatOneVault() throws {
        // Regression: this hardcoded FORMAT_VERSION, which was harmless while that was
        // 1 and would now convert the vault into one demanding a Secret Key nobody has.
        let created = try createVault(masterPassword: password)
        let changed = try changeMasterPassword(
            file: created.file,
            currentPassword: password,
            newPassword: newPassword
        )
        XCTAssertEqual(changed.file.formatVersion, 1)
        XCTAssertNil(changed.kit)
        XCTAssertNoThrow(try unlockVault(file: changed.file, masterPassword: newPassword))
    }
}

// ---------------------------------------------------------------------------

final class VaultV2UpgradeTests: XCTestCase {
    func testBindsAFormatOneVaultAndKeepsItsEntries() throws {
        var created = try createVault(masterPassword: password)
        let entry = try createEntry(data: created.session.data, input: EntryInput(title: "Bank", password: "swordfish"))
        created.session.data = entry.data
        let v1 = try saveVault(session: &created.session, previous: created.file)

        let upgraded = try upgradeToV2(file: v1, masterPassword: password)
        XCTAssertEqual(upgraded.file.formatVersion, 2)
        XCTAssertTrue(vaultHasRecoveryKit(upgraded.file))

        let session = try unlockVault(
            file: upgraded.file,
            masterPassword: password,
            secretKey: upgraded.kit.secretKey
        )
        XCTAssertEqual(session.data.entries.first?.password, "swordfish")
    }

    func testRotatesTheVekSoAStolenPreUpgradeCopyDoesNotFollowItForward() throws {
        let created = try createVault(masterPassword: password)
        let upgraded = try upgradeToV2(file: created.file, masterPassword: password)
        XCTAssertEqual(upgraded.file.vaultId, created.file.vaultId)
        XCTAssertNotEqual(upgraded.file.wrappedKey.ctB64, created.file.wrappedKey.ctB64)
        XCTAssertNotEqual(upgraded.file.payload.ctB64, created.file.payload.ctB64)
    }

    func testRefusesAnAlreadyBoundVault() throws {
        let v2 = try makeV2()
        XCTAssertThrowsError(try upgradeToV2(file: v2.file, masterPassword: password))
    }
}

// ---------------------------------------------------------------------------

final class VaultV2TamperingTests: XCTestCase {
    func testRejectsAFormatOneEnvelopeCarryingARecoveryKit() throws {
        var file = try makeV2().file
        file.formatVersion = 1
        XCTAssertThrowsError(try parseVaultFile(file)) { err in
            XCTAssertTrue("\(err)".contains("cannot carry a Recovery Kit"), "got \(err)")
        }
    }

    func testRejectsHalfARecoveryKit() throws {
        var file = try makeV2().file
        file.recoveryWrappedKey = nil
        XCTAssertThrowsError(try parseVaultFile(file)) { err in
            XCTAssertTrue("\(err)".contains("incomplete Recovery Kit"), "got \(err)")
        }
    }

    func testRefusesADowngradedEnvelopeRatherThanAcceptingWeakerDerivation() throws {
        var file = try makeV2().file
        file.recoveryKdf = nil
        file.recoveryWrappedKey = nil
        file.formatVersion = 1
        XCTAssertThrowsError(try unlockVault(file: file, masterPassword: password)) { err in
            guard let kh = err as? KeyholeError, case .decryption = kh else {
                return XCTFail("Expected decryption error, got \(err)")
            }
        }
    }
}

// ---------------------------------------------------------------------------

/// One format, two independent implementations. These are the only tests that would
/// notice them drifting apart.
final class CrossImplementationVectorTests: XCTestCase {
    private struct Fixture: Decodable {
        let masterPassword: String
        let secretKey: String
        let recoveryCode: String
        let entryPassword: String
        let vault: VaultFile
    }

    private func loadTSFixture() throws -> Fixture {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "ts-v2-vault", withExtension: "json", subdirectory: "Fixtures")
                ?? Bundle.module.url(forResource: "ts-v2-vault", withExtension: "json"),
            "ts-v2-vault.json missing — regenerate with core/harness/make-v2-fixture.ts"
        )
        return try JSONDecoder().decode(Fixture.self, from: try Data(contentsOf: url))
    }

    func testOpensAFormatTwoVaultWrittenByTypeScript() throws {
        let fixture = try loadTSFixture()
        XCTAssertEqual(fixture.vault.formatVersion, 2)

        let session = try unlockVault(
            file: fixture.vault,
            masterPassword: fixture.masterPassword,
            secretKey: fixture.secretKey
        )
        XCTAssertEqual(session.data.entries.first?.password, fixture.entryPassword)
        XCTAssertEqual(session.data.entries.first?.username, "vector@example.com")
    }

    func testRecoversAFormatTwoVaultWrittenByTypeScript() throws {
        // Proves the recovery wrap, its separate KDF params and its AAD template all
        // agree across implementations — none of which the unlock path exercises.
        let fixture = try loadTSFixture()
        let session = try unlockWithRecoveryCode(file: fixture.vault, recoveryCode: fixture.recoveryCode)
        XCTAssertEqual(session.data.entries.first?.password, fixture.entryPassword)
    }

    func testRejectsTheTypeScriptVaultWithoutItsSecretKey() throws {
        let fixture = try loadTSFixture()
        XCTAssertThrowsError(try unlockVault(file: fixture.vault, masterPassword: fixture.masterPassword))
    }

    /// Emits the Swift-written half of the vector pair for the TypeScript suite to
    /// open. Guarded so ordinary runs never dirty the tree:
    ///
    ///   KEYHOLE_WRITE_VECTORS=1 swift test --filter testEmitSwiftVector
    func testEmitSwiftVector() throws {
        guard ProcessInfo.processInfo.environment["KEYHOLE_WRITE_VECTORS"] == "1" else {
            throw XCTSkip("Set KEYHOLE_WRITE_VECTORS=1 to regenerate the Swift-written vector.")
        }

        var created = try createVaultWithRecoveryKit(masterPassword: "interop-fixture-master-password")
        let entry = try createEntry(
            data: created.session.data,
            input: EntryInput(
                title: "Interop",
                username: "vector@example.com",
                password: "written-by-swift",
                urls: ["https://example.com/login"]
            )
        )
        created.session.data = entry.data
        let file = try saveVault(session: &created.session, previous: created.file)

        let payload: [String: Any] = [
            "note": "Generated by VaultV2Tests.testEmitSwiftVector. Credentials below are not secret.",
            "masterPassword": "interop-fixture-master-password",
            "secretKey": created.kit.secretKey,
            "recoveryCode": created.kit.recoveryCode,
            "entryPassword": "written-by-swift",
            "vault": try JSONSerialization.jsonObject(with: try JSONEncoder().encode(file)),
        ]
        let out = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // .../ios/Tests/KeyholeCoreTests
            .deletingLastPathComponent() // .../ios/Tests
            .deletingLastPathComponent() // .../ios
            .deletingLastPathComponent() // repo root
            .appendingPathComponent("core/test/fixtures/swift-v2-vault.json")
        try FileManager.default.createDirectory(
            at: out.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try JSONSerialization
            .data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            .write(to: out)
        print("Wrote \(out.path)")
        print("  secretKey:    \(created.kit.secretKey)")
        print("  recoveryCode: \(created.kit.recoveryCode)")
    }
}
