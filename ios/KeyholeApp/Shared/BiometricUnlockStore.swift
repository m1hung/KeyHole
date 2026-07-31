import Foundation
import LocalAuthentication
import Security

/// Opt-in Face ID / Touch ID unlock.
///
/// When enabled, the master password is stored in the Keychain protected by
/// biometry (`.biometryCurrentSet`) and this-device-only accessibility. It is
/// never written to UserDefaults or the vault file. Disabling biometrics, changing
/// the master password, or deleting the vault clears the Keychain item.
///
/// The Keychain item is shared with AutoFill via a keychain-access-group that
/// matches the App Group (`TEAMID.group.app.keyhole.vault`).
enum BiometricUnlockStore {
    private static let service = "app.keyhole.vault.biometric"
    private static let account = "master-password"
    private static let enabledKey = "keyhole.biometricUnlock.enabled"

    static var isEnabled: Bool {
        get { AppGroup.defaults.bool(forKey: enabledKey) }
        set { AppGroup.defaults.set(newValue, forKey: enabledKey) }
    }

    static var biometryTypeName: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "Biometrics"
        }
    }

    static var canUseBiometrics: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    /// True when the preference is on and a Keychain secret exists.
    static var isReady: Bool {
        isEnabled && hasStoredSecret
    }

    static var hasStoredSecret: Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: false,
            kSecUseAuthenticationContext as String: context,
        ]
        applyAccessGroup(&query)
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        // Interaction required means the item exists but needs biometrics.
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Persist the master password after a successful unlock/enable, gated by biometrics.
    static func enable(storing masterPassword: String) throws {
        try save(masterPassword: masterPassword)
        isEnabled = true
    }

    static func disable() {
        deleteSecret()
        isEnabled = false
    }

    /// Update the stored password after a master-password change (keeps preference).
    static func updateStoredPassword(_ masterPassword: String) throws {
        guard isEnabled else { return }
        try save(masterPassword: masterPassword)
    }

    static func deleteSecret() {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        applyAccessGroup(&query)
        SecItemDelete(query as CFDictionary)
        // Also delete any legacy item stored without an access group.
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ] as CFDictionary)
    }

    /// Prompt Face ID / Touch ID and return the master password, or throw.
    static func unlockMasterPassword(
        reason: String = "Unlock your Keyhole vault"
    ) async throws -> String {
        guard isEnabled else {
            throw BiometricUnlockError.notEnabled
        }
        let context = LAContext()
        context.localizedCancelTitle = "Use Password"
        var laError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError) else {
            throw BiometricUnlockError.unavailable(laError?.localizedDescription ?? "Biometrics unavailable.")
        }

        let ok = try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )
        guard ok else { throw BiometricUnlockError.cancelled }

        return try readSecret(context: context)
    }

    // MARK: - Keychain

    private static func save(masterPassword: String) throws {
        guard let data = masterPassword.data(using: .utf8) else {
            throw BiometricUnlockError.encoding
        }
        deleteSecret()

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &error
        ) else {
            throw BiometricUnlockError.keychain(
                error?.takeRetainedValue().localizedDescription ?? "Could not create Keychain access control."
            )
        }

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access,
        ]
        applyAccessGroup(&query)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw BiometricUnlockError.keychain("Keychain save failed (\(status)).")
        }
    }

    private static func readSecret(context: LAContext) throws -> String {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
        ]
        applyAccessGroup(&query)

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data,
              let password = String(data: data, encoding: .utf8)
        else {
            if status == errSecItemNotFound {
                isEnabled = false
                throw BiometricUnlockError.notEnabled
            }
            throw BiometricUnlockError.keychain("Keychain read failed (\(status)).")
        }
        return password
    }

    private static func applyAccessGroup(_ query: inout [String: Any]) {
        if let group = sharedKeychainAccessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
    }

    /// `TEAMID.group.app.keyhole.vault` when App Groups + keychain-access-groups are live.
    private static var sharedKeychainAccessGroup: String? {
        guard AppGroup.isAvailable, let teamID = bundleSeedID() else { return nil }
        return "\(teamID).\(AppGroup.id)"
    }

    /// Team ID from the default Keychain access group (Apple's bundle-seed trick).
    private static func bundleSeedID() -> String? {
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "keyhole.bundle-seed",
            kSecAttrService as String: "keyhole.bundle-seed",
            kSecReturnAttributes as String: true,
        ]
        var result: CFTypeRef?
        var status = SecItemCopyMatching(probe as CFDictionary, &result)
        if status == errSecItemNotFound {
            status = SecItemAdd(probe as CFDictionary, &result)
        }
        guard status == errSecSuccess,
              let attrs = result as? [String: Any],
              let accessGroup = attrs[kSecAttrAccessGroup as String] as? String,
              let team = accessGroup.split(separator: ".").first
        else {
            return nil
        }
        return String(team)
    }
}

enum BiometricUnlockError: LocalizedError {
    case notEnabled
    case unavailable(String)
    case cancelled
    case encoding
    case keychain(String)

    var errorDescription: String? {
        switch self {
        case .notEnabled:
            return "Biometric unlock is not set up. Unlock with your master password first."
        case .unavailable(let detail):
            return detail
        case .cancelled:
            return "Biometric unlock cancelled."
        case .encoding:
            return "Could not encode master password for Keychain."
        case .keychain(let detail):
            return detail
        }
    }
}
