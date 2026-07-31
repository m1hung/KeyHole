import AuthenticationServices
import Foundation
import KeyholeCore

/// Publishes username + site identities into Apple's credential identity store so
/// Keyhole appears in the QuickType bar above the keyboard.
///
/// Identities never include passwords or private keys — only service URL/domain,
/// username / passkey metadata, and the vault entry id (`recordIdentifier`) so
/// AutoFill can resolve the secret after unlock.
enum QuickTypeCredentialStore {
    struct PublishResult: Equatable {
        var enabled: Bool
        var count: Int
        var errorMessage: String?
    }

    static func passwordIdentities(from data: VaultData) -> [ASPasswordCredentialIdentity] {
        var out: [ASPasswordCredentialIdentity] = []
        for entry in liveEntries(data) where entry.kind == .login {
            let user = entry.username
            guard !user.isEmpty else { continue }
            var seenHosts = Set<String>()
            for raw in entry.urls {
                guard let target = parseTarget(raw) else { continue }
                let host = target.hostname
                guard seenHosts.insert(host).inserted else { continue }

                out.append(
                    ASPasswordCredentialIdentity(
                        serviceIdentifier: ASCredentialServiceIdentifier(
                            identifier: host,
                            type: .domain
                        ),
                        user: user,
                        recordIdentifier: entry.id
                    )
                )
                out.append(
                    ASPasswordCredentialIdentity(
                        serviceIdentifier: ASCredentialServiceIdentifier(
                            identifier: target.origin,
                            type: .URL
                        ),
                        user: user,
                        recordIdentifier: entry.id
                    )
                )
            }
        }
        return out
    }

    static func passkeyIdentities(from data: VaultData) -> [ASPasskeyCredentialIdentity] {
        var out: [ASPasskeyCredentialIdentity] = []
        for entry in liveEntries(data) {
            for pk in entry.passkeys {
                guard let credentialId = Data(base64Encoded: pk.credentialIdB64),
                      let userHandle = Data(base64Encoded: pk.userHandleB64)
                else { continue }
                out.append(
                    ASPasskeyCredentialIdentity(
                        relyingPartyIdentifier: pk.relyingPartyId,
                        userName: pk.userName.isEmpty ? entry.title : pk.userName,
                        credentialID: credentialId,
                        userHandle: userHandle,
                        recordIdentifier: "\(entry.id):\(pk.id)"
                    )
                )
            }
        }
        return out
    }

    /// Replace the system identity store with the current unlocked vault.
    @discardableResult
    static func publish(from data: VaultData) async -> PublishResult {
        let passwords = passwordIdentities(from: data)
        let passkeys = passkeyIdentities(from: data)
        let identities: [any ASCredentialIdentity] = passwords + passkeys
        let state = await storeState()
        guard state.isEnabled else {
            return PublishResult(
                enabled: false,
                count: 0,
                errorMessage: "Turn on Keyhole under AutoFill & Passwords in iPhone Settings."
            )
        }
        do {
            try await replaceIdentities(identities)
            return PublishResult(enabled: true, count: identities.count, errorMessage: nil)
        } catch {
            return PublishResult(enabled: true, count: 0, errorMessage: error.localizedDescription)
        }
    }

    static func clear() async {
        let state = await storeState()
        guard state.isEnabled else { return }
        try? await removeAll()
    }

    // MARK: - ASCredentialIdentityStore wrappers

    private static func storeState() async -> ASCredentialIdentityStoreState {
        await withCheckedContinuation { cont in
            ASCredentialIdentityStore.shared.getState { state in
                cont.resume(returning: state)
            }
        }
    }

    private static func replaceIdentities(_ identities: [any ASCredentialIdentity]) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities) { success, error in
                if let error {
                    cont.resume(throwing: error)
                } else if success {
                    cont.resume()
                } else {
                    cont.resume(throwing: QuickTypeStoreError("Couldn’t update keyboard suggestions."))
                }
            }
        }
    }

    private static func removeAll() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            ASCredentialIdentityStore.shared.removeAllCredentialIdentities { success, error in
                if let error {
                    cont.resume(throwing: error)
                } else if success {
                    cont.resume()
                } else {
                    cont.resume(throwing: QuickTypeStoreError("Couldn’t clear keyboard suggestions."))
                }
            }
        }
    }
}

private struct QuickTypeStoreError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
