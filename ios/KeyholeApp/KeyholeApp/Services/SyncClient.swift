import Foundation
import KeyholeCore

public struct SyncConfig: Sendable {
    public var baseUrl: String
    public var accountId: String

    public init(baseUrl: String, accountId: String) {
        self.baseUrl = baseUrl
        self.accountId = accountId
    }
}

public struct SyncClientError: Error, LocalizedError, Sendable {
    public var message: String
    public var status: Int
    public var code: String?

    public init(_ message: String, status: Int, code: String? = nil) {
        self.message = message
        self.status = status
        self.code = code
    }

    public var errorDescription: String? { message }
}

public enum SyncClient {
    private static func authHeader(accountId: String, syncAuthSecretB64: String) -> String {
        let raw = "\(accountId):\(syncAuthSecretB64)"
        let b64 = Data(raw.utf8).base64EncodedString()
        return "Basic \(b64)"
    }

    private static func parseJSON(_ data: Data) throws -> Any? {
        if data.isEmpty { return nil }
        return try JSONSerialization.jsonObject(with: data)
    }

    private static func root(_ baseUrl: String) -> String {
        baseUrl.replacingOccurrences(of: "/+$", with: "", options: .regularExpression)
    }

    public static func healthCheck(baseUrl: String) async -> Bool {
        guard let url = URL(string: "\(root(baseUrl))/api/v1/health") else { return false }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return false }
            guard let obj = try parseJSON(data) as? [String: Any], obj["ok"] as? Bool == true else { return false }
            return true
        } catch {
            return false
        }
    }

    public static func fetchPrelogin(baseUrl: String, accountId: String) async throws -> KdfParams {
        var components = URLComponents(string: "\(root(baseUrl))/api/v1/prelogin")!
        components.queryItems = [URLQueryItem(name: "account", value: accountId)]
        let (data, response) = try await URLSession.shared.data(from: components.url!)
        let http = response as! HTTPURLResponse
        let body = try? JSONDecoder().decode(PreloginBody.self, from: data)
        guard http.statusCode == 200, let kdf = body?.kdf else {
            throw SyncClientError(body?.error ?? "Prelogin failed.", status: http.statusCode)
        }
        try KeyholeCrypto.assertKdfParamsAcceptable(kdf)
        return kdf
    }

    public struct RegisterResult: Decodable, Sendable {
        public var accountId: String
        public var version: Int
        public var updatedAt: String
    }

    public static func registerAccount(
        baseUrl: String,
        accountId: String,
        authSecretB64: String,
        envelope: VaultFile
    ) async throws -> RegisterResult {
        let url = URL(string: "\(root(baseUrl))/api/v1/account")!
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let payload = RegisterBody(accountId: accountId, authSecret: authSecretB64, envelope: envelope)
        req.httpBody = try JSONEncoder().encode(payload)
        let (data, response) = try await URLSession.shared.data(for: req)
        let http = response as! HTTPURLResponse
        if http.statusCode == 409 {
            let err = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error
            throw SyncClientError(err ?? "That account already exists.", status: 409)
        }
        guard http.statusCode >= 200, http.statusCode < 300 else {
            let err = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error
            throw SyncClientError(err ?? "Registration failed.", status: http.statusCode)
        }
        return try JSONDecoder().decode(RegisterResult.self, from: data)
    }

    public struct VaultRemote: Sendable {
        public var envelope: VaultFile
        public var version: Int
        public var updatedAt: String
    }

    public static func getVault(
        baseUrl: String,
        accountId: String,
        syncAuthSecretB64: String
    ) async throws -> VaultRemote {
        let url = URL(string: "\(root(baseUrl))/api/v1/vault")!
        var req = URLRequest(url: url)
        req.setValue(authHeader(accountId: accountId, syncAuthSecretB64: syncAuthSecretB64), forHTTPHeaderField: "Authorization")
        let (data, response) = try await URLSession.shared.data(for: req)
        let http = response as! HTTPURLResponse
        if http.statusCode == 429 {
            throw SyncClientError("Too many attempts. Try again shortly.", status: 429)
        }
        if http.statusCode == 401 {
            throw SyncClientError(
                "Unauthorized — wrong master password for this account, or the account was registered from a different vault. Use Register & upload on first enroll, or import that vault into this device.",
                status: 401
            )
        }
        guard http.statusCode >= 200, http.statusCode < 300 else {
            let err = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error
            throw SyncClientError(err ?? "Could not fetch vault.", status: http.statusCode)
        }
        let body = try JSONDecoder().decode(VaultRemoteBody.self, from: data)
        return VaultRemote(envelope: body.envelope, version: body.version, updatedAt: body.updatedAt)
    }

    public enum PutVaultResponse: Sendable {
        case ok(version: Int, updatedAt: String)
        case conflict(version: Int, envelope: VaultFile, updatedAt: String)
    }

    public static func putVault(
        baseUrl: String,
        accountId: String,
        syncAuthSecretB64: String,
        envelope: VaultFile,
        expectedVersion: Int,
        nextAuthSecretB64: String? = nil
    ) async throws -> PutVaultResponse {
        let url = URL(string: "\(root(baseUrl))/api/v1/vault")!
        var req = URLRequest(url: url)
        req.httpMethod = "PUT"
        req.setValue(authHeader(accountId: accountId, syncAuthSecretB64: syncAuthSecretB64), forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = PutBody(envelope: envelope, expectedVersion: expectedVersion, authSecret: nextAuthSecretB64)
        req.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await URLSession.shared.data(for: req)
        let http = response as! HTTPURLResponse

        if http.statusCode == 409,
           let conflict = try? JSONDecoder().decode(VaultRemoteBody.self, from: data)
        {
            return .conflict(version: conflict.version, envelope: conflict.envelope, updatedAt: conflict.updatedAt)
        }
        if http.statusCode == 429 {
            throw SyncClientError("Too many attempts. Try again shortly.", status: 429)
        }
        if http.statusCode == 401 {
            throw SyncClientError(
                "Unauthorized — wrong master password for this account, or the account was registered from a different vault.",
                status: 401
            )
        }
        guard http.statusCode >= 200, http.statusCode < 300 else {
            let err = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error
            throw SyncClientError(err ?? "Upload failed.", status: http.statusCode)
        }
        let ok = try JSONDecoder().decode(PutOkBody.self, from: data)
        return .ok(version: ok.version, updatedAt: ok.updatedAt)
    }

    // MARK: - Bodies

    private struct PreloginBody: Decodable {
        var kdf: KdfParams?
        var error: String?
    }

    private struct ErrorBody: Decodable {
        var error: String?
    }

    private struct RegisterBody: Encodable {
        var accountId: String
        var authSecret: String
        var envelope: VaultFile
    }

    private struct VaultRemoteBody: Decodable {
        var envelope: VaultFile
        var version: Int
        var updatedAt: String
    }

    private struct PutBody: Encodable {
        var envelope: VaultFile
        var expectedVersion: Int
        var authSecret: String?
    }

    private struct PutOkBody: Decodable {
        var version: Int
        var updatedAt: String
    }
}

public struct PerformSyncResult: Sendable {
    public var file: VaultFile
    public var session: VaultSession
    public var message: String
}

public enum RunSync {
    private static let maxRetries = 4

    private static func readRemoteData(
        envelope: VaultFile,
        session: VaultSession,
        masterPassword: String?
    ) throws -> VaultData {
        if envelope.vaultId == session.vaultId {
            do {
                return try openVaultWithKey(file: envelope, vaultKey: session.key)
            } catch {
                // Fall through
            }
        }
        guard let masterPassword, !masterPassword.isEmpty else {
            throw SyncClientError("Master password required to open the remote vault.", status: 401)
        }
        return try unlockVault(file: envelope, masterPassword: masterPassword).data
    }

    public static func performSync(
        baseUrl: String,
        accountId: String,
        syncAuthSecretB64: String,
        masterPassword: String?,
        localFile: VaultFile,
        session: VaultSession
    ) async throws -> PerformSyncResult {
        var remote = try await SyncClient.getVault(
            baseUrl: baseUrl,
            accountId: accountId,
            syncAuthSecretB64: syncAuthSecretB64
        )

        if remote.envelope.vaultId != localFile.vaultId {
            throw SyncClientError(
                "Remote vault id differs from this device. Refusing to merge two distinct vaults.",
                status: 409,
                code: "vault_mismatch"
            )
        }

        var workingSession = session
        var file = localFile
        var expectedVersion = remote.version

        let remoteData = try readRemoteData(
            envelope: remote.envelope,
            session: workingSession,
            masterPassword: masterPassword
        )
        let merged = mergeVaultData(workingSession.data, remoteData)
        workingSession.data = merged.data
        file = try saveVault(session: &workingSession, previous: file)

        for _ in 0..<maxRetries {
            let response = try await SyncClient.putVault(
                baseUrl: baseUrl,
                accountId: accountId,
                syncAuthSecretB64: syncAuthSecretB64,
                envelope: file,
                expectedVersion: expectedVersion
            )
            switch response {
            case .ok(let version, _):
                var parts = ["\(merged.stats.entriesKept) entries kept"]
                if merged.stats.entriesDeleted > 0 {
                    parts.append("\(merged.stats.entriesDeleted) deleted remotely")
                }
                if merged.stats.entriesReconciled > 0 {
                    parts.append("\(merged.stats.entriesReconciled) reconciled")
                }
                return PerformSyncResult(
                    file: file,
                    session: workingSession,
                    message: "Synced with server (v\(version)). \(parts.joined(separator: "; "))."
                )
            case .conflict(let version, let envelope, let updatedAt):
                remote = SyncClient.VaultRemote(envelope: envelope, version: version, updatedAt: updatedAt)
                expectedVersion = version
                let conflictData = try readRemoteData(
                    envelope: remote.envelope,
                    session: workingSession,
                    masterPassword: masterPassword
                )
                let remerged = mergeVaultData(workingSession.data, conflictData)
                workingSession.data = remerged.data
                file = try saveVault(session: &workingSession, previous: file)
            }
        }
        throw SyncClientError("Sync failed.", status: 500)
    }

    /// Replace this device's vault with the account's server copy (vault-id mismatch recovery).
    public static func adoptRemote(
        baseUrl: String,
        accountId: String,
        masterPassword: String
    ) async throws -> (file: VaultFile, session: VaultSession, syncAuthSecretB64: String, message: String) {
        let kdf = try await SyncClient.fetchPrelogin(baseUrl: baseUrl, accountId: accountId)
        let derived = try await Task.detached(priority: .userInitiated) {
            try KeyholeCrypto.deriveSyncAuthSecret(masterPassword: masterPassword, params: kdf)
        }.value
        let remote = try await SyncClient.getVault(
            baseUrl: baseUrl,
            accountId: accountId,
            syncAuthSecretB64: derived
        )
        let remoteSession = try await Task.detached(priority: .userInitiated) {
            try unlockVault(file: remote.envelope, masterPassword: masterPassword)
        }.value
        return (
            remote.envelope,
            remoteSession,
            derived,
            "Replaced this device's vault with the server copy (v\(remote.version))."
        )
    }

    /// Overwrite the server account with this device's vault and rotate sync credentials.
    public static func overwriteRemote(
        baseUrl: String,
        accountId: String,
        masterPassword: String,
        localFile: VaultFile
    ) async throws -> (syncAuthSecretB64: String, message: String) {
        // Confirm the password unlocks the local vault before touching the server.
        _ = try await Task.detached(priority: .userInitiated) {
            try unlockVault(file: localFile, masterPassword: masterPassword)
        }.value

        let accountKdf = try await SyncClient.fetchPrelogin(baseUrl: baseUrl, accountId: accountId)
        let currentSecret = try await Task.detached(priority: .userInitiated) {
            try KeyholeCrypto.deriveSyncAuthSecret(masterPassword: masterPassword, params: accountKdf)
        }.value
        let nextSecret = try await Task.detached(priority: .userInitiated) {
            try KeyholeCrypto.deriveSyncAuthSecret(masterPassword: masterPassword, params: localFile.kdf)
        }.value
        let remote = try await SyncClient.getVault(
            baseUrl: baseUrl,
            accountId: accountId,
            syncAuthSecretB64: currentSecret
        )
        let uploaded = try await SyncClient.putVault(
            baseUrl: baseUrl,
            accountId: accountId,
            syncAuthSecretB64: currentSecret,
            envelope: localFile,
            expectedVersion: remote.version,
            nextAuthSecretB64: nextSecret
        )
        switch uploaded {
        case .ok(let version, _):
            return (nextSecret, "Replaced the server vault with this device's copy (v\(version)).")
        case .conflict:
            throw SyncClientError("Server changed during overwrite. Try again.", status: 409)
        }
    }
}
