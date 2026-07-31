import CryptoKit
import Foundation

// MARK: - Authenticator flags (WebAuthn §6.1)

struct AuthenticatorFlags: OptionSet {
    let rawValue: UInt8

    static let userPresent = AuthenticatorFlags(rawValue: 1 << 0)
    static let userVerified = AuthenticatorFlags(rawValue: 1 << 2)
    static let backupEligible = AuthenticatorFlags(rawValue: 1 << 3)
    static let backedUp = AuthenticatorFlags(rawValue: 1 << 4)
    static let attestedCredentialData = AuthenticatorFlags(rawValue: 1 << 6)

    static let registration: AuthenticatorFlags = [
        .userPresent, .userVerified, .backupEligible, .backedUp, .attestedCredentialData,
    ]
    static let assertion: AuthenticatorFlags = [
        .userPresent, .userVerified, .backupEligible, .backedUp,
    ]
}

// MARK: - COSE EC2 public key

enum WebAuthnCrypto {
    /// COSE_Key for P-256 (kty=2, alg=-7, crv=1, x, y).
    static func coseKey(from publicKey: P256.Signing.PublicKey) -> Data {
        let raw = publicKey.rawRepresentation
        precondition(raw.count == 64)
        let x = raw.prefix(32)
        let y = raw.suffix(32)
        let bytes = MiniCBOR.encodeMap([
            (MiniCBOR.encodeUnsigned(1), MiniCBOR.encodeUnsigned(2)), // kty: EC2
            (MiniCBOR.encodeUnsigned(3), MiniCBOR.encodeNegative(-7)), // alg: ES256
            (MiniCBOR.encodeNegative(-1), MiniCBOR.encodeUnsigned(1)), // crv: P-256
            (MiniCBOR.encodeNegative(-2), MiniCBOR.encodeBytes(Data(x))),
            (MiniCBOR.encodeNegative(-3), MiniCBOR.encodeBytes(Data(y))),
        ])
        return Data(bytes)
    }

    static func authenticatorData(
        relyingPartyId: String,
        flags: AuthenticatorFlags,
        signCount: UInt32,
        attestedCredentialData: Data? = nil
    ) -> Data {
        var out = Data()
        out.append(contentsOf: SHA256.hash(data: Data(relyingPartyId.utf8)))
        out.append(flags.rawValue)
        out.append(UInt8((signCount >> 24) & 0xff))
        out.append(UInt8((signCount >> 16) & 0xff))
        out.append(UInt8((signCount >> 8) & 0xff))
        out.append(UInt8(signCount & 0xff))
        if let attestedCredentialData {
            out.append(attestedCredentialData)
        }
        return out
    }

    static func attestedCredentialData(credentialId: Data, publicKey: P256.Signing.PublicKey) -> Data {
        var out = Data(repeating: 0, count: 16) // AAGUID (zeros for software authenticator)
        let idLen = UInt16(credentialId.count)
        out.append(UInt8((idLen >> 8) & 0xff))
        out.append(UInt8(idLen & 0xff))
        out.append(credentialId)
        out.append(coseKey(from: publicKey))
        return out
    }

    /// Attestation object with fmt="none" (CBOR map).
    static func noneAttestationObject(authenticatorData: Data) -> Data {
        let bytes = MiniCBOR.encodeMap([
            (MiniCBOR.encodeText("fmt"), MiniCBOR.encodeText("none")),
            (MiniCBOR.encodeText("attStmt"), MiniCBOR.encodeEmptyMap()),
            (MiniCBOR.encodeText("authData"), MiniCBOR.encodeBytes(authenticatorData)),
        ])
        return Data(bytes)
    }

    static func buildRegistration(
        relyingPartyId: String,
        privateKey: P256.Signing.PrivateKey,
        credentialId: Data
    ) -> Data {
        let attested = attestedCredentialData(credentialId: credentialId, publicKey: privateKey.publicKey)
        let authData = authenticatorData(
            relyingPartyId: relyingPartyId,
            flags: .registration,
            signCount: 0,
            attestedCredentialData: attested
        )
        return noneAttestationObject(authenticatorData: authData)
    }

    static func buildAssertion(
        relyingPartyId: String,
        clientDataHash: Data,
        signCount: UInt32,
        privateKey: P256.Signing.PrivateKey
    ) throws -> (authenticatorData: Data, signature: Data) {
        let authData = authenticatorData(
            relyingPartyId: relyingPartyId,
            flags: .assertion,
            signCount: signCount
        )
        var toSign = authData
        toSign.append(clientDataHash)
        let signature = try privateKey.signature(for: toSign)
        return (authData, signature.derRepresentation)
    }

    static func generateCredentialId(byteCount: Int = 16) -> Data {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
}
