// Offline RS256 JWT verification.
//
// SDK MUST reject `alg: none`, `HS256`, `HS384`, `HS512`. ONLY `RS256` is
// accepted. The header's `alg` is read ONLY to reject anything that is not
// RS256 — it NEVER selects a verifier, which is the alg-confusion defence.
// `RS256` is
// hardcoded (RFC 9068).
//
// `aud` accepts BOTH scalar string AND array form per RFC 7519 §4.1.3.
// `nbf` is validated only if present (RFC 7519 §4.1.5).

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Crypto)
import Crypto
#endif
#if canImport(Security)
import Security
#endif

struct JWTHeader: Sendable, Codable {
    let alg: String?
    let kid: String?
    let typ: String?
}

struct JWTPayload: Sendable {
    let iss: String?
    let sub: String?
    let aud: [String]
    let exp: Date?
    let nbf: Date?
    let iat: Date?
    let jti: String?
    let raw: [String: AnyClaim]
}

struct VerifiedJWT: Sendable {
    let header: JWTHeader
    let payload: JWTPayload
    let user: User
}

enum JWTVerifier {
    /// Verify `token` using JWKS. Throws `SdkError` on failure.
    /// `expectedIssuer` and `expectedAudience` are checked on the payload.
    /// `now` is wall-clock with skew already subtracted by caller.
    static func verify(
        token: String,
        jwks: JWKSet,
        expectedIssuer: URL,
        expectedAudience: String?,
        now: Date = Date()
    ) throws -> VerifiedJWT {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwt_malformed"
            )
        }
        let headerData = base64URLDecode(String(parts[0]))
        let payloadData = base64URLDecode(String(parts[1]))
        let signatureData = base64URLDecode(String(parts[2]))
        guard let headerData, let payloadData, let signatureData else {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwt_b64_decode_failed"
            )
        }

        let header = try JSONDecoder().decode(JWTHeader.self, from: headerData)
        // SECURITY: the verifier is hardcoded to RS256 and is NEVER selected
        // from the header. `alg` is read solely to reject a token asserting
        // anything else — none/HS256/HS384/HS512, or no `alg` at all — so the
        // failure mode is visible rather than silent (RFC 9700 §2.3).
        // `header.alg` is optional in the decoded model, and a MISSING `alg`
        // must be rejected exactly like a wrong one — `if let` alone let a
        // token with no `alg` skip this branch entirely. RFC 9068 requires the
        // claim to be present. The Flutter port already rejected it.
        if header.alg != "RS256" {
            let alg = header.alg ?? "absent"
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwt_alg_rejected_\(alg)"
            )
        }

        // Decode payload claims as AnyClaim map.
        guard let raw = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwt_payload_not_object"
            )
        }
        let claims = try Self.decodeClaims(raw)
        let payload = try Self.parsePayload(raw: raw, claims: claims)

        // Verify iss
        if let iss = payload.iss, iss != expectedIssuer.absoluteString {
            // Some providers omit trailing slash; do a normalized comparison.
            let expected = expectedIssuer.absoluteString
            if iss.trimmingCharacters(in: ["/"]) != expected.trimmingCharacters(in: ["/"]) {
                throw SdkError(
                    code: .codeExchangeFailed,
                    reason: .oauthStateMismatch,
                    errorMessage: "jwt_iss_mismatch"
                )
            }
        }

        // Verify aud (scalar OR array; SDK normalizes to array on parse).
        if let expectedAudience, !payload.aud.isEmpty,
            !payload.aud.contains(expectedAudience)
        {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .oauthStateMismatch,
                errorMessage: "jwt_aud_mismatch"
            )
        }

        // Verify exp
        if let exp = payload.exp, now >= exp {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .sessionExpired,
                errorMessage: "jwt_exp_passed"
            )
        }

        // Verify nbf if present
        if let nbf = payload.nbf, now < nbf {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwt_nbf_future"
            )
        }

        // Verify signature against JWKS (kid match required).
        let signingInput = "\(parts[0]).\(parts[1])"
        guard let inputData = signingInput.data(using: .utf8) else {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwt_input_encoding"
            )
        }
        let kid = header.kid
        let key = try jwks.findKey(kid: kid)
        try Self.verifyRS256(input: inputData, signature: signatureData, key: key)

        let user = Self.userFromClaims(claims)
        return VerifiedJWT(header: header, payload: payload, user: user)
    }

    // MARK: - Claim parsing

    static func decodeClaims(_ raw: [String: Any]) throws -> [String: AnyClaim] {
        let data = try JSONSerialization.data(withJSONObject: raw)
        return try JSONDecoder().decode([String: AnyClaim].self, from: data)
    }

    static func parsePayload(raw: [String: Any], claims: [String: AnyClaim]) throws -> JWTPayload {
        let iss = raw["iss"] as? String
        let sub = raw["sub"] as? String
        let jti = raw["jti"] as? String
        let exp = (raw["exp"] as? Double).map { Date(timeIntervalSince1970: $0) }
        let nbf = (raw["nbf"] as? Double).map { Date(timeIntervalSince1970: $0) }
        let iat = (raw["iat"] as? Double).map { Date(timeIntervalSince1970: $0) }
        // aud: scalar OR array
        let aud: [String]
        if let scalar = raw["aud"] as? String {
            aud = [scalar]
        } else if let arr = raw["aud"] as? [String] {
            aud = arr
        } else {
            aud = []
        }
        return JWTPayload(iss: iss, sub: sub, aud: aud, exp: exp, nbf: nbf, iat: iat, jti: jti, raw: claims)
    }

    static func userFromClaims(_ claims: [String: AnyClaim]) -> User {
        let id = claims["sub"]?.stringValue ?? ""
        let email = claims["email"]?.stringValue
        let emailVerified: Bool
        if case .bool(let v) = claims["email_verified"] { emailVerified = v } else { emailVerified = false }
        let displayName = claims["name"]?.stringValue
        let avatar = claims["picture"]?.stringValue.flatMap { URL(string: $0) }
        return User(
            id: id,
            email: email,
            emailVerified: emailVerified,
            displayName: displayName,
            avatarURL: avatar,
            claims: claims
        )
    }

    // MARK: - Signature verification

    static func verifyRS256(input: Data, signature: Data, key: JWK) throws {
        #if canImport(Security) && (os(iOS) || os(macOS) || os(watchOS) || os(tvOS) || os(visionOS))
        guard let secKey = try key.toSecKey() else {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwks_key_unbuildable"
            )
        }
        var error: Unmanaged<CFError>?
        let valid = SecKeyVerifySignature(
            secKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            input as CFData,
            signature as CFData,
            &error
        )
        if !valid {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwt_signature_invalid"
            )
        }
        #elseif canImport(Crypto)
        // Linux fallback using swift-crypto.
        let pubKey = try key.toCryptoPublicKey()
        let sig = _RSA.Signing.RSASignature(rawRepresentation: signature)
        let digest = SHA256.hash(data: input)
        guard pubKey.isValidSignature(sig, for: digest, padding: .insecurePKCS1v1_5) else {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwt_signature_invalid_linux"
            )
        }
        #else
        _ = (input, signature, key)
        throw SdkError(
            code: .codeExchangeFailed,
            reason: .invalidCredentials,
            errorMessage: "jwt_verify_unavailable_on_platform"
        )
        #endif
    }
}
