import CryptoKit
import Foundation
import Security
import XCTest

@testable import RakomiSDK

/// Issuer-bound signing keys: keys come from the jwks_uri of the EXPECTED
/// issuer's discovery document, `iss` is required and exact, and a token's
/// `alg` must equal its key's `alg`. Both polarities over the real verifier.
final class IssuerBoundKeysTests: XCTestCase {
    private let issuer = URL(string: "https://auth.example.test/t/tn_abc/test")!
    private let audience = "https://api.rakomi.com"

    // MARK: - Helpers

    private static func b64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func claims(iss: String?) -> [String: Any] {
        let now = Date().timeIntervalSince1970
        var c: [String: Any] = ["sub": "u1", "aud": audience, "iat": now, "exp": now + 600]
        if let iss { c["iss"] = iss }
        return c
    }

    private func signingInput(alg: String, kid: String, claims: [String: Any]) throws -> String {
        let header = try JSONSerialization.data(withJSONObject: ["alg": alg, "kid": kid, "typ": "JWT"])
        let payload = try JSONSerialization.data(withJSONObject: claims)
        return "\(Self.b64url(header)).\(Self.b64url(payload))"
    }

    private func makeRSAKey(kid: String, alg: String) throws -> (SecKey, JWK) {
        var error: Unmanaged<CFError>?
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
            let pub = SecKeyCopyPublicKey(priv),
            let der = SecKeyCopyExternalRepresentation(pub, &error) as Data?
        else { throw XCTSkip("RSA key generation unavailable") }
        // PKCS#1 RSAPublicKey DER: SEQUENCE { INTEGER n, INTEGER e }.
        let (n, e) = try Self.parsePKCS1(der)
        return (priv, JWK(kty: "RSA", kid: kid, use: "sig", alg: alg, n: Self.b64url(n), e: Self.b64url(e)))
    }

    private static func parsePKCS1(_ der: Data) throws -> (Data, Data) {
        var bytes = [UInt8](der)
        func readLength(_ i: inout Int) -> Int {
            let first = Int(bytes[i])
            i += 1
            if first < 0x80 { return first }
            var len = 0
            for _ in 0..<(first & 0x7f) {
                len = (len << 8) | Int(bytes[i])
                i += 1
            }
            return len
        }
        var i = 1  // skip SEQUENCE tag
        _ = readLength(&i)
        func readInteger() -> Data {
            i += 1  // INTEGER tag
            let len = readLength(&i)
            var value = Data(bytes[i..<(i + len)])
            i += len
            while value.first == 0x00 && value.count > 1 { value.removeFirst() }
            return value
        }
        let n = readInteger()
        let e = readInteger()
        bytes = []
        return (n, e)
    }

    private func signRSA(_ key: SecKey, input: String, pss: Bool) throws -> String {
        var error: Unmanaged<CFError>?
        let algorithm: SecKeyAlgorithm = pss ? .rsaSignatureMessagePSSSHA256 : .rsaSignatureMessagePKCS1v15SHA256
        guard let sig = SecKeyCreateSignature(key, algorithm, Data(input.utf8) as CFData, &error) as Data? else {
            throw XCTSkip("RSA signing unavailable")
        }
        return "\(input).\(Self.b64url(sig))"
    }

    /// A token signed with an RSA key: `alg`/`kid` go in the header, `iss` in the claims.
    private func signedRSA(_ key: SecKey, alg: String, kid: String, iss: String?) throws -> String {
        let input = try signingInput(alg: alg, kid: kid, claims: claims(iss: iss))
        return try signRSA(key, input: input, pss: alg == "PS256")
    }

    private func verify(_ token: String, keys: [JWK]) throws -> VerifiedJWT {
        try JWTVerifier.verify(
            token: token,
            jwks: JWKSet(keys: keys),
            expectedIssuer: issuer,
            expectedAudience: audience
        )
    }

    // MARK: - Discovery

    func testDiscoveryURLsInsertThenAppendThePathAndHonourAnOrigin() {
        XCTAssertEqual(
            IssuerDiscovery.discoveryURLs(issuer: issuer, discoveryOrigin: nil).map(\.absoluteString),
            [
                "https://auth.example.test/.well-known/oauth-authorization-server/t/tn_abc/test",
                "https://auth.example.test/t/tn_abc/test/.well-known/openid-configuration",
            ]
        )
        XCTAssertEqual(
            IssuerDiscovery.discoveryURLs(
                issuer: URL(string: "https://api.rakomi.com/t/tn_abc")!,
                discoveryOrigin: URL(string: "http://localhost:3001")!
            ).first?.absoluteString,
            "http://localhost:3001/.well-known/oauth-authorization-server/t/tn_abc"
        )
    }

    func testExtractJWKSURIRequiresTheExactIssuerAndHTTPS() throws {
        let ok = #"{"issuer":"https://auth.example.test/t/tn_abc/test","jwks_uri":"https://keys.example.test/j"}"#
        XCTAssertEqual(
            try IssuerDiscovery.extractJWKSURI(document: Data(ok.utf8), issuer: issuer).absoluteString,
            "https://keys.example.test/j"
        )
        let other = #"{"issuer":"https://auth.example.test/t/tn_other","jwks_uri":"https://keys.example.test/j"}"#
        XCTAssertThrowsError(try IssuerDiscovery.extractJWKSURI(document: Data(other.utf8), issuer: issuer)) {
            XCTAssertEqual(($0 as? SdkError)?.errorMessage, "jwks_discovery_issuer_mismatch")
        }
        let http = #"{"issuer":"https://auth.example.test/t/tn_abc/test","jwks_uri":"http://keys.example.test/j"}"#
        XCTAssertThrowsError(try IssuerDiscovery.extractJWKSURI(document: Data(http.utf8), issuer: issuer))
    }

    func testDiscoveryOriginIsTheDeploymentOnlyForPlatformFamilyIssuers() {
        let base = URL(string: "http://127.0.0.1:3001")!
        XCTAssertEqual(
            IssuerDiscovery.discoveryOrigin(
                for: URL(string: "https://api.rakomi.com/t/x")!,
                apiBaseURL: base
            ),
            base
        )
        XCTAssertNil(IssuerDiscovery.discoveryOrigin(for: issuer, apiBaseURL: base))
        XCTAssertNil(IssuerDiscovery.discoveryOrigin(for: URL(string: "https://evilrakomi.com/t/x")!, apiBaseURL: base))
    }

    // MARK: - Verification

    func testRS256PS256AndES256TokensVerify() throws {
        let (rsaPriv, rsJWK) = try makeRSAKey(kid: "k-rs", alg: "RS256")
        let psJWK = JWK(kty: "RSA", kid: "k-ps", use: "sig", alg: "PS256", n: rsJWK.n, e: rsJWK.e)
        let ec = P256.Signing.PrivateKey()
        let point = ec.publicKey.x963Representation
        let esJWK = JWK(
            kty: "EC",
            kid: "k-es",
            use: "sig",
            alg: "ES256",
            crv: "P-256",
            x: Self.b64url(point.subdata(in: 1..<33)),
            y: Self.b64url(point.subdata(in: 33..<65))
        )
        let keys = [rsJWK, psJWK, esJWK]

        let rs = try signedRSA(rsaPriv, alg: "RS256", kid: "k-rs", iss: issuer.absoluteString)
        XCTAssertNoThrow(try verify(rs, keys: keys))
        let ps = try signedRSA(rsaPriv, alg: "PS256", kid: "k-ps", iss: issuer.absoluteString)
        XCTAssertNoThrow(try verify(ps, keys: keys))
        let esInput = try signingInput(alg: "ES256", kid: "k-es", claims: claims(iss: issuer.absoluteString))
        let esSig = try ec.signature(for: Data(esInput.utf8)).rawRepresentation
        XCTAssertNoThrow(try verify("\(esInput).\(Self.b64url(esSig))", keys: keys))
    }

    func testHeaderAlgDifferentFromTheKeyAlgIsRejected() throws {
        let (rsaPriv, rsJWK) = try makeRSAKey(kid: "k-rs", alg: "RS256")
        // Signed PS256, naming a kid published as RS256.
        let token = try signedRSA(rsaPriv, alg: "PS256", kid: "k-rs", iss: issuer.absoluteString)
        XCTAssertThrowsError(try verify(token, keys: [rsJWK])) {
            XCTAssertEqual(($0 as? SdkError)?.errorMessage, "jwt_alg_rejected_key_mismatch")
        }
    }

    func testATokenWithoutIssIsRejected() throws {
        let (rsaPriv, rsJWK) = try makeRSAKey(kid: "k-rs", alg: "RS256")
        let token = try signedRSA(rsaPriv, alg: "RS256", kid: "k-rs", iss: nil)
        XCTAssertThrowsError(try verify(token, keys: [rsJWK])) {
            XCTAssertEqual(($0 as? SdkError)?.errorMessage, "jwt_iss_mismatch")
        }
    }

    func testAKeyOutsideTheIssuerSetIsAKidMiss() throws {
        let (rsaPriv, _) = try makeRSAKey(kid: "k-foreign", alg: "RS256")
        let (_, mine) = try makeRSAKey(kid: "k-mine", alg: "RS256")
        let token = try signedRSA(rsaPriv, alg: "RS256", kid: "k-foreign", iss: issuer.absoluteString)
        XCTAssertThrowsError(try verify(token, keys: [mine])) {
            XCTAssertEqual(($0 as? SdkError)?.errorMessage, "jwks_kid_miss")
        }
    }

    func testHMACAndNoneHeadersAreRejectedBeforeKeyLookup() throws {
        for alg in ["HS256", "none"] {
            let input = try signingInput(alg: alg, kid: "k", claims: claims(iss: issuer.absoluteString))
            XCTAssertThrowsError(try verify("\(input).c2ln", keys: [])) {
                XCTAssertEqual(($0 as? SdkError)?.errorMessage, "jwt_alg_rejected_\(alg)")
            }
        }
    }
}
