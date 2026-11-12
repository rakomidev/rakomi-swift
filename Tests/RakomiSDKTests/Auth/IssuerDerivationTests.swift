// Multi-issuer offline verification (flutter-swift-sdks-need-the-same-multi-issuer-offline-
// verification-fix) — the SAME trust model `@rakomi/react-native`'s `deriveDefaultIssuer` applies
// (`packages/react-native/src/internal/token-runtime.ts`), ported for Swift.
//
// `RakomiAuthConfiguration.deriveDefaultIssuer(from:)` derives the default `issuer` FROM
// `apiBaseURL` instead of a hardcoded platform constant. The second group below exercises it wired
// into the REAL `JWTVerifier.verify` exactly as `RakomiAuthController.verifyAndDecodeUser` wires
// them at runtime — the same production matcher, never a stand-alone string comparison (FMEA row
// 8), driven through a REAL RS256 keypair (FMEA row 9), never a hand-written string standing in for
// a signature.

import XCTest

@testable import RakomiSDK

#if canImport(Security)
import Security
#endif

final class IssuerDerivationTests: XCTestCase {

    // MARK: - deriveDefaultIssuer — pure derivation

    func testDerivesIssuerFromCustomDomainBaseURL() {
        let derived = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://tenant-a.example.com")!
        )
        XCTAssertEqual(derived, URL(string: "https://tenant-a.example.com")!)
    }

    func testStripsTrailingSlash() {
        let derived = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://tenant-a.example.com/")!
        )
        XCTAssertEqual(derived.absoluteString, "https://tenant-a.example.com")
    }

    func testPreservesTenantPathSuffixedBaseURL() {
        let derived = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://auth.acme.com/staging")!
        )
        XCTAssertEqual(derived.absoluteString, "https://auth.acme.com/staging")

        let derivedTrailing = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://auth.acme.com/staging/")!
        )
        XCTAssertEqual(derivedTrailing.absoluteString, "https://auth.acme.com/staging")
    }

    func testBackwardCompatPlatformHostedBaseURLDerivesByteIdenticalFrozenConstant() {
        let derived = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://api.rakomi.com")!
        )
        XCTAssertEqual(derived, kRakomiPlatformIssuerDefault)
        XCTAssertEqual(kRakomiPlatformIssuerDefault.absoluteString, "https://api.rakomi.com")
    }

    /// should-PASS: ANY `rakomi.com` subdomain is a platform host — frozen constant, never the
    /// subdomain itself (server issuer identity is frozen in every environment).
    func testAnyRakomiComSubdomainIsAPlatformHost() {
        XCTAssertEqual(
            RakomiAuthConfiguration.deriveDefaultIssuer(from: URL(string: "https://accounts.rakomi.com")!),
            kRakomiPlatformIssuerDefault
        )
        XCTAssertEqual(
            RakomiAuthConfiguration.deriveDefaultIssuer(from: URL(string: "https://rakomi.com")!),
            kRakomiPlatformIssuerDefault
        )
        XCTAssertEqual(
            RakomiAuthConfiguration.deriveDefaultIssuer(from: URL(string: "https://a.b.rakomi.com")!),
            kRakomiPlatformIssuerDefault
        )
    }

    /// should-PASS: localhost/127.0.0.1/::1 are platform hosts — frozen constant (local dev mints
    /// under the same frozen issuer identity).
    func testLocalhostVariantsArePlatformHosts() {
        XCTAssertEqual(
            RakomiAuthConfiguration.deriveDefaultIssuer(from: URL(string: "http://localhost:3001")!),
            kRakomiPlatformIssuerDefault
        )
        XCTAssertEqual(
            RakomiAuthConfiguration.deriveDefaultIssuer(from: URL(string: "http://127.0.0.1:3001")!),
            kRakomiPlatformIssuerDefault
        )
        XCTAssertEqual(
            RakomiAuthConfiguration.deriveDefaultIssuer(from: URL(string: "http://[::1]:3001")!),
            kRakomiPlatformIssuerDefault
        )
    }

    /// should-FAIL plant: a confusable host that is NOT a `rakomi.com` subdomain is treated as a
    /// genuine custom host (iss = its own base URL), never silently folded into the platform
    /// constant — substring matching, not label-boundary matching, would misclassify both of these.
    func testConfusableHostsAreTreatedAsGenuineCustomHostsNotPlatform() {
        // `evilrakomi.com` — ends with the literal characters "rakomi.com" but is NOT
        // ".rakomi.com" on a label boundary.
        XCTAssertEqual(
            RakomiAuthConfiguration.deriveDefaultIssuer(from: URL(string: "https://evilrakomi.com")!)
                .absoluteString,
            "https://evilrakomi.com"
        )
        // `rakomi.com.evil.net` — CONTAINS "rakomi.com" but does not END with it at all.
        XCTAssertEqual(
            RakomiAuthConfiguration.deriveDefaultIssuer(from: URL(string: "https://rakomi.com.evil.net")!)
                .absoluteString,
            "https://rakomi.com.evil.net"
        )
    }

    // MARK: - RakomiAuthConfiguration wiring

    func testConfigurationDerivesIssuerFromApiBaseURLWhenIssuerNotGiven() throws {
        let config = try RakomiAuthConfiguration(
            publishableKey: "pk_test_issuer_derivation",
            redirectURI: URL(string: "myapp://callback")!,
            apiBaseURL: URL(string: "https://tenant-a.example.com")!
        )
        XCTAssertEqual(config.issuer.absoluteString, "https://tenant-a.example.com")
        // `aud` stays the frozen platform constant regardless of `apiBaseURL` — see
        // `RakomiAuthConfiguration.audience`'s doc comment.
        XCTAssertEqual(config.audience, kRakomiPlatformAudienceDefault)
    }

    func testConfigurationBackwardCompatPlatformHostedIssuerUnchanged() throws {
        let config = try RakomiAuthConfiguration(
            publishableKey: "pk_test_issuer_derivation",
            redirectURI: URL(string: "myapp://callback")!
        )
        XCTAssertEqual(config.issuer, kRakomiPlatformIssuerDefault)
    }

    func testConfigurationExplicitIssuerOverridePreserved() throws {
        let override = URL(string: "https://custom-test-issuer.example.com")!
        let config = try RakomiAuthConfiguration(
            publishableKey: "pk_test_issuer_derivation",
            redirectURI: URL(string: "myapp://callback")!,
            apiBaseURL: URL(string: "https://tenant-a.example.com")!,
            issuer: override
        )
        XCTAssertEqual(config.issuer, override)
    }

    // MARK: - deriveDefaultIssuer + JWTVerifier — the wired trust model

    func testShouldPassVerifiesTokenWhoseIssEqualsDerivedBaseURLIssuer() throws {
        let fixture = try SignedIssuerFixture(kid: "kid-tenant-a")
        let issuer = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://tenant-a.example.com")!
        )
        let token = fixture.sign(iss: "https://tenant-a.example.com", aud: "https://api.rakomi.com")
        let verified = try JWTVerifier.verify(
            token: token,
            jwks: fixture.jwks,
            expectedIssuer: issuer,
            expectedAudience: "https://api.rakomi.com"
        )
        XCTAssertEqual(verified.user.id, "user-1")
    }

    func testShouldFailRejectsTokenWhoseIssBelongsToDifferentTenantBaseURL() throws {
        // Same keypair/JWKS as the should-PASS case above (planted into the REAL verifier per
        // FMEA row 9), only the token's `iss` claim differs — isolates the iss check from key
        // material.
        let fixture = try SignedIssuerFixture(kid: "kid-tenant-a")
        let issuer = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://tenant-a.example.com")!
        )
        let forged = fixture.sign(iss: "https://tenant-b.example.com", aud: "https://api.rakomi.com")
        XCTAssertThrowsError(
            try JWTVerifier.verify(
                token: forged,
                jwks: fixture.jwks,
                expectedIssuer: issuer,
                expectedAudience: "https://api.rakomi.com"
            )
        ) { err in
            guard let sdkErr = err as? SdkError else {
                XCTFail("expected SdkError")
                return
            }
            XCTAssertEqual(sdkErr.reason, .oauthStateMismatch)
        }
    }

    func testBackwardCompatPlatformHostedTenantVerifiesUnchangedAgainstFrozenDefault() throws {
        let fixture = try SignedIssuerFixture(kid: "kid-platform")
        let issuer = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://api.rakomi.com")!
        )
        let token = fixture.sign(iss: "https://api.rakomi.com", aud: "https://api.rakomi.com")
        let verified = try JWTVerifier.verify(
            token: token,
            jwks: fixture.jwks,
            expectedIssuer: issuer,
            expectedAudience: "https://api.rakomi.com"
        )
        XCTAssertEqual(verified.user.id, "user-1")
    }

    /// should-PASS: a DIFFERENT `rakomi.com` platform host (e.g. a staging `apiBaseURL`) still
    /// verifies a real platform token — this is the exact scenario the naive
    /// "expected iss = apiBaseURL" design broke.
    func testDifferentPlatformHostStillVerifiesARealPlatformToken() throws {
        let fixture = try SignedIssuerFixture(kid: "kid-platform-alt-host")
        let issuer = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://accounts.rakomi.com")!
        )
        // A REAL platform-minted token always carries the frozen iss, regardless of which
        // platform host the app is pointed at.
        let token = fixture.sign(iss: "https://api.rakomi.com", aud: "https://api.rakomi.com")
        let verified = try JWTVerifier.verify(
            token: token,
            jwks: fixture.jwks,
            expectedIssuer: issuer,
            expectedAudience: "https://api.rakomi.com"
        )
        XCTAssertEqual(verified.user.id, "user-1")
    }

    /// should-FAIL plant: a confusable non-platform host never accepts a genuine platform-issued
    /// token — `evilrakomi.com` is a distinct, untrusted issuer identity, not folded into the
    /// platform constant.
    func testConfusableNonPlatformHostNeverAcceptsAGenuinePlatformToken() throws {
        let fixture = try SignedIssuerFixture(kid: "kid-evil-host")
        let issuer = RakomiAuthConfiguration.deriveDefaultIssuer(
            from: URL(string: "https://evilrakomi.com")!
        )
        XCTAssertEqual(issuer.absoluteString, "https://evilrakomi.com")
        // A genuine platform token — would pass against the REAL platform constant, but must
        // NOT pass here.
        let token = fixture.sign(iss: "https://api.rakomi.com", aud: "https://api.rakomi.com")
        XCTAssertThrowsError(
            try JWTVerifier.verify(
                token: token,
                jwks: fixture.jwks,
                expectedIssuer: issuer,
                expectedAudience: "https://api.rakomi.com"
            )
        ) { err in
            guard let sdkErr = err as? SdkError else {
                XCTFail("expected SdkError")
                return
            }
            XCTAssertEqual(sdkErr.reason, .oauthStateMismatch)
        }
    }
}

// MARK: - Fixture: a real RSA-2048 keypair + matching JWKS + a real RS256 signer

/// A locally-generated RSA-2048 keypair, its JWKS document, and a signer for well-formed access
/// tokens — used above so the should-PASS/should-FAIL pair is driven through the REAL
/// `JWTVerifier.verify` (and its real `SecKeyVerifySignature` call), not a hand-written string
/// standing in for a signature.
private struct SignedIssuerFixture {
    let jwks: JWKSet
    private let privateKey: SecKey
    private let kid: String

    init(kid: String) throws {
        self.kid = kid
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var genError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &genError) else {
            throw genError!.takeRetainedValue() as Error
        }
        self.privateKey = privateKey
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SdkError(code: .invalidConfig, reason: .invalidCredentials, errorMessage: "test_pubkey_missing")
        }
        var repError: Unmanaged<CFError>?
        guard
            let externalRepresentation = SecKeyCopyExternalRepresentation(publicKey, &repError) as Data?
        else {
            throw repError!.takeRetainedValue() as Error
        }
        let (n, e) = try Self.parsePKCS1RSAPublicKey(externalRepresentation)
        let jwk = JWK(
            kty: "RSA",
            kid: kid,
            use: "sig",
            alg: "RS256",
            n: Self.base64URLEncode(n),
            e: Self.base64URLEncode(e)
        )
        self.jwks = JWKSet(keys: [jwk])
    }

    /// Sign a well-formed RS256 access token with the given claims — a real signature over a real
    /// keypair, verifiable by `JWTVerifier.verify` exactly as a real access token would be.
    func sign(iss: String, aud: String, sub: String = "user-1", expiresIn: TimeInterval = 900) -> String {
        let now = Date()
        let header: [String: String] = ["alg": "RS256", "typ": "JWT", "kid": kid]
        let payload: [String: Any] = [
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "iat": Int(now.timeIntervalSince1970),
            "exp": Int(now.addingTimeInterval(expiresIn).timeIntervalSince1970),
        ]
        // swiftlint:disable:next force_try — test-only, a fixed literal shape that always encodes.
        let headerB64 = Self.base64URLEncode(
            try! JSONSerialization.data(withJSONObject: header, options: [.sortedKeys])
        )
        let payloadB64 = Self.base64URLEncode(
            try! JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        )
        let signingInput = "\(headerB64).\(payloadB64)"
        var sigError: Unmanaged<CFError>?
        guard
            let signature = SecKeyCreateSignature(
                privateKey,
                .rsaSignatureMessagePKCS1v15SHA256,
                Data(signingInput.utf8) as CFData,
                &sigError
            ) as Data?
        else {
            // Test-only fixture — a signing failure here is a test-environment defect, not a
            // production code path, so a fatal error surfaces it immediately rather than producing
            // a token this fixture's own callers cannot use.
            fatalError("SecKeyCreateSignature failed in test fixture: \(String(describing: sigError))")
        }
        return "\(signingInput).\(Self.base64URLEncode(signature))"
    }

    /// Minimal ASN.1 DER reader for `SEQUENCE { INTEGER n, INTEGER e }` — the exact shape
    /// `JWK.encodeRSAPublicKeyPKCS1` (production code, `Internal/JWKSCache.swift`) produces and
    /// `SecKeyCopyExternalRepresentation` returns for an RSA public key on Apple platforms. Strips a
    /// leading `0x00` sign-padding byte per RFC 7517 §4 (unsigned big-endian integers).
    private static func parsePKCS1RSAPublicKey(_ der: Data) throws -> (n: Data, e: Data) {
        let bytes = [UInt8](der)
        var index = 0

        func readLength() throws -> Int {
            guard index < bytes.count else { throw asn1Error() }
            let first = bytes[index]
            index += 1
            if first & 0x80 == 0 { return Int(first) }
            let numBytes = Int(first & 0x7f)
            var length = 0
            for _ in 0..<numBytes {
                guard index < bytes.count else { throw asn1Error() }
                length = (length << 8) | Int(bytes[index])
                index += 1
            }
            return length
        }

        func readTLV(expectedTag: UInt8) throws -> Data {
            guard index < bytes.count, bytes[index] == expectedTag else { throw asn1Error() }
            index += 1
            let length = try readLength()
            guard index + length <= bytes.count else { throw asn1Error() }
            let value = Data(bytes[index..<(index + length)])
            index += length
            return value
        }

        guard index < bytes.count, bytes[index] == 0x30 else { throw asn1Error() }  // SEQUENCE
        index += 1
        _ = try readLength()
        var n = try readTLV(expectedTag: 0x02)  // INTEGER modulus
        var e = try readTLV(expectedTag: 0x02)  // INTEGER exponent
        if n.first == 0x00 { n = n.dropFirst() }
        if e.first == 0x00 { e = e.dropFirst() }
        return (n, e)
    }

    private static func asn1Error() -> Error {
        SdkError(code: .invalidConfig, reason: .invalidCredentials, errorMessage: "test_asn1_parse_failed")
    }

    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
