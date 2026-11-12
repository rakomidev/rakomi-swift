// RS256 verifier behaviour.

import XCTest

@testable import RakomiSDK

final class JWTVerifyTests: XCTestCase {

    struct Fixtures: Decodable {
        struct Tokens: Decodable {
            let happy: String
            let expired: String
            let futureNbf: String
            let audArray: String
            let audWrong: String
            let issWrong: String
            let algNone: String
            let wrongKid: String
        }
        let jwks: JWKSet
        let issuer: String
        let audience: String
        let tokens: Tokens
    }

    /// The instant the fixture was minted, read out of the fixture itself.
    ///
    /// Every token in `jwt_fixtures.json` was signed at one moment with a fixed
    /// `exp`, so verifying them against the wall clock makes the outcome a
    /// function of the day the suite runs: the positive cases went red once the
    /// fixture aged past its expiry, and the negative `expired` case started
    /// passing for the wrong reason. Anchoring the verifier to the `iat` of the
    /// fixture's own happy-path token keeps both polarities meaningful for as
    /// long as the fixture exists.
    private func fixtureNow(_ f: Fixtures) throws -> Date {
        let segments = f.tokens.happy.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, let payload = Self.base64URLDecode(String(segments[1])) else {
            throw XCTSkip("happy-path fixture token is not a three-segment JWT")
        }
        guard
            let json = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
            let iat = json["iat"] as? Double
        else {
            throw XCTSkip("happy-path fixture token carries no numeric iat")
        }
        return Date(timeIntervalSince1970: iat + 1)
    }

    private static func base64URLDecode(_ input: String) -> Data? {
        var s = input.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s.append("=") }
        return Data(base64Encoded: s)
    }

    /// A token that carries `email_verified` and one that does not must not read
    /// the same. The platform omits the claim on the ordinary sign-in path, so
    /// the absent case is the common one.
    func testAbsentEmailVerifiedClaimIsNotReportedAsUnverified() {
        let withClaim = JWTVerifier.userFromClaims([
            "sub": .string("usr_1"), "email": .string("a@b.test"), "email_verified": .bool(true),
        ])
        let withFalse = JWTVerifier.userFromClaims([
            "sub": .string("usr_1"), "email": .string("a@b.test"), "email_verified": .bool(false),
        ])
        let absent = JWTVerifier.userFromClaims([
            "sub": .string("usr_1"), "email": .string("a@b.test"),
        ])
        XCTAssertEqual(withClaim.emailVerified, true)
        XCTAssertEqual(withFalse.emailVerified, false)
        XCTAssertNil(absent.emailVerified, "an absent claim must not be reported as a negative")
    }

    private func loadFixtures() throws -> Fixtures {
        let bundle = Bundle.module
        guard
            let url = bundle.url(forResource: "jwt_fixtures", withExtension: "json", subdirectory: "Fixtures")
                ?? bundle.url(forResource: "Fixtures/jwt_fixtures", withExtension: "json")
                ?? bundle.url(forResource: "jwt_fixtures", withExtension: "json")
        else {
            throw XCTSkip("Fixture jwt_fixtures.json not found in test bundle")
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Fixtures.self, from: data)
    }

    func testHappyPath() throws {
        let f = try loadFixtures()
        let verified = try JWTVerifier.verify(
            token: f.tokens.happy,
            jwks: f.jwks,
            expectedIssuer: URL(string: f.issuer)!,
            expectedAudience: f.audience,
            now: try fixtureNow(f)
        )
        XCTAssertEqual(verified.user.id, "user_abc")
        XCTAssertEqual(verified.user.email, "alice@example.com")
        XCTAssertEqual(verified.user.emailVerified, true)
    }

    func testAlgNoneRejected() throws {
        let f = try loadFixtures()
        XCTAssertThrowsError(
            try JWTVerifier.verify(
                token: f.tokens.algNone,
                jwks: f.jwks,
                expectedIssuer: URL(string: f.issuer)!,
                expectedAudience: f.audience,
                now: try fixtureNow(f)
            )
        ) { err in
            guard let sdkErr = err as? SdkError else {
                XCTFail("expected SdkError")
                return
            }
            XCTAssertTrue(sdkErr.errorMessage?.contains("alg") ?? false)
        }
    }

    func testExpired() throws {
        let f = try loadFixtures()
        XCTAssertThrowsError(
            try JWTVerifier.verify(
                token: f.tokens.expired,
                jwks: f.jwks,
                expectedIssuer: URL(string: f.issuer)!,
                expectedAudience: f.audience,
                now: try fixtureNow(f)
            )
        ) { err in
            guard let sdkErr = err as? SdkError else {
                XCTFail()
                return
            }
            XCTAssertEqual(sdkErr.reason, .sessionExpired)
        }
    }

    func testFutureNbf() throws {
        let f = try loadFixtures()
        XCTAssertThrowsError(
            try JWTVerifier.verify(
                token: f.tokens.futureNbf,
                jwks: f.jwks,
                expectedIssuer: URL(string: f.issuer)!,
                expectedAudience: f.audience,
                now: try fixtureNow(f)
            )
        )
    }

    func testAudArrayAccepted() throws {
        let f = try loadFixtures()
        let verified = try JWTVerifier.verify(
            token: f.tokens.audArray,
            jwks: f.jwks,
            expectedIssuer: URL(string: f.issuer)!,
            expectedAudience: f.audience,
            now: try fixtureNow(f)
        )
        XCTAssertEqual(verified.user.id, "user_abc")
    }

    func testAudWrongRejected() throws {
        let f = try loadFixtures()
        XCTAssertThrowsError(
            try JWTVerifier.verify(
                token: f.tokens.audWrong,
                jwks: f.jwks,
                expectedIssuer: URL(string: f.issuer)!,
                expectedAudience: f.audience,
                now: try fixtureNow(f)
            )
        )
    }

    func testIssMismatchRejected() throws {
        let f = try loadFixtures()
        XCTAssertThrowsError(
            try JWTVerifier.verify(
                token: f.tokens.issWrong,
                jwks: f.jwks,
                expectedIssuer: URL(string: f.issuer)!,
                expectedAudience: f.audience,
                now: try fixtureNow(f)
            )
        ) { err in
            guard let sdkErr = err as? SdkError else {
                XCTFail()
                return
            }
            XCTAssertEqual(sdkErr.reason, .oauthStateMismatch)
        }
    }

    func testWrongKidRejected() throws {
        let f = try loadFixtures()
        XCTAssertThrowsError(
            try JWTVerifier.verify(
                token: f.tokens.wrongKid,
                jwks: f.jwks,
                expectedIssuer: URL(string: f.issuer)!,
                expectedAudience: f.audience,
                now: try fixtureNow(f)
            )
        )
    }

    func testJWKSFindKidMissThrows() {
        let jwks = JWKSet(keys: [
            JWK(kty: "RSA", kid: "k1", use: "sig", alg: "RS256", n: "n", e: "e")
        ])
        XCTAssertThrowsError(try jwks.findKey(kid: "k2"))
    }

    func testJWKSFindKidNilSingleKey() throws {
        let jwks = JWKSet(keys: [
            JWK(kty: "RSA", kid: "k1", use: "sig", alg: "RS256", n: "n", e: "e")
        ])
        let key = try jwks.findKey(kid: nil)
        XCTAssertEqual(key.kid, "k1")
    }
}
