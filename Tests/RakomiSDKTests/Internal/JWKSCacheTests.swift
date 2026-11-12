import XCTest

@testable import RakomiSDK

final class JWKSCacheTests: XCTestCase {

    func testJWKSetEncodeDecode() throws {
        let original = JWKSet(keys: [
            JWK(kty: "RSA", kid: "abc", use: "sig", alg: "RS256", n: "ABC", e: "AQAB")
        ])
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(JWKSet.self, from: data)
        XCTAssertEqual(decoded, original)
    }

    func testInvalidate() async {
        // Smoke: call invalidate without any cached entry; must not throw.
        let storage = KeychainStorage(service: "com.rakomi.swift-sdk.tests.\(UUID())")
        let cache = JWKSCache(
            storage: storage,
            tenantId: "t1",
            source: .url(URL(string: "https://api.rakomi.test/.well-known/jwks.json")!),
            session: makeRakomiURLSession(certificateFingerprints: nil)
        )
        await cache.invalidate()
    }
}

extension JWKSCacheTests {

    /// A real key set can carry keys this SDK must not verify with. RFC 7517 §5
    /// says a consumer ignores what it does not understand, so one such
    /// neighbour never makes the whole set unusable: RSA (RS256/PS256) and
    /// EC P-256 (ES256) signing keys are found, everything else is not.
    func testMixedKeySetServesAllowedKeysAndIgnoresTheRest() throws {
        let json = """
            {"keys":[
              {"kty":"RSA","kid":"rsa-1","alg":"RS256","use":"sig","n":"AQAB","e":"AQAB"},
              {"kty":"EC","kid":"ec-1","alg":"ES256","use":"sig","crv":"P-256","x":"AQ","y":"AQ"},
              {"kty":"RSA","kid":"rsa-2","alg":"PS256","n":"AQAB","e":"AQAB"},
              {"kty":"oct","kid":"hmac","alg":"HS256","k":"c2VjcmV0"},
              {"kty":"EC","kid":"ec-384","alg":"ES256","use":"sig","crv":"P-384","x":"AQ","y":"AQ"},
              {"kty":"RSA","kid":"rsa-noalg","use":"sig","n":"AQAB","e":"AQAB"},
              {"kty":"RSA","kid":"rsa-enc","alg":"RS256","use":"enc","n":"AQAB","e":"AQAB"}
            ]}
            """
        let set = try JSONDecoder().decode(JWKSet.self, from: Data(json.utf8))
        XCTAssertEqual(try set.findKey(kid: "rsa-1").kid, "rsa-1")
        XCTAssertEqual(try set.findKey(kid: "ec-1").alg, "ES256")
        XCTAssertEqual(try set.findKey(kid: "rsa-2").alg, "PS256")
        for kid in ["hmac", "ec-384", "rsa-noalg", "rsa-enc"] {
            XCTAssertThrowsError(try set.findKey(kid: kid), kid) { error in
                XCTAssertEqual((error as? SdkError)?.errorMessage, "jwks_kid_miss")
            }
        }
    }

    /// The other polarity: ignoring an unusable key must not turn a set that
    /// cannot serve the request into a silent success. The lookup still fails,
    /// and it fails with the kid-miss diagnostic.
    func testKeySetOfOnlyUnusableKeysStillFailsTheLookup() throws {
        let json = """
            {"keys":[
              {"kty":"oct","kid":"hmac","alg":"HS256","k":"c2VjcmV0"},
              {"kty":"EC","kid":"ec-384","alg":"ES256","use":"sig","crv":"P-384","x":"AQ","y":"AQ"}
            ]}
            """
        let set = try JSONDecoder().decode(JWKSet.self, from: Data(json.utf8))
        XCTAssertThrowsError(try set.findKey(kid: "hmac")) { error in
            XCTAssertEqual((error as? SdkError)?.errorMessage, "jwks_kid_miss")
        }
        XCTAssertThrowsError(try set.findKey(kid: nil)) { error in
            XCTAssertEqual((error as? SdkError)?.errorMessage, "jwks_kid_required")
        }
    }

    /// A body that is not a JWK Set at all is still a hard failure.
    func testNonJWKSBodyFailsToDecode() {
        XCTAssertThrowsError(
            try JSONDecoder().decode(JWKSet.self, from: Data(#"{"not_keys":[]}"#.utf8))
        )
    }
}
