// PKCE (RFC 7636).

import XCTest

@testable import RakomiSDK

final class PKCETests: XCTestCase {

    func testS256Enforced() throws {
        let pair = try PKCE.generate()
        XCTAssertEqual(pair.method, "S256")
        XCTAssertTrue(PKCE.verify(verifier: pair.verifier, challenge: pair.challenge))
    }

    func testVerifierIsBase64URLNoPadding() throws {
        let pair = try PKCE.generate()
        XCTAssertFalse(pair.verifier.contains("="))
        XCTAssertFalse(pair.verifier.contains("+"))
        XCTAssertFalse(pair.verifier.contains("/"))
        // 32 random bytes → 43 base64url chars without padding.
        XCTAssertEqual(pair.verifier.count, 43)
    }

    func testChallengeIsBase64URLNoPadding() throws {
        let pair = try PKCE.generate()
        XCTAssertFalse(pair.challenge.contains("="))
        XCTAssertFalse(pair.challenge.contains("+"))
        XCTAssertFalse(pair.challenge.contains("/"))
    }

    func testVerifyFailsForMismatchedChallenge() throws {
        let pair = try PKCE.generate()
        XCTAssertFalse(PKCE.verify(verifier: pair.verifier, challenge: "tampered"))
    }

    func testTwoGenerateCallsProduceDistinctVerifiers() throws {
        let a = try PKCE.generate()
        let b = try PKCE.generate()
        XCTAssertNotEqual(a.verifier, b.verifier, "CSPRNG must produce distinct verifiers")
    }

    func testBase64URLRoundTrip() {
        let bytes = Data([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88])
        let encoded = base64URLEncode(bytes)
        XCTAssertNil(encoded.firstIndex(of: "="))
        let decoded = base64URLDecode(encoded)
        XCTAssertEqual(decoded, bytes)
    }

    func testConstantTimeEqualsTrue() {
        XCTAssertTrue(constantTimeEquals("abcdef", "abcdef"))
    }

    func testConstantTimeEqualsFalseDifferentLength() {
        XCTAssertFalse(constantTimeEquals("abcdef", "abc"))
    }

    func testConstantTimeEqualsFalseSameLength() {
        XCTAssertFalse(constantTimeEquals("abcdef", "abcdez"))
    }

    func testSecureRandomBytesProducesRequestedCount() throws {
        let bytes = try secureRandomBytes(count: 64)
        XCTAssertEqual(bytes.count, 64)
    }

    func testSecureRandomBytesIsNonZeroDist() throws {
        let bytes = try secureRandomBytes(count: 32)
        let allZero = bytes.allSatisfy { $0 == 0 }
        XCTAssertFalse(allZero, "CSPRNG must not produce all-zero output")
    }
}
