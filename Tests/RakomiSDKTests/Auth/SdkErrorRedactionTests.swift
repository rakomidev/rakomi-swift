// JWT/Bearer redaction in error messages.

import XCTest

@testable import RakomiSDK

final class SdkErrorRedactionTests: XCTestCase {

    func testRedactsJWTInMessage() {
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"
        let err = SdkError(reason: .unknown, errorMessage: "ohno: \(token)")
        XCTAssertTrue(err.redactedMessage.contains("[redacted]"))
        XCTAssertFalse(err.redactedMessage.contains(token))
    }

    func testRedactsBearer() {
        let err = SdkError(reason: .unknown, errorMessage: "auth: Bearer abc.def.ghi")
        XCTAssertFalse(err.redactedMessage.contains("Bearer abc"))
    }

    func testRedactsEmbeddedJWT() {
        // Embedded tokens (non-anchored) must be redacted.
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJ0eXAiOiJKV1QifQ.signedstuff"
        let msg = "wrapper before \(token) wrapper after"
        let err = SdkError(reason: .unknown, errorMessage: msg)
        XCTAssertFalse(err.redactedMessage.contains(token))
    }

    func testNoRedactionWhenNoToken() {
        let err = SdkError(reason: .network, errorMessage: "plain message")
        XCTAssertEqual(err.redactedMessage, "plain message")
    }

    func testNilMessageRedactsToEmpty() {
        let err = SdkError(reason: .unknown)
        XCTAssertEqual(err.redactedMessage, "")
    }

    func testErrorDescriptionContainsCodeAndReason() {
        let err = SdkError(
            code: .biometricError,
            reason: .biometricCancelled,
            errorMessage: "user_cancelled"
        )
        let desc = err.errorDescription ?? ""
        XCTAssertTrue(desc.contains("BIOMETRIC_ERROR"))
        XCTAssertTrue(desc.contains("biometric_cancelled"))
    }
}
