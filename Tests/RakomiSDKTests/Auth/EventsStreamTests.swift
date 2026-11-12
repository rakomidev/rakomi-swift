// Auth events stream tests.

import XCTest

@testable import RakomiSDK

final class EventsStreamTests: XCTestCase {

    func testAuditSignificance() {
        XCTAssertEqual(AuthEvent.signedIn(User(id: "u")).auditSignificance, .high)
        XCTAssertEqual(AuthEvent.tokenRefreshed.auditSignificance, .low)
        XCTAssertEqual(AuthEvent.mfaChallengeRequired(challengeId: "c").auditSignificance, .medium)
        XCTAssertEqual(AuthEvent.mfaChallengeVerified.auditSignificance, .high)
        XCTAssertEqual(AuthEvent.sessionRevoked.auditSignificance, .high)
        XCTAssertEqual(AuthEvent.userUpdated(User(id: "u")).auditSignificance, .medium)
        XCTAssertEqual(AuthEvent.signedOut(reason: nil).auditSignificance, .high)
    }

    func testEventEquality() {
        XCTAssertEqual(AuthEvent.tokenRefreshed, AuthEvent.tokenRefreshed)
        XCTAssertNotEqual(
            AuthEvent.signedIn(User(id: "a")),
            AuthEvent.signedIn(User(id: "b"))
        )
    }
}
