// Clock-skew probe boundaries.

import XCTest

@testable import RakomiSDK

final class ClockSkewTests: XCTestCase {

    func testMaxAcceptableClockSkewIsFiveMinutes() {
        XCTAssertEqual(maxAcceptableClockSkew, 300)
    }

    func testJwksTtl24h() {
        XCTAssertEqual(jwksCacheTTL, 24 * 60 * 60)
    }

    func testRefreshBackoffEnvelope() {
        XCTAssertEqual(refreshBackoffSeconds, [2, 8, 30])
    }

    func testOfflineStaleMaxCycles() {
        XCTAssertEqual(offlineStaleMaxCycles, 3)
    }

    func testJWKSResponseSizeCap() {
        XCTAssertEqual(maxJWKSResponseBytes, 16 * 1024)
    }
}
