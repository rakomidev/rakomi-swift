import XCTest

@testable import RakomiSDK

final class UserSessionTests: XCTestCase {

    func testAnyClaimRoundTripObject() throws {
        let payload: [String: AnyClaim] = [
            "sub": .string("u_1"),
            "email": .string("a@b.test"),
            "email_verified": .bool(true),
            "exp": .int(1_724_000_000),
            "roles": .array([.string("admin"), .string("user")]),
            "metadata": .object(["org": .string("acme")]),
        ]
        let data = try JSONEncoder().encode(payload)
        let decoded = try JSONDecoder().decode([String: AnyClaim].self, from: data)
        XCTAssertEqual(decoded["sub"]?.stringValue, "u_1")
    }

    func testSessionIsStaleLeadtime() {
        let session = Session(
            accessToken: "t",
            refreshToken: nil,
            expiresAt: Date().addingTimeInterval(30),
            tenantId: "t1"
        )
        // 30s remaining, leadtime 60s → stale
        XCTAssertTrue(session.isStale(now: Date(), leadtime: 60))
        // 30s remaining, leadtime 0 → not stale
        XCTAssertFalse(session.isStale(now: Date(), leadtime: 0))
    }

    func testWcagAACompliantContrastFallbackOnLowContrast() {
        let bad = RakomiBranding(primaryHex: "#777777", onPrimaryHex: "#888888")
        let safe = bad.wcagAACompliant()
        // Contrast between near-equal greys is far below 4.5 → fallback to default.
        XCTAssertEqual(safe.primaryHex, RakomiBranding.default.primaryHex)
    }

    func testWcagAACompliantContrastPassesOnHighContrast() {
        let good = RakomiBranding(primaryHex: "#000000", onPrimaryHex: "#FFFFFF")
        let safe = good.wcagAACompliant()
        XCTAssertEqual(safe.primaryHex, "#000000")
    }
}
