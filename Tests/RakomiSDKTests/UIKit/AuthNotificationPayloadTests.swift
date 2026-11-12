// Guards the credential-free contract of the UIKit NotificationCenter bridge.
//
// ⚠ HONEST STATUS — READ BEFORE CITING THIS FILE AS EVIDENCE.
// This suite has NEVER EXECUTED. `MACOS_CI_ENABLED=false`, so `swift-sdk-pr-light`
// is skipped, and a skipped required check aggregates as GREEN — there is no
// Swift build and no Swift test run anywhere in CI, and no Swift toolchain on the
// Linux dev host that authored it. It is DESIGN-effective only. It becomes
// evidence the first time it runs, not before. Do not read a green
// `sdk-required` as this suite having passed.

import XCTest

@testable import RakomiSDK

final class AuthNotificationPayloadTests: XCTestCase {

    /// The substrate this suite asserts over: a session holding values that are
    /// unmistakable if they ever leak. An assert-absence check over a session
    /// with empty tokens would pass for the wrong reason.
    private static let accessTokenSentinel = "ACCESS-TOKEN-SENTINEL-must-never-be-broadcast"
    private static let refreshTokenSentinel = "REFRESH-TOKEN-SENTINEL-must-never-be-broadcast"

    private func authenticatedState() -> AuthState {
        let user = User(id: "usr_1", email: "a@b.test", emailVerified: true)
        let session = Session(
            accessToken: Self.accessTokenSentinel,
            refreshToken: Self.refreshTokenSentinel,
            expiresAt: Date().addingTimeInterval(3600),
            tenantId: "t1"
        )
        return .authenticated(user, session)
    }

    /// PRECONDITION — without this, the absence assertions below are vacuous.
    func testSentinelsAreActuallyPresentInTheStateBeingProjected() throws {
        let state = authenticatedState()
        guard case .authenticated(_, let session) = state else {
            return XCTFail("expected .authenticated")
        }
        XCTAssertEqual(session.accessToken, Self.accessTokenSentinel)
        XCTAssertEqual(session.refreshToken, Self.refreshTokenSentinel)
    }

    func testAuthenticatedPayloadCarriesNoTokenValue() throws {
        let info = RakomiAuthUIKitObserver.userInfo(for: authenticatedState())
        let flattened = info.map { "\($0.key)=\($0.value)" }.joined(separator: "&")
        XCTAssertFalse(flattened.contains(Self.accessTokenSentinel))
        XCTAssertFalse(flattened.contains(Self.refreshTokenSentinel))
        XCTAssertEqual(info[RakomiAuthNotificationKey.state], "authenticated")
        XCTAssertEqual(info[RakomiAuthNotificationKey.userId], "usr_1")
    }

    /// The payload is a CLOSED vocabulary. A future case that adds a field goes
    /// through this assertion, so widening it is a deliberate act, not a drift.
    func testPayloadKeysAreAClosedSetForEveryState() throws {
        let allowed: Set<String> = [
            RakomiAuthNotificationKey.state,
            RakomiAuthNotificationKey.userId,
            RakomiAuthNotificationKey.errorReason,
        ]
        let states: [AuthState] = [
            .loading,
            .signedOut,
            authenticatedState(),
            .error(SdkError(code: .networkError, reason: .sessionExpired)),
        ]
        var seenStateValues: Set<String> = []
        for state in states {
            let info = RakomiAuthUIKitObserver.userInfo(for: state)
            XCTAssertFalse(info.isEmpty, "every state must project a non-empty payload")
            XCTAssertTrue(
                Set(info.keys).isSubset(of: allowed),
                "unexpected key(s): \(Set(info.keys).subtracting(allowed))"
            )
            if let value = info[RakomiAuthNotificationKey.state] { seenStateValues.insert(value) }
        }
        XCTAssertEqual(
            seenStateValues,
            ["loading", "signedOut", "authenticated", "error"],
            "every AuthState case must be distinguishable from the payload alone"
        )
    }
}
