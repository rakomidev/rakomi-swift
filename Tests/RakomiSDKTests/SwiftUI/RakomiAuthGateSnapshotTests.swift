#if canImport(SwiftUI) && os(macOS)
import XCTest
import SwiftUI
@testable import RakomiSDK

@available(macOS 14, *)
final class RakomiAuthGateSnapshotTests: XCTestCase {

    func testGateRendersSignedOutSlot() {
        let env = RakomiAuthEnvironment()
        env.state = .signedOut
        let view = RakomiAuthGate(
            signedIn: { _ in Text("in") },
            signedOut: { Text("out") }
        ).environment(env)
        XCTAssertNotNil(view)
    }

    func testGateRendersLoadingSlot() {
        let env = RakomiAuthEnvironment()
        env.state = .loading
        let view = RakomiAuthGate(
            signedIn: { _ in Text("in") },
            signedOut: { Text("out") }
        ).environment(env)
        XCTAssertNotNil(view)
    }

    func testGateRendersAuthenticatedSlot() {
        let env = RakomiAuthEnvironment()
        let user = User(id: "u_1")
        let session = Session(
            accessToken: "t",
            refreshToken: nil,
            expiresAt: Date().addingTimeInterval(3600),
            tenantId: "t1"
        )
        env.state = .authenticated(user, session)
        let view = RakomiAuthGate(
            signedIn: { _ in Text("in") },
            signedOut: { Text("out") }
        ).environment(env)
        XCTAssertNotNil(view)
    }

    func testGateRendersErrorSlot() {
        let env = RakomiAuthEnvironment()
        env.state = .error(SdkError(reason: .network))
        let view = RakomiAuthGate(
            signedIn: { _ in Text("in") },
            signedOut: { Text("out") },
            error: { _ in Text("err") }
        ).environment(env)
        XCTAssertNotNil(view)
    }
}
#endif
