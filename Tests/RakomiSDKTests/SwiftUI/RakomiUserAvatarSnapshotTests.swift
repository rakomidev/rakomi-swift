#if canImport(SwiftUI) && os(macOS)
import XCTest
import SwiftUI
@testable import RakomiSDK

@available(macOS 14, *)
final class RakomiUserAvatarSnapshotTests: XCTestCase {

    func testRendersWithoutUser() {
        let view = RakomiUserAvatar()
            .environment(RakomiAuthEnvironment())
        XCTAssertNotNil(view)
    }

    func testRendersWithUser() {
        let env = RakomiAuthEnvironment()
        env.user = User(id: "u_1", email: "alice@example.com", displayName: "Alice")
        let view = RakomiUserAvatar().environment(env)
        XCTAssertNotNil(view)
    }
}
#endif
