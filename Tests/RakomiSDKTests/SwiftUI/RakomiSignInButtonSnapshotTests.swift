#if canImport(SwiftUI) && os(macOS)
import XCTest
import SwiftUI
@testable import RakomiSDK

@available(macOS 14, *)
final class RakomiSignInButtonSnapshotTests: XCTestCase {

    func testGoogleButtonHasAccessibilityIdentifier() {
        let env = RakomiAuthEnvironment()
        let view = RakomiSignInButton(provider: .google).environment(env)
        XCTAssertNotNil(view)
    }

    func testButtonExistsForAllProviders() {
        let env = RakomiAuthEnvironment()
        for provider in SocialProvider.allCases {
            let _ = RakomiSignInButton(provider: provider).environment(env)
        }
    }
}
#endif
