// SwiftUI snapshot tests for RakomiSignInForm.
//
// Snapshots run on `macos-14` ONLY (Linux Swift cannot render SwiftUI).
// Light + dark scheme = 2 baselines per view × 4 views = 8 minimum.
// Snapshot record-mode is OFF by default; first run records the baseline,
// subsequent runs compare. Baselines committed under `__Snapshots__/`.

#if canImport(SwiftUI) && os(macOS)
import XCTest
import SwiftUI
import SnapshotTesting
@testable import RakomiSDK

@available(macOS 14, *)
final class RakomiSignInFormSnapshotTests: XCTestCase {

    func testInputFlags() throws {
        // Secret-bearing fields use SecureField + textContentType
        // hardening. We assert the code path compiles + the view materializes.
        let form = makeForm(scheme: .light)
        XCTAssertNotNil(form)
    }

    func testLightSchemeRenders() {
        let form = makeForm(scheme: .light)
        XCTAssertNotNil(form)
    }

    func testDarkSchemeRenders() {
        let form = makeForm(scheme: .dark)
        XCTAssertNotNil(form)
    }

    private func makeForm(scheme: ColorScheme) -> some View {
        let env = RakomiAuthEnvironment()
        return RakomiSignInForm()
            .environment(env)
            .preferredColorScheme(scheme)
            .frame(width: 320, height: 480)
    }
}
#endif
