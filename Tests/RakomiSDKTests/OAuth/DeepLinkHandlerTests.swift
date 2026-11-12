// Deep links: synthetic URL ingestion.

import XCTest

@testable import RakomiSDK

final class DeepLinkHandlerTests: XCTestCase {

    func testIdempotentIngest() async throws {
        let configuration = try RakomiAuthConfiguration(
            publishableKey: "pk_test_t1",
            redirectURI: URL(string: "rakomi://callback")!,
            apiBaseURL: URL(string: "https://api.rakomi.test")!
        )
        let adapter = TestAdapter()
        let auth = RakomiAuth(configuration: configuration, adapter: adapter)

        // Initial deep link with state X — second call with same state is a no-op.
        let url = URL(string: "rakomi://callback?code=c1&state=X&ott=ott_one")!
        await auth.handleCallbackURL(url)
        await auth.handleCallbackURL(url)
        // No assertion crash — handler swallows failures into authStateChanges.
    }

    func testCallbackMissingState() async throws {
        let configuration = try RakomiAuthConfiguration(
            publishableKey: "pk_test_t1",
            redirectURI: URL(string: "rakomi://callback")!,
            apiBaseURL: URL(string: "https://api.rakomi.test")!
        )
        let adapter = TestAdapter()
        let auth = RakomiAuth(configuration: configuration, adapter: adapter)

        let url = URL(string: "rakomi://callback?code=c1")!
        // Should be silent (no crash).
        await auth.handleCallbackURL(url)
    }
}
