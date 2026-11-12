// Controller-level state machine smoke tests.

import XCTest

@testable import RakomiSDK

final class AuthControllerTests: XCTestCase {

    func testInitialStateIsLoading() async throws {
        let configuration = try RakomiAuthConfiguration(
            publishableKey: "pk_test_t1",
            redirectURI: URL(string: "rakomi://callback")!,
            apiBaseURL: URL(string: "https://api.rakomi.test")!
        )
        let auth = RakomiAuth(configuration: configuration, adapter: TestAdapter())
        let state = await auth.controller.currentState()
        XCTAssertEqual(state, .loading)
    }

    func testTenantIdParsedFromPublishableKey() throws {
        let cfg = try RakomiAuthConfiguration(
            publishableKey: "pk_live_acme_inc",
            redirectURI: URL(string: "myapp://callback")!,
            apiBaseURL: URL(string: "https://api.rakomi.test")!
        )
        XCTAssertEqual(cfg.tenantId, "acme_inc")
    }

    func testRedirectURISchemeGuardRejectsHttps() {
        XCTAssertThrowsError(
            try RakomiAuthConfiguration(
                publishableKey: "pk_test_t1",
                redirectURI: URL(string: "https://evil.example/callback")!,
                apiBaseURL: URL(string: "https://api.rakomi.test")!
            )
        )
    }

    func testRedirectURISchemeGuardRejectsJavascript() {
        XCTAssertThrowsError(
            try RakomiAuthConfiguration(
                publishableKey: "pk_test_t1",
                redirectURI: URL(string: "javascript://x")!,
                apiBaseURL: URL(string: "https://api.rakomi.test")!
            )
        )
    }

    func testApiBaseURLMustBeHttps() {
        XCTAssertThrowsError(
            try RakomiAuthConfiguration(
                publishableKey: "pk_test_t1",
                redirectURI: URL(string: "myapp://callback")!,
                apiBaseURL: URL(string: "http://evil.example")!
            )
        )
    }

    func testApiBaseURLLoopbackBypass() {
        XCTAssertNoThrow(
            try RakomiAuthConfiguration(
                publishableKey: "pk_test_t1",
                redirectURI: URL(string: "myapp://callback")!,
                apiBaseURL: URL(string: "http://localhost:3001")!
            )
        )
        XCTAssertNoThrow(
            try RakomiAuthConfiguration(
                publishableKey: "pk_test_t1",
                redirectURI: URL(string: "myapp://callback")!,
                apiBaseURL: URL(string: "http://127.0.0.1:3001")!
            )
        )
    }

    func testApiBaseURLLoopbackRegexAnchored() {
        // Regression: an unanchored regex allowed `localhost.evil.com`. Confirm
        // the Swift port rejects this attack vector.
        XCTAssertThrowsError(
            try RakomiAuthConfiguration(
                publishableKey: "pk_test_t1",
                redirectURI: URL(string: "myapp://callback")!,
                apiBaseURL: URL(string: "http://attacker.localhost.example.com")!
            )
        )
        XCTAssertThrowsError(
            try RakomiAuthConfiguration(
                publishableKey: "pk_test_t1",
                redirectURI: URL(string: "myapp://callback")!,
                apiBaseURL: URL(string: "http://10.example.com")!
            )
        )
    }

    func testEmptyPublishableKeyRejected() {
        XCTAssertThrowsError(
            try RakomiAuthConfiguration(
                publishableKey: "",
                redirectURI: URL(string: "myapp://callback")!,
                apiBaseURL: URL(string: "https://api.rakomi.test")!
            )
        )
    }
}
