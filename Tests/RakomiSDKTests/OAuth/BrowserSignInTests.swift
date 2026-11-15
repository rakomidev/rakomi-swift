// The browser sign-in flow, in both directions.
//
// It used to call `/v1/auth/oauth/start` and `/v1/auth/oauth/callback`, paths
// that have never existed. An operator tapping a provider button on the SDK's
// own sign-in form was sent to a browser sheet showing 404 — recorded in the
// API log as `GET /v1/auth/oauth/start → 404`. The flow is now the standard
// authorization-code exchange with PKCE against the endpoints the server
// publishes, and a configuration that cannot perform it says so instead of
// opening a browser.

import XCTest

@testable import RakomiSDK

final class BrowserSignInTests: XCTestCase {

    private func configuration(clientId: String?) throws -> RakomiAuthConfiguration {
        try RakomiAuthConfiguration(
            publishableKey: "pk_test_browser",
            redirectURI: URL(string: "com.rakomi.quickstart://callback")!,
            apiBaseURL: URL(string: "https://api.example.test")!,
            clientId: clientId
        )
    }

    // MARK: - Fail closed

    func testAConfigurationWithoutAClientIdCannotStartABrowserSignIn() throws {
        let without = try configuration(clientId: nil)
        let empty = try configuration(clientId: "")
        let with = try configuration(clientId: "client_abc")

        XCTAssertFalse(without.supportsBrowserSignIn)
        XCTAssertFalse(empty.supportsBrowserSignIn, "an empty client id is not a client id")
        XCTAssertTrue(with.supportsBrowserSignIn)
    }

    func testSignInWithProviderReportsNotConfiguredAndNeverOpensABrowser() async throws {
        let adapter = TestAdapter()
        let auth = RakomiAuth(configuration: try configuration(clientId: nil), adapter: adapter)
        let recorder = StateCollector()
        let observer = Task { for await s in auth.authStateChanges() { await recorder.record(s) } }
        defer { observer.cancel() }
        try await Task.sleep(nanoseconds: 150_000_000)

        await auth.signIn(withProvider: .google)
        try await Task.sleep(nanoseconds: 250_000_000)

        let errors = await recorder.errors
        let seen = await recorder.labels
        XCTAssertEqual(errors.count, 1, "expected exactly one error, saw \(seen)")
        XCTAssertEqual(errors.first?.code, .invalidConfig)
        XCTAssertEqual(errors.first?.reason, .notConfigured)
        XCTAssertEqual(errors.first?.redactedMessage, "oauth_client_id_missing")

        let launches = await adapter.browserLaunchCount
        XCTAssertEqual(launches, 0, "no browser may be opened on a request the server must reject")
    }

    /// The other polarity: with a client id the flow gets past the guard and
    /// fails at the network instead, which is what proves the guard was the only
    /// thing stopping it.
    func testWithAClientIdTheFlowProceedsPastTheGuard() async throws {
        let adapter = TestAdapter()
        let auth = RakomiAuth(configuration: try configuration(clientId: "client_abc"), adapter: adapter)
        let recorder = StateCollector()
        let observer = Task { for await s in auth.authStateChanges() { await recorder.record(s) } }
        defer { observer.cancel() }
        try await Task.sleep(nanoseconds: 150_000_000)

        await auth.signIn(withProvider: .google)
        try await Task.sleep(nanoseconds: 1_500_000_000)

        let errors = await recorder.errors
        XCTAssertFalse(errors.isEmpty)
        XCTAssertNotEqual(
            errors.first?.reason,
            .notConfigured,
            "the configuration guard fired even though a client id was supplied"
        )
    }

    // MARK: - The endpoints are discovered, not guessed

    func testMetadataIsDecodedFromTheDiscoveryDocument() throws {
        let json = """
            {"issuer":"https://api.example.test",
             "authorization_endpoint":"https://accounts.example.test/authorize",
             "token_endpoint":"https://api.example.test/oauth/token"}
            """
        let metadata = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: Data(json.utf8))
        XCTAssertEqual(metadata.authorizationEndpoint.host, "accounts.example.test")
        XCTAssertEqual(metadata.tokenEndpoint.path, "/oauth/token")
    }

    func testTheAuthorizationHostNeedNotBeTheApiHost() throws {
        // The reason discovery exists: constructing `<apiBaseURL>/oauth/authorize`
        // points a browser at a JSON endpoint on the wrong host.
        let json = """
            {"issuer":"https://api.example.test",
             "authorization_endpoint":"https://accounts.example.test/authorize",
             "token_endpoint":"https://api.example.test/oauth/token"}
            """
        let metadata = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: Data(json.utf8))
        XCTAssertNotEqual(metadata.authorizationEndpoint.host, metadata.tokenEndpoint.host)
    }

    // MARK: - The token request is form-encoded, per RFC 6749 §4.1.3

    func testFormEncodingIsStableAndEscapesReservedCharacters() {
        let encoded = HTTPClient.formEncode([
            "grant_type": "authorization_code",
            "redirect_uri": "com.rakomi.quickstart://callback",
            "code": "a+b c",
        ])
        XCTAssertEqual(
            encoded,
            "code=a%2Bb%20c&grant_type=authorization_code&redirect_uri=com.rakomi.quickstart%3A%2F%2Fcallback"
        )
    }

    // MARK: - The paths that never existed must not come back

    func testTheRetiredPathsAreGoneFromTheSource() throws {
        // #filePath is Tests/RakomiSDKTests/OAuth/<this file>; the package root
        // is four levels up.
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: packageRoot.appendingPathComponent("Sources/RakomiSDK/OAuth/SocialAuth.swift"),
            encoding: .utf8
        )
        XCTAssertFalse(source.contains("/v1/auth/oauth/start"), "the 404 path is back")
        XCTAssertFalse(source.contains("/v1/auth/oauth/callback"), "the 404 path is back")
        XCTAssertTrue(source.contains("authorization_code"))
        XCTAssertTrue(source.contains("code_challenge"))
    }
}

/// Records emitted states for assertions.
actor StateCollector {
    private(set) var states: [AuthState] = []
    func record(_ s: AuthState) { states.append(s) }
    var errors: [SdkError] {
        states.compactMap { state -> SdkError? in
            guard case .error(let e) = state else { return nil }
            return e
        }
    }
    var labels: [String] {
        states.map {
            switch $0 {
            case .loading: return "loading"
            case .signedOut: return "signedOut"
            case .authenticated: return "authenticated"
            case .error(let e): return "error(\(e.reason.wire))"
            }
        }
    }
}
