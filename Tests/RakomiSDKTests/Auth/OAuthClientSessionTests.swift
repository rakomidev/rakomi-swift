// A session issued to an OAuth client (browser sign-in, authorization code)
// refreshes and ends at the OAuth endpoints, with its client_id.
//
// The server answers `/v1/auth/refresh` for such a session like an unknown token
// (it authenticates no client there), so the SDK records which client made the
// session, keeps that across a cold start, and refreshes it at the published
// token endpoint (RFC 6749 §6). Sign-out revokes its refresh token at the
// published revocation endpoint (RFC 7009). A first-party session (password,
// MFA, magic link, native Apple, device code) keeps `/v1/auth/refresh`, and its
// sign-out calls `/v1/auth/logout` with the access token that route reads.

import XCTest

@testable import RakomiSDK

// MARK: - Test doubles

/// Answers refresh POSTs from a script and records where each one went.
private actor RoutingTransport: DpopRefreshTransport {
    private var queue: [DpopRefreshHTTPResult]
    private(set) var endpoints: [RefreshEndpoint] = []
    private(set) var proofs: [String?] = []
    private(set) var tokens: [String] = []

    init(_ results: [DpopRefreshHTTPResult]) { self.queue = results }

    func sendRefresh(
        refreshToken: String,
        endpoint: RefreshEndpoint,
        dpopProof: String?
    ) async throws -> DpopRefreshHTTPResult {
        tokens.append(refreshToken)
        endpoints.append(endpoint)
        proofs.append(dpopProof)
        if queue.isEmpty {
            return DpopRefreshHTTPResult(
                statusCode: 503,
                body: Data(),
                dpopNonce: nil,
                useDpopNonceChallenge: false,
                dpopProofRejected: false
            )
        }
        return queue.removeFirst()
    }
}

/// One request the stub served.
private struct SeenRequest: Sendable {
    let method: String
    let url: URL
    let headers: [String: String]
    let body: String
}

/// Serves canned responses by `host + path` and records every request. A path
/// with no response fails at the transport.
private final class RecordingURLProtocol: URLProtocol {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var responses: [String: (Int, Data)] = [:]
    nonisolated(unsafe) private static var seen: [SeenRequest] = []

    static func reset() {
        lock.lock()
        responses = [:]
        seen = []
        lock.unlock()
    }

    static func respond(_ url: String, status: Int = 200, body: Data = Data("{}".utf8)) {
        let u = URL(string: url)!
        lock.lock()
        responses["\(u.host ?? "")\(u.path)"] = (status, body)
        lock.unlock()
    }

    static func requests() -> [SeenRequest] {
        lock.lock()
        defer { lock.unlock() }
        return seen
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                body.append(buffer, count: n)
            }
            stream.close()
        }
        Self.lock.lock()
        Self.seen.append(
            SeenRequest(
                method: request.httpMethod ?? "GET",
                url: url,
                headers: request.allHTTPHeaderFields ?? [:],
                body: String(decoding: body, as: UTF8.self)
            )
        )
        let canned = Self.responses["\(url.host ?? "")\(url.path)"]
        Self.lock.unlock()
        guard let (status, data) = canned,
            let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: [:])
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// `TestAdapter` whose clock stands at the fixture tokens' mint time.
private actor FixtureClockAdapter: RakomiNativeAdapter {
    let inner: TestAdapter
    let at: Date

    init(at: Date, inner: TestAdapter = TestAdapter()) {
        self.at = at
        self.inner = inner
    }

    func storageRead(key: String) async -> String? { await inner.storageRead(key: key) }
    func storageWrite(key: String, value: String) async -> StorageWriteResult {
        await inner.storageWrite(key: key, value: value)
    }
    func storageDelete(key: String) async { await inner.storageDelete(key: key) }
    func storageDeleteAll(prefix: String) async { await inner.storageDeleteAll(prefix: prefix) }
    func storageHas(key: String) async -> Bool { await inner.storageHas(key: key) }
    func userDefaultsRead(key: String) async -> String? { await inner.userDefaultsRead(key: key) }
    func userDefaultsWrite(key: String, value: String) async { await inner.userDefaultsWrite(key: key, value: value) }
    func userDefaultsDelete(key: String) async { await inner.userDefaultsDelete(key: key) }
    func launchSystemBrowser(url: URL, callbackScheme: String) async -> BrowserAuthSessionResult {
        await inner.launchSystemBrowser(url: url, callbackScheme: callbackScheme)
    }
    func biometricAvailable() async -> Bool { await inner.biometricAvailable() }
    func requestBiometric(reason: String) async -> BiometricResult { await inner.requestBiometric(reason: reason) }
    func supportsNativePasskey() async -> Bool { false }
    nonisolated var connectivityStream: AsyncStream<ConnectivityState> { inner.connectivityStream }
    nonisolated var lifecycleStream: AsyncStream<AppLifecycleEvent> { inner.lifecycleStream }
    nonisolated func now() -> Date { at }
}

private struct Fixtures {
    let token: String
    let issuer: String
    let audience: String
    let jwks: Data
    let mintedAt: Date

    static func load() throws -> Fixtures {
        let bundle = Bundle.module
        guard
            let url = bundle.url(forResource: "jwt_fixtures", withExtension: "json", subdirectory: "Fixtures")
                ?? bundle.url(forResource: "Fixtures/jwt_fixtures", withExtension: "json")
                ?? bundle.url(forResource: "jwt_fixtures", withExtension: "json")
        else { throw XCTSkip("Fixture jwt_fixtures.json not found in test bundle") }
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let happy = try XCTUnwrap((root["tokens"] as? [String: Any])?["happy"] as? String)
        let payload = try XCTUnwrap(decodeSegment(happy, index: 1))
        let iat = try XCTUnwrap(payload["iat"] as? Double)
        return Fixtures(
            token: happy,
            issuer: try XCTUnwrap(root["issuer"] as? String),
            audience: try XCTUnwrap(root["audience"] as? String),
            jwks: try JSONSerialization.data(withJSONObject: try XCTUnwrap(root["jwks"])),
            mintedAt: Date(timeIntervalSince1970: iat + 1)
        )
    }

    func ok(refreshToken: String = "rt_rotated", tokenType: String = "Bearer") -> DpopRefreshHTTPResult {
        let obj: [String: Any] = [
            "access_token": token,
            "refresh_token": refreshToken,
            "expires_in": 3600,
            "token_type": tokenType,
        ]
        return DpopRefreshHTTPResult(
            statusCode: 200,
            body: try! JSONSerialization.data(withJSONObject: obj),
            dpopNonce: nil,
            useDpopNonceChallenge: false,
            dpopProofRejected: false
        )
    }
}

/// The JSON object in segment `index` of a compact JWT.
private func decodeSegment(_ jwt: String, index: Int) -> [String: Any]? {
    let segments = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard segments.count > index else { return nil }
    var b64 = String(segments[index]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while b64.count % 4 != 0 { b64.append("=") }
    guard let data = Data(base64Encoded: b64) else { return nil }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
}

private func formFields(_ body: String) -> [String: String] {
    var out: [String: String] = [:]
    for pair in body.split(separator: "&") {
        let kv = pair.split(separator: "=", maxSplits: 1).map { String($0).removingPercentEncoding ?? String($0) }
        if kv.count == 2 { out[kv[0]] = kv[1] }
    }
    return out
}

// MARK: - Tests

final class OAuthClientSessionTests: XCTestCase {

    private let clientId = "client_browser_app"
    private let jwksHost = "jwks.oauth-client-session.test"

    private struct Harness {
        let controller: RakomiAuthController
        let adapter: FixtureClockAdapter
        let transport: RoutingTransport
        let configuration: RakomiAuthConfiguration
        let tokenEndpoint: URL
        let revocationEndpoint: URL

        var refreshKey: String { StorageKeys.refreshToken(tenantId: configuration.tenantId) }
        var clientKey: String { StorageKeys.oauthClientId(tenantId: configuration.tenantId) }
    }

    override func setUp() {
        super.setUp()
        RecordingURLProtocol.reset()
    }

    private func makeHarness(
        _ script: [DpopRefreshHTTPResult],
        fixtures: Fixtures,
        inner: TestAdapter = TestAdapter(),
        publishableKey: String? = nil,
        seedMetadata: Bool = true
    ) async throws -> Harness {
        RecordingURLProtocol.respond("https://\(jwksHost)/.well-known/jwks.json", body: fixtures.jwks)
        let configuration = try RakomiAuthConfiguration(
            publishableKey: publishableKey ?? "pk_test_client_\(UUID().uuidString.prefix(8))",
            redirectURI: URL(string: "com.rakomi.quickstart://callback")!,
            apiBaseURL: URL(string: fixtures.issuer)!,
            issuer: URL(string: fixtures.issuer)!,
            jwksURL: URL(string: "https://\(jwksHost)/.well-known/jwks.json")!,
            clientId: clientId,
            audience: fixtures.audience
        )
        let stub = URLSessionConfiguration.ephemeral
        stub.protocolClasses = [RecordingURLProtocol.self]
        let adapter = FixtureClockAdapter(at: fixtures.mintedAt, inner: inner)
        let controller = RakomiAuthController(
            configuration: configuration,
            adapter: adapter,
            jwksSession: URLSession(configuration: stub),
            apiSession: URLSession(configuration: stub)
        )
        await controller.setRefreshBackoff([])
        let tokenEndpoint = URL(string: "\(fixtures.issuer)/oauth/token")!
        let revocationEndpoint = URL(string: "\(fixtures.issuer)/oauth/revoke")!
        if seedMetadata {
            await controller.seedAuthorizationServerMetadata(
                AuthorizationServerMetadata(
                    issuer: fixtures.issuer,
                    authorizationEndpoint: URL(string: "https://accounts.rakomi.test/authorize")!,
                    tokenEndpoint: tokenEndpoint,
                    revocationEndpoint: revocationEndpoint
                )
            )
        }
        let transport = RoutingTransport(script)
        await controller.setDpopTransport(transport)
        return Harness(
            controller: controller,
            adapter: adapter,
            transport: transport,
            configuration: configuration,
            tokenEndpoint: tokenEndpoint,
            revocationEndpoint: revocationEndpoint
        )
    }

    private func signIn(_ h: Harness, fixtures: Fixtures, oauthClientId: String?) async throws {
        try await h.controller.completeSignIn(
            accessToken: fixtures.token,
            refreshToken: "rt_signed_in",
            expiresIn: 3600,
            oauthClientId: oauthClientId
        )
    }

    // MARK: Refresh routing

    func testAClientSessionRefreshesAtTheTokenEndpointWithItsClientId() async throws {
        let fixtures = try Fixtures.load()
        let h = try await makeHarness([fixtures.ok()], fixtures: fixtures)
        try await signIn(h, fixtures: fixtures, oauthClientId: clientId)
        let marker = await h.adapter.storageRead(key: h.clientKey)
        XCTAssertEqual(marker, clientId, "the session's client was not recorded")

        _ = try await h.controller.refresh(force: true)

        let endpoints = await h.transport.endpoints
        XCTAssertEqual(endpoints, [.tokenEndpoint(h.tokenEndpoint, clientId: clientId)])
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertEqual(stored, "rt_rotated")
    }

    func testAFirstPartySessionRefreshesAtV1AuthRefresh() async throws {
        let fixtures = try Fixtures.load()
        let h = try await makeHarness([fixtures.ok()], fixtures: fixtures)
        try await signIn(h, fixtures: fixtures, oauthClientId: nil)
        let marker = await h.adapter.storageRead(key: h.clientKey)
        XCTAssertNil(marker)

        _ = try await h.controller.refresh(force: true)

        let endpoints = await h.transport.endpoints
        XCTAssertEqual(endpoints, [.firstParty])
    }

    func testAFirstPartySignInAfterAClientSessionDropsTheClient() async throws {
        let fixtures = try Fixtures.load()
        let h = try await makeHarness([fixtures.ok()], fixtures: fixtures)
        try await signIn(h, fixtures: fixtures, oauthClientId: clientId)
        try await signIn(h, fixtures: fixtures, oauthClientId: nil)

        _ = try await h.controller.refresh(force: true)

        let endpoints = await h.transport.endpoints
        XCTAssertEqual(endpoints, [.firstParty], "a stale client marker routed a first-party session")
    }

    func testColdStartRestoresTheClientRouting() async throws {
        let fixtures = try Fixtures.load()
        let inner = TestAdapter()
        let publishableKey = "pk_test_cold_\(UUID().uuidString.prefix(8))"
        let first = try await makeHarness([], fixtures: fixtures, inner: inner, publishableKey: publishableKey)
        try await signIn(first, fixtures: fixtures, oauthClientId: clientId)

        // A new launch: a fresh controller over the same storage.
        let second = try await makeHarness(
            [fixtures.ok()],
            fixtures: fixtures,
            inner: inner,
            publishableKey: publishableKey
        )
        await second.controller.hydrate()

        let state = await second.controller.currentState()
        guard case .authenticated = state else { return XCTFail("expected authenticated, got \(state)") }
        let endpoints = await second.transport.endpoints
        XCTAssertEqual(endpoints, [.tokenEndpoint(second.tokenEndpoint, clientId: clientId)])
        let tokens = await second.transport.tokens
        XCTAssertEqual(tokens, ["rt_signed_in"])
    }

    func testADpopBoundClientSessionSignsItsProofForTheTokenEndpoint() async throws {
        let fixtures = try Fixtures.load()
        let h = try await makeHarness([fixtures.ok(tokenType: "DPoP")], fixtures: fixtures)
        let dpop = try await h.controller.enableDpop(prover: CryptoKitDpopProver(preferSecureEnclave: false))
        await dpop.observeTokenType("DPoP", attachedProof: true)
        try await signIn(h, fixtures: fixtures, oauthClientId: clientId)

        _ = try await h.controller.refresh(force: true)

        let proofs = await h.transport.proofs
        let proof = try XCTUnwrap(proofs.first ?? nil, "the bound session attached no proof")
        let claims = try XCTUnwrap(decodeSegment(proof, index: 1))
        XCTAssertEqual(claims["htu"] as? String, h.tokenEndpoint.absoluteString)
        XCTAssertEqual(claims["htm"] as? String, "POST")
    }

    func testUnavailableMetadataKeepsTheClientSession() async throws {
        let fixtures = try Fixtures.load()
        let h = try await makeHarness([fixtures.ok()], fixtures: fixtures, seedMetadata: false)
        try await signIn(h, fixtures: fixtures, oauthClientId: clientId)

        do {
            _ = try await h.controller.refresh(force: true)
            XCTFail("a refresh without the token endpoint must not succeed")
        } catch let err as SdkError {
            XCTAssertTrue(RefreshFailure.keepsSession(err), "metadata unavailability is transient: \(err)")
        }
        let calls = await h.transport.tokens
        XCTAssertEqual(calls, [], "no refresh may go to /v1/auth/refresh for a client session")
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertEqual(stored, "rt_signed_in")
        let marker = await h.adapter.storageRead(key: h.clientKey)
        XCTAssertEqual(marker, clientId)
    }

    func testARejectedClientRefreshClearsTheSessionAndTheClient() async throws {
        let fixtures = try Fixtures.load()
        let rejected = DpopRefreshHTTPResult(
            statusCode: 400,
            body: Data(#"{"error":"invalid_grant"}"#.utf8),
            dpopNonce: nil,
            useDpopNonceChallenge: false,
            dpopProofRejected: false
        )
        let h = try await makeHarness([rejected], fixtures: fixtures)
        try await signIn(h, fixtures: fixtures, oauthClientId: clientId)

        _ = try? await h.controller.refresh(force: true)

        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored)
        let marker = await h.adapter.storageRead(key: h.clientKey)
        XCTAssertNil(marker)
    }

    // MARK: The production transport

    func testTheTransportPostsAClientRefreshFormEncodedToTheTokenEndpoint() async throws {
        let tokenURL = URL(string: "https://api.transport.test/oauth/token")!
        RecordingURLProtocol.respond(tokenURL.absoluteString, body: Data(#"{"access_token":"at"}"#.utf8))
        let stub = URLSessionConfiguration.ephemeral
        stub.protocolClasses = [RecordingURLProtocol.self]
        let client = HTTPClient(
            baseURL: URL(string: "https://api.transport.test")!,
            publishableKey: "pk_test_transport",
            session: URLSession(configuration: stub)
        )
        let transport = HTTPClientDpopRefreshTransport(httpClient: client)

        let result = try await transport.sendRefresh(
            refreshToken: "sid:raw",
            endpoint: .tokenEndpoint(tokenURL, clientId: "client_x"),
            dpopProof: "proof.jwt.value"
        )

        XCTAssertEqual(result.statusCode, 200)
        let seen = try XCTUnwrap(RecordingURLProtocol.requests().last)
        XCTAssertEqual(seen.method, "POST")
        XCTAssertEqual(seen.url, tokenURL)
        XCTAssertEqual(seen.headers["Content-Type"], "application/x-www-form-urlencoded")
        XCTAssertEqual(seen.headers["DPoP"], "proof.jwt.value")
        XCTAssertEqual(
            formFields(seen.body),
            ["grant_type": "refresh_token", "refresh_token": "sid:raw", "client_id": "client_x"]
        )
    }

    func testTheTransportPostsAFirstPartyRefreshToV1AuthRefresh() async throws {
        RecordingURLProtocol.respond("https://api.transport.test/v1/auth/refresh", body: Data("{}".utf8))
        let stub = URLSessionConfiguration.ephemeral
        stub.protocolClasses = [RecordingURLProtocol.self]
        let client = HTTPClient(
            baseURL: URL(string: "https://api.transport.test")!,
            publishableKey: "pk_test_transport",
            session: URLSession(configuration: stub)
        )
        let transport = HTTPClientDpopRefreshTransport(httpClient: client)

        _ = try await transport.sendRefresh(refreshToken: "sid:raw", endpoint: .firstParty, dpopProof: nil)

        let seen = try XCTUnwrap(RecordingURLProtocol.requests().last)
        XCTAssertEqual(seen.url.path, "/v1/auth/refresh")
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(seen.body.utf8)) as? [String: String])
        XCTAssertEqual(json, ["refresh_token": "sid:raw"])
        XCTAssertNil(seen.headers["DPoP"])
    }

    // MARK: Sign-out

    func testSigningOutAClientSessionRevokesItsRefreshTokenAtTheRevocationEndpoint() async throws {
        let fixtures = try Fixtures.load()
        let h = try await makeHarness([], fixtures: fixtures)
        RecordingURLProtocol.respond(h.revocationEndpoint.absoluteString)
        try await signIn(h, fixtures: fixtures, oauthClientId: clientId)

        await h.controller.signOut()

        let api = RecordingURLProtocol.requests().filter { $0.url.host == h.revocationEndpoint.host }
        XCTAssertEqual(api.map(\.url.path), ["/oauth/revoke"], "expected one revocation and no /v1/auth/logout")
        let revoke = try XCTUnwrap(api.first)
        XCTAssertEqual(revoke.method, "POST")
        XCTAssertEqual(
            formFields(revoke.body),
            ["token": "rt_signed_in", "token_type_hint": "refresh_token", "client_id": clientId]
        )
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored)
        let marker = await h.adapter.storageRead(key: h.clientKey)
        XCTAssertNil(marker, "sign-out left the client marker behind")
        let state = await h.controller.currentState()
        guard case .signedOut = state else { return XCTFail("expected signedOut, got \(state)") }
    }

    func testSigningOutAFirstPartySessionCallsLogoutWithItsAccessToken() async throws {
        let fixtures = try Fixtures.load()
        let h = try await makeHarness([], fixtures: fixtures)
        RecordingURLProtocol.respond("\(fixtures.issuer)/v1/auth/logout", status: 204, body: Data())
        try await signIn(h, fixtures: fixtures, oauthClientId: nil)

        await h.controller.signOut()

        let api = RecordingURLProtocol.requests().filter { $0.url.host == URL(string: fixtures.issuer)!.host }
        XCTAssertEqual(api.map(\.url.path), ["/v1/auth/logout"])
        let logout = try XCTUnwrap(api.first)
        XCTAssertEqual(logout.headers["Authorization"], "Bearer \(fixtures.token)")
        XCTAssertFalse(logout.body.contains("rt_signed_in"), "the refresh token is not the logout credential")
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored)
    }

    func testSigningOutClearsLocallyWhenTheServerIsUnreachable() async throws {
        let fixtures = try Fixtures.load()
        let h = try await makeHarness([], fixtures: fixtures)
        try await signIn(h, fixtures: fixtures, oauthClientId: clientId)

        await h.controller.signOut()

        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored)
        let marker = await h.adapter.storageRead(key: h.clientKey)
        XCTAssertNil(marker)
    }
}
