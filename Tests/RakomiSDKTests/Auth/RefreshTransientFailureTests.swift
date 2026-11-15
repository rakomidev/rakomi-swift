// A refresh that fails for a TRANSIENT reason must keep the session.
//
// A 5xx, 429 or 408 from the refresh endpoint, or a transport failure, says the
// server could not answer right now — not that the grant is bad. Signing the
// user out on it turns a short outage into a forced re-login for everyone who
// refreshed during it. Only a definitive rejection (a bare 401, or a 4xx naming
// the grant or client as invalid) ends the session. A server-sent Retry-After
// is honoured: no refresh hits the network before it elapses.
//
// Both refresh paths are covered — Bearer and DPoP-bound — plus cold start.

import XCTest

@testable import RakomiSDK

// MARK: - Test doubles

/// Answers refresh POSTs from a script; an exhausted script answers 503.
private actor ScriptedRefreshTransport: DpopRefreshTransport {
    private var queue: [DpopRefreshHTTPResult]
    private(set) var presentedTokens: [String] = []
    private(set) var presentedProofs: [String?] = []

    init(_ results: [DpopRefreshHTTPResult]) { self.queue = results }

    func sendRefresh(refreshToken: String, dpopProof: String?) async throws -> DpopRefreshHTTPResult {
        presentedTokens.append(refreshToken)
        presentedProofs.append(dpopProof)
        if queue.isEmpty { return response(503) }
        return queue.removeFirst()
    }

    func callCount() -> Int { presentedTokens.count }
    func tokens() -> [String] { presentedTokens }
}

/// A clock the test can move.
private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date
    init(_ start: Date) { value = start }
    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
    func advance(_ seconds: TimeInterval) {
        lock.lock()
        value = value.addingTimeInterval(seconds)
        lock.unlock()
    }
}

/// `TestAdapter` with a controllable clock (the fixture tokens are verified
/// against the moment they were minted, never the wall clock).
private actor ClockedAdapter: RakomiNativeAdapter {
    let inner = TestAdapter()
    let clock: TestClock

    init(clock: TestClock) { self.clock = clock }

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
    nonisolated func now() -> Date { clock.now }
}

private func response(
    _ status: Int,
    body: String = "{}",
    retryAfter: String? = nil
) -> DpopRefreshHTTPResult {
    DpopRefreshHTTPResult(
        statusCode: status,
        body: Data(body.utf8),
        dpopNonce: nil,
        useDpopNonceChallenge: false,
        dpopProofRejected: false,
        retryAfter: retryAfter
    )
}

// MARK: - Fixtures

private struct TokenFixtures {
    let happyToken: String
    let issuer: String
    let audience: String
    let jwksJSON: Data
    let mintedAt: Date

    static func load() throws -> TokenFixtures {
        let bundle = Bundle.module
        guard
            let url = bundle.url(forResource: "jwt_fixtures", withExtension: "json", subdirectory: "Fixtures")
                ?? bundle.url(forResource: "Fixtures/jwt_fixtures", withExtension: "json")
                ?? bundle.url(forResource: "jwt_fixtures", withExtension: "json")
        else { throw XCTSkip("Fixture jwt_fixtures.json not found in test bundle") }
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
        let tokens = try XCTUnwrap(root["tokens"] as? [String: Any])
        let happy = try XCTUnwrap(tokens["happy"] as? String)
        let segments = happy.split(separator: ".", omittingEmptySubsequences: false)
        var b64 = String(segments[1]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        let payload = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: XCTUnwrap(Data(base64Encoded: b64))) as? [String: Any]
        )
        let iat = try XCTUnwrap(payload["iat"] as? Double)
        return TokenFixtures(
            happyToken: happy,
            issuer: try XCTUnwrap(root["issuer"] as? String),
            audience: try XCTUnwrap(root["audience"] as? String),
            jwksJSON: try JSONSerialization.data(withJSONObject: try XCTUnwrap(root["jwks"])),
            mintedAt: Date(timeIntervalSince1970: iat + 1)
        )
    }

    func okBody(refreshToken: String = "rt_rotated") -> DpopRefreshHTTPResult {
        let obj: [String: Any] = [
            "access_token": happyToken,
            "refresh_token": refreshToken,
            "expires_in": 3600,
            "token_type": "Bearer",
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

// MARK: - Tests

final class RefreshTransientFailureTests: XCTestCase {

    private let storedRefreshToken = "rt_stored_credential"
    private let jwksHost = "jwks.refresh-transient.test"

    private struct Harness {
        let controller: RakomiAuthController
        let adapter: ClockedAdapter
        let transport: ScriptedRefreshTransport
        let clock: TestClock
        let refreshKey: String
    }

    private func makeHarness(
        _ script: [DpopRefreshHTTPResult],
        fixtures: TokenFixtures,
        dpopBound: Bool = false,
        biometricLock: Bool = false
    ) async throws -> Harness {
        StubURLProtocol.responses[jwksHost] = (fixtures.jwksJSON, 200, ["Content-Type": "application/json"])
        let config = try RakomiAuthConfiguration(
            publishableKey: "pk_test_transient_\(UUID().uuidString.prefix(8))",
            redirectURI: URL(string: "transient://callback")!,
            apiBaseURL: URL(string: fixtures.issuer)!,
            issuer: URL(string: fixtures.issuer)!,
            jwksURL: URL(string: "https://\(jwksHost)/.well-known/jwks.json")!,
            freshAuthWindow: 1,
            audience: fixtures.audience,
            requireBiometricUnlock: biometricLock
        )
        let clock = TestClock(fixtures.mintedAt)
        let adapter = ClockedAdapter(clock: clock)
        let refreshKey = StorageKeys.refreshToken(tenantId: config.tenantId)
        _ = await adapter.storageWrite(key: refreshKey, value: storedRefreshToken)
        let stubConfig = URLSessionConfiguration.ephemeral
        stubConfig.protocolClasses = [StubURLProtocol.self]
        let controller = RakomiAuthController(
            configuration: config,
            adapter: adapter,
            jwksSession: URLSession(configuration: stubConfig)
        )
        await controller.setRefreshBackoff([])
        if dpopBound {
            let session = try await controller.enableDpop(prover: CryptoKitDpopProver(preferSecureEnclave: false))
            await session.observeTokenType("DPoP", attachedProof: true)
        }
        let transport = ScriptedRefreshTransport(script)
        await controller.setDpopTransport(transport)
        return Harness(
            controller: controller,
            adapter: adapter,
            transport: transport,
            clock: clock,
            refreshKey: refreshKey
        )
    }

    private func refreshError(_ h: Harness) async -> SdkError? {
        do {
            _ = try await h.controller.refresh(force: true)
            return nil
        } catch {
            return error as? SdkError
        }
    }

    private func expectRefreshError(
        _ h: Harness,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws -> SdkError {
        let err = await refreshError(h)
        return try XCTUnwrap(err, "the refresh was expected to fail with a typed SdkError", file: file, line: line)
    }

    private func assertSessionKept(_ h: Harness, file: StaticString = #filePath, line: UInt = #line) async {
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertEqual(stored, storedRefreshToken, "the stored refresh token was discarded", file: file, line: line)
        let state = await h.controller.currentState()
        if case .signedOut = state {
            XCTFail("a transient refresh failure signed the user out", file: file, line: line)
        }
    }

    // MARK: Bearer

    func testBearer503KeepsSessionAndStoredCredential() async throws {
        let h = try await makeHarness([response(503)], fixtures: try TokenFixtures.load())
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.code, .refreshFailed)
        XCTAssertEqual(err.reason, .refreshNetwork)
        XCTAssertEqual(err.httpStatus, 503)
        await assertSessionKept(h)
    }

    func testBearer429IsTransientAndCarriesRetryAfter() async throws {
        let h = try await makeHarness([response(429, retryAfter: "7")], fixtures: try TokenFixtures.load())
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .refreshNetwork)
        XCTAssertEqual(err.httpStatus, 429)
        XCTAssertEqual(err.retryAfter, 7)
        await assertSessionKept(h)
    }

    func testBearer400InvalidGrantSignsOut() async throws {
        let h = try await makeHarness(
            [response(400, body: #"{"error":"invalid_grant"}"#)],
            fixtures: try TokenFixtures.load()
        )
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .refreshRevoked)
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored, "a definitive rejection must clear the stored credential")
        let state = await h.controller.currentState()
        guard case .signedOut = state else { return XCTFail("expected signedOut, got \(state)") }
        let calls = await h.transport.callCount()
        XCTAssertEqual(calls, 1, "a definitive rejection is never retried")
    }

    func testBearerBare401SignsOut() async throws {
        let h = try await makeHarness([response(401)], fixtures: try TokenFixtures.load())
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .refreshRevoked)
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored)
    }

    func testBearer403WithoutCodeKeepsSession() async throws {
        let h = try await makeHarness([response(403)], fixtures: try TokenFixtures.load())
        let err = try await expectRefreshError(h)
        XCTAssertNotEqual(err.reason, .refreshRevoked)
        XCTAssertEqual(err.httpStatus, 403)
        await assertSessionKept(h)
    }

    private func assertSignedOut(_ h: Harness, file: StaticString = #filePath, line: UInt = #line) async {
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored, "a definitive rejection must clear the stored credential", file: file, line: line)
        let state = await h.controller.currentState()
        guard case .signedOut = state else {
            return XCTFail("expected signedOut, got \(state)", file: file, line: line)
        }
    }

    /// The bodies the API answers a refresh with when the account is blocked or
    /// held pending parental consent: a 403 whose problem+json `code` names the
    /// reason (the server revokes the session before answering). Also the bare
    /// code and the legacy `{error: {code}}` envelope.
    private let sessionEnding403Bodies = [
        #"{"type":"about:blank","status":403,"code":"auth/user_blocked"}"#,
        #"{"code":"user_blocked"}"#,
        #"{"error":{"code":"auth/user_blocked","message":"Account is frozen"}}"#,
        #"{"code":"auth/pending_parental_consent"}"#,
    ]

    func testBearer403WithSessionEndingCodeSignsOut() async throws {
        for body in sessionEnding403Bodies {
            let h = try await makeHarness([response(403, body: body)], fixtures: try TokenFixtures.load())
            let err = try await expectRefreshError(h)
            XCTAssertEqual(err.reason, .refreshRevoked, body)
            XCTAssertEqual(err.httpStatus, 403, body)
            await assertSignedOut(h)
            let calls = await h.transport.callCount()
            XCTAssertEqual(calls, 1, "a definitive rejection is never retried (\(body))")
        }
    }

    func testBearer403WithNonDefinitiveCodeKeepsSession() async throws {
        let h = try await makeHarness(
            [response(403, body: #"{"code":"http/403"}"#)],
            fixtures: try TokenFixtures.load()
        )
        let err = try await expectRefreshError(h)
        XCTAssertNotEqual(err.reason, .refreshRevoked)
        await assertSessionKept(h)
    }

    /// A 2xx means the server consumed the presented refresh token. Presenting
    /// it again would be a reuse, which revokes every session of the user, so an
    /// unreadable success ends the session locally and is never re-sent.
    func testBearerUnreadableSuccessSignsOutWithoutResending() async throws {
        let fixtures = try TokenFixtures.load()
        let h = try await makeHarness([response(200, body: "<html>"), fixtures.okBody()], fixtures: fixtures)
        await h.controller.setRefreshBackoff([0, 0])
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .refreshRevoked)
        await assertSignedOut(h)
        let calls = await h.transport.callCount()
        XCTAssertEqual(calls, 1, "the consumed refresh token was presented again")
    }

    // MARK: DPoP-bound

    func testDpopBound408KeepsSessionAndBinding() async throws {
        let h = try await makeHarness([response(408)], fixtures: try TokenFixtures.load(), dpopBound: true)
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .network)
        XCTAssertEqual(err.httpStatus, 408)
        await assertSessionKept(h)
        let bound = await h.controller.currentDpopSession()?.isBound
        XCTAssertEqual(bound, true)
    }

    func testDpopBound403WithSessionEndingCodeSignsOut() async throws {
        for body in sessionEnding403Bodies {
            let h = try await makeHarness(
                [response(403, body: body)],
                fixtures: try TokenFixtures.load(),
                dpopBound: true
            )
            let err = try await expectRefreshError(h)
            XCTAssertEqual(err.reason, .invalidRefreshToken, body)
            await assertSignedOut(h)
        }
    }

    func testDpopBound403WithoutCodeKeepsSession() async throws {
        let h = try await makeHarness([response(403)], fixtures: try TokenFixtures.load(), dpopBound: true)
        let err = try await expectRefreshError(h)
        XCTAssertNotEqual(err.reason, .invalidRefreshToken)
        await assertSessionKept(h)
    }

    func testDpopBound503KeepsSessionAndBinding() async throws {
        let h = try await makeHarness([response(503)], fixtures: try TokenFixtures.load(), dpopBound: true)
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .network)
        XCTAssertEqual(err.httpStatus, 503)
        await assertSessionKept(h)
        let bound = await h.controller.currentDpopSession()?.isBound
        XCTAssertEqual(bound, true, "a transient failure must keep the DPoP key binding")
        let proofs = await h.transport.presentedProofs
        XCTAssertNotNil(proofs.first ?? nil, "the bound path attached a proof")
    }

    func testDpopBound429KeepsSessionAndBinding() async throws {
        let h = try await makeHarness(
            [response(429, retryAfter: "3")],
            fixtures: try TokenFixtures.load(),
            dpopBound: true
        )
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .network)
        XCTAssertEqual(err.retryAfter, 3)
        await assertSessionKept(h)
        let bound = await h.controller.currentDpopSession()?.isBound
        XCTAssertEqual(bound, true)
    }

    func testDpopBoundUnreadableSuccessBodySignsOutWithoutResending() async throws {
        let fixtures = try TokenFixtures.load()
        let h = try await makeHarness(
            [response(200, body: "<html>"), fixtures.okBody()],
            fixtures: fixtures,
            dpopBound: true
        )
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .invalidRefreshToken)
        XCTAssertFalse(RefreshFailure.keepsSession(err))
        await assertSignedOut(h)
        _ = await refreshError(h)
        let calls = await h.transport.callCount()
        XCTAssertEqual(calls, 1, "the consumed refresh token was presented again")
    }

    func testDpopBoundInvalidGrantStillSignsOut() async throws {
        let h = try await makeHarness(
            [response(400, body: #"{"error":"invalid_grant"}"#)],
            fixtures: try TokenFixtures.load(),
            dpopBound: true
        )
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.reason, .invalidRefreshToken)
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored)
    }

    // MARK: Retry-After

    func testRetryAfterDeltaSecondsIsParsedOntoTheError() async throws {
        let h = try await makeHarness([response(503, retryAfter: "30")], fixtures: try TokenFixtures.load())
        let err = try await expectRefreshError(h)
        XCTAssertEqual(err.retryAfter, 30)
    }

    func testRetryAfterHttpDateIsParsedOntoTheError() async throws {
        let fixtures = try TokenFixtures.load()
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        let header = formatter.string(from: fixtures.mintedAt.addingTimeInterval(90))
        let h = try await makeHarness([response(503, retryAfter: header)], fixtures: fixtures)
        let err = try await expectRefreshError(h)
        let seconds = try XCTUnwrap(err.retryAfter)
        XCTAssertEqual(seconds, 90, accuracy: 1.5)
    }

    func testUnparseableRetryAfterIsNotInvented() async throws {
        let h = try await makeHarness([response(503, retryAfter: "soon")], fixtures: try TokenFixtures.load())
        let err = try await expectRefreshError(h)
        XCTAssertNil(err.retryAfter)
    }

    func testNoRefreshHitsTheNetworkInsideTheRetryAfterWindow() async throws {
        let fixtures = try TokenFixtures.load()
        let h = try await makeHarness([response(503, retryAfter: "60"), fixtures.okBody()], fixtures: fixtures)

        let first = try await expectRefreshError(h)
        XCTAssertEqual(first.retryAfter, 60)
        h.clock.advance(30)
        let second = try await expectRefreshError(h)
        XCTAssertEqual(second.httpStatus, 503, "inside the window the held transient error is returned")
        var calls = await h.transport.callCount()
        XCTAssertEqual(calls, 1, "a refresh inside the Retry-After window reached the network")

        h.clock.advance(31)
        let session = try await h.controller.refresh(force: true)
        XCTAssertEqual(session.accessToken, fixtures.happyToken)
        calls = await h.transport.callCount()
        XCTAssertEqual(calls, 2)
    }

    func testNoBiometricPromptInsideTheRetryAfterWindow() async throws {
        let fixtures = try TokenFixtures.load()
        let h = try await makeHarness(
            [response(503, retryAfter: "60"), fixtures.okBody()],
            fixtures: fixtures,
            biometricLock: true
        )
        _ = try await expectRefreshError(h)
        var prompts = await h.adapter.inner.biometricRequestCount
        XCTAssertEqual(prompts, 1)

        h.clock.advance(30)
        _ = try await expectRefreshError(h)
        prompts = await h.adapter.inner.biometricRequestCount
        XCTAssertEqual(prompts, 1, "a refresh inside the Retry-After window prompted for biometrics")
        var calls = await h.transport.callCount()
        XCTAssertEqual(calls, 1)

        h.clock.advance(31)
        _ = try await h.controller.refresh(force: true)
        prompts = await h.adapter.inner.biometricRequestCount
        XCTAssertEqual(prompts, 2)
        calls = await h.transport.callCount()
        XCTAssertEqual(calls, 2)
    }

    func testRetryAfterIsCappedAtTwoMinutes() async throws {
        let fixtures = try TokenFixtures.load()
        let h = try await makeHarness([response(503, retryAfter: "86400"), fixtures.okBody()], fixtures: fixtures)
        _ = await refreshError(h)
        h.clock.advance(121)
        let session = try await h.controller.refresh(force: true)
        XCTAssertEqual(session.accessToken, fixtures.happyToken)
    }

    // MARK: Cold start

    func testColdStart503KeepsCredentialAndLaterGetTokenSucceeds() async throws {
        let fixtures = try TokenFixtures.load()
        let h = try await makeHarness([response(503), fixtures.okBody()], fixtures: fixtures)

        await h.controller.hydrate()
        let state = await h.controller.currentState()
        guard case .error(let err) = state else {
            return XCTFail("a transient cold-start failure must surface a typed error, got \(state)")
        }
        XCTAssertEqual(err.httpStatus, 503)
        await assertSessionKept(h)

        let token = try await h.controller.getToken()
        XCTAssertEqual(token, fixtures.happyToken)
        let presented = await h.transport.tokens()
        XCTAssertEqual(presented, [storedRefreshToken, storedRefreshToken])
        let after = await h.controller.currentState()
        guard case .authenticated = after else { return XCTFail("expected authenticated, got \(after)") }
    }

    func testColdStartGetTokenInsideRetryAfterWindowMakesNoNetworkCall() async throws {
        let fixtures = try TokenFixtures.load()
        let h = try await makeHarness([response(503, retryAfter: "60"), fixtures.okBody()], fixtures: fixtures)

        await h.controller.hydrate()
        do {
            _ = try await h.controller.getToken()
            XCTFail("inside the Retry-After window getToken must not produce a token")
        } catch let err as SdkError {
            XCTAssertEqual(err.code, .refreshFailed)
            XCTAssertEqual(err.httpStatus, 503)
        }
        var calls = await h.transport.callCount()
        XCTAssertEqual(calls, 1, "getToken inside the Retry-After window reached the network")

        h.clock.advance(61)
        let token = try await h.controller.getToken()
        XCTAssertEqual(token, fixtures.happyToken)
        calls = await h.transport.callCount()
        XCTAssertEqual(calls, 2)
    }

    func testColdStartDefinitiveRejectionSignsOut() async throws {
        let h = try await makeHarness([response(401)], fixtures: try TokenFixtures.load())
        await h.controller.hydrate()
        let state = await h.controller.currentState()
        guard case .signedOut = state else { return XCTFail("expected signedOut, got \(state)") }
        let stored = await h.adapter.storageRead(key: h.refreshKey)
        XCTAssertNil(stored)
    }

    // MARK: Classification (shared by both paths)

    func testClassification() {
        XCTAssertTrue(RefreshFailure.isTransientStatus(500))
        XCTAssertTrue(RefreshFailure.isTransientStatus(503))
        XCTAssertTrue(RefreshFailure.isTransientStatus(429))
        XCTAssertTrue(RefreshFailure.isTransientStatus(408))
        XCTAssertFalse(RefreshFailure.isTransientStatus(400))
        XCTAssertTrue(RefreshFailure.isDefinitiveRejection(status: 401, oauthError: nil))
        XCTAssertTrue(RefreshFailure.isDefinitiveRejection(status: 400, oauthError: "invalid_grant"))
        XCTAssertFalse(RefreshFailure.isDefinitiveRejection(status: 403, oauthError: nil))
        XCTAssertFalse(RefreshFailure.isDefinitiveRejection(status: 400, oauthError: "invalid_request"))
        XCTAssertFalse(RefreshFailure.isDefinitiveRejection(status: 503, oauthError: "invalid_grant"))
        XCTAssertEqual(
            RefreshFailure.oauthError(from: Data(#"{"code":"auth/invalid_refresh_token"}"#.utf8)),
            "invalid_refresh_token"
        )
        XCTAssertTrue(RefreshFailure.isDefinitiveRejection(status: 403, oauthError: "user_blocked"))
        XCTAssertTrue(RefreshFailure.isDefinitiveRejection(status: 403, oauthError: "pending_parental_consent"))
        XCTAssertEqual(
            RefreshFailure.oauthError(from: Data(#"{"error":{"code":"auth/user_blocked"}}"#.utf8)),
            "user_blocked"
        )
        XCTAssertEqual(RefreshFailure.oauthError(from: Data(#"{"code":"USER_BLOCKED"}"#.utf8)), "user_blocked")
        // Only the `auth/` namespace is dropped.
        XCTAssertEqual(
            RefreshFailure.oauthError(from: Data(#"{"code":"billing/user_blocked"}"#.utf8)),
            "billing/user_blocked"
        )
        XCTAssertNil(RefreshFailure.oauthError(from: Data(#"{"code":""}"#.utf8)))
    }
}
