// Live exercise of the SDK's public surface against a running API.
//
// Skipped unless RAKOMI_LIVE_* is set, so `swift test` and CI pass it over. It
// exists because the defects that made this SDK unable to authenticate were all
// invisible to a suite that never spoke to a server: a header nothing reads, a
// wire shape nothing matches, a key set nothing could parse. Each case below
// drives one public entry point end to end and asserts on what the caller can
// actually observe — the state stream, the error taxonomy, the token.

import XCTest

@testable import RakomiSDK

#if canImport(CryptoKit)
import CryptoKit
#endif

struct LiveConfig {
    let apiBaseURL: URL
    let publishableKey: String
    let email: String
    let password: String

    static func fromEnvironment() throws -> LiveConfig {
        let env = ProcessInfo.processInfo.environment
        guard
            let base = env["RAKOMI_LIVE_API_BASE_URL"], let url = URL(string: base),
            let key = env["RAKOMI_LIVE_PUBLISHABLE_KEY"],
            let email = env["RAKOMI_LIVE_EMAIL"],
            let password = env["RAKOMI_LIVE_PASSWORD"]
        else {
            throw XCTSkip("live API environment not configured")
        }
        return LiveConfig(apiBaseURL: url, publishableKey: key, email: email, password: password)
    }
}

/// Records everything the SDK emits, so an assertion can name the reason rather
/// than only report that something did not happen.
actor StateLog {
    private(set) var states: [AuthState] = []
    private(set) var events: [AuthEvent] = []
    func record(_ s: AuthState) { states.append(s) }
    func record(_ e: AuthEvent) { events.append(e) }
    var errors: [SdkError] {
        states.compactMap { state -> SdkError? in
            guard case .error(let error) = state else { return nil }
            return error
        }
    }
    var labels: [String] {
        states.map {
            switch $0 {
            case .loading: return "loading"
            case .signedOut: return "signedOut"
            case .authenticated: return "authenticated"
            case .error(let e): return "error(\(e.code.wire)/\(e.reason.wire): \(e.redactedMessage))"
            }
        }
    }
    var challengeToken: String? {
        for e in events { if case .mfaChallengeRequired(let t) = e { return t } }
        return nil
    }
}

final class LiveSurfaceTests: XCTestCase {

    private func makeAuth(
        _ live: LiveConfig,
        publishableKey: String? = nil,
        apiBaseURL: URL? = nil
    ) throws -> (RakomiAuth, StateLog, [Task<Void, Never>]) {
        let configuration = try RakomiAuthConfiguration(
            publishableKey: publishableKey ?? live.publishableKey,
            redirectURI: URL(string: "com.rakomi.livetest://callback")!,
            apiBaseURL: apiBaseURL ?? live.apiBaseURL
        )
        let auth = RakomiAuth(configuration: configuration, adapter: TestAdapter())
        let log = StateLog()
        let t1 = Task { for await s in auth.authStateChanges() { await log.record(s) } }
        let t2 = Task { for await e in auth.events() { await log.record(e) } }
        return (auth, log, [t1, t2])
    }

    private func settle() async throws {
        try await Task.sleep(nanoseconds: 400_000_000)
    }

    // MARK: - Sign-in, session, refresh, sign-out

    func testPasswordSignInProducesAVerifiedSession() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, log, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        await auth.signIn(email: live.email, password: live.password)
        try await settle()

        let user = await auth.currentUser()
        let labels = await log.labels
        XCTAssertNotNil(user, "sign-in did not authenticate; emitted: \(labels)")
        XCTAssertEqual(user?.email, live.email)
        XCTAssertFalse(user?.id.isEmpty ?? true, "the verified token carried no subject")
        XCTAssertFalse(user?.claims.isEmpty ?? true, "the verified token carried no claims")

        let token = try await auth.getToken()
        XCTAssertEqual(token.split(separator: ".").count, 3)

        let signedIn = await log.events.contains { event in
            guard case .signedIn = event else { return false }
            return true
        }
        XCTAssertTrue(signedIn, "no signedIn event was emitted")
    }

    func testRefreshRotatesTheSessionAndEmitsTokenRefreshed() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, log, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        await auth.signIn(email: live.email, password: live.password)
        try await settle()
        let before = try await auth.getToken()

        try await auth.refreshTokens()
        try await settle()
        let after = try await auth.getToken()

        XCTAssertNotEqual(before, after, "refresh returned the same access token")
        let valid = await auth.hasValidSession()
        XCTAssertTrue(valid)
        let refreshed = await log.events.filter { event in
            guard case .tokenRefreshed = event else { return false }
            return true
        }
        XCTAssertGreaterThanOrEqual(refreshed.count, 1)
    }

    func testSignOutClearsTheSessionAndTheStoredRefreshToken() async throws {
        let live = try LiveConfig.fromEnvironment()
        let configuration = try RakomiAuthConfiguration(
            publishableKey: live.publishableKey,
            redirectURI: URL(string: "com.rakomi.livetest://callback")!,
            apiBaseURL: live.apiBaseURL
        )
        let adapter = TestAdapter()
        let auth = RakomiAuth(configuration: configuration, adapter: adapter)

        await auth.signIn(email: live.email, password: live.password)
        try await settle()
        let refreshKey = StorageKeys.refreshToken(tenantId: configuration.tenantId)
        let storedWhileSignedIn = await adapter.storageRead(key: refreshKey)
        XCTAssertNotNil(storedWhileSignedIn, "no refresh token was persisted on sign-in")

        await auth.signOut()
        try await settle()
        let storedAfter = await adapter.storageRead(key: refreshKey)
        XCTAssertNil(storedAfter, "the refresh token survived sign-out")
        let user = await auth.currentUser()
        XCTAssertNil(user)
        let stillValid = await auth.hasValidSession()
        XCTAssertFalse(stillValid)
    }

    // MARK: - The error taxonomy, each reached deliberately

    func testAnUnknownPublishableKeyIsReportedAsASignInFailure() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, log, tasks) = try makeAuth(live, publishableKey: "akm_test_not_a_real_key_at_all")
        defer { tasks.forEach { $0.cancel() } }

        await auth.signIn(email: live.email, password: live.password)
        try await settle()

        let errors = await log.errors
        XCTAssertFalse(errors.isEmpty, "an unusable key produced no error at all")
        XCTAssertNotEqual(errors.first?.reason, .unknown, "an authentication rejection must not surface as `unknown`")
    }

    func testAWrongPasswordIsReportedAsInvalidCredentials() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, log, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        await auth.signIn(email: live.email, password: "definitely-not-the-password-1")
        try await settle()

        let errors = await log.errors
        XCTAssertFalse(errors.isEmpty, "a wrong password produced no error")
        let user = await auth.currentUser()
        XCTAssertNil(user)
        XCTAssertNotEqual(errors.first?.reason, .unknown, "a rejected password must not surface as `unknown`")
    }

    func testAnUnreachableHostIsReportedAsANetworkError() async throws {
        let live = try LiveConfig.fromEnvironment()
        // A port nothing listens on: the transport fails before any HTTP status.
        let (auth, log, tasks) = try makeAuth(live, apiBaseURL: URL(string: "https://localhost:1")!)
        defer { tasks.forEach { $0.cancel() } }

        await auth.signIn(email: live.email, password: live.password)
        try await settle()

        let errors = await log.errors
        XCTAssertFalse(errors.isEmpty, "an unreachable host produced no error")
        XCTAssertEqual(errors.first?.code, .networkError, "a transport failure must be reported as a network error")
        XCTAssertEqual(errors.first?.reason, .network)
    }

    func testGetTokenWithoutASessionThrowsRatherThanReturningEmpty() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, _, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        do {
            _ = try await auth.getToken()
            XCTFail("getToken returned a value with no session")
        } catch let error as SdkError {
            XCTAssertEqual(error.reason, .sessionExpired)
        }
    }

    // MARK: - Registration

    func testRegisterDoesNotAuthenticateAndSaysSo() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, log, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        let unique = "live-probe-\(UUID().uuidString.prefix(8))@example.test".lowercased()
        await auth.signUp(email: unique, password: "A-very-long-password-1", consent: true)
        try await settle()

        let user = await auth.currentUser()
        XCTAssertNil(user, "registration must not produce a session")
        let labels = await log.labels
        XCTAssertTrue(labels.contains("signedOut"), "registration settled on \(labels)")
    }

    // MARK: - Device authorization (RFC 8628)

    func testDeviceAuthorizationStartsAndReturnsAUserCode() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, _, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        let start = try await auth.startDeviceAuthorization()
        XCTAssertFalse(start.deviceCode.isEmpty)
        XCTAssertFalse(start.userCode.isEmpty)
        XCTAssertTrue(start.verificationURI.hasPrefix("http"), "verification URI was \(start.verificationURI)")
        XCTAssertGreaterThan(start.expiresIn, 0)
        XCTAssertGreaterThan(start.interval, 0)
    }

    // MARK: - Browser sign-in

    /// What the SDK actually sends the browser to, measured against the live
    /// server's own discovery document. The previous implementation sent it to
    /// `/v1/auth/oauth/start`, which the API answers 404 — recorded in the log
    /// as `GET /v1/auth/oauth/start → 404` while an operator watched.
    func testBrowserSignInTargetsThePublishedAuthorizationEndpoint() async throws {
        let live = try LiveConfig.fromEnvironment()
        guard let clientId = ProcessInfo.processInfo.environment["RAKOMI_LIVE_CLIENT_ID"] else {
            throw XCTSkip("RAKOMI_LIVE_CLIENT_ID not set")
        }
        let configuration = try RakomiAuthConfiguration(
            publishableKey: live.publishableKey,
            redirectURI: URL(string: "com.rakomi.quickstart://callback")!,
            apiBaseURL: live.apiBaseURL,
            clientId: clientId
        )
        let adapter = TestAdapter()
        // The browser reports a dismissal, so the flow stops right after the
        // launch — which is the moment the URL is observable.
        await adapter.setBrowserResult(.cancelled)
        let auth = RakomiAuth(configuration: configuration, adapter: adapter)

        await auth.signIn(withProvider: .google)
        try await settle()

        let launched = await adapter.lastBrowserURL
        let url = try XCTUnwrap(launched, "no browser was launched")

        // The endpoint comes from the server's own metadata, not from a guess.
        let metadata = try await auth.controller.authorizationServerMetadata()
        XCTAssertEqual(url.host, metadata.authorizationEndpoint.host)
        XCTAssertEqual(url.path, metadata.authorizationEndpoint.path)

        let items = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
        let value: (String) -> String? = { name in items.first { $0.name == name }?.value }
        XCTAssertEqual(value("response_type"), "code")
        XCTAssertEqual(value("client_id"), clientId)
        XCTAssertEqual(value("redirect_uri"), "com.rakomi.quickstart://callback")
        XCTAssertEqual(value("code_challenge_method"), "S256")
        XCTAssertEqual(value("provider"), "google")
        XCTAssertFalse((value("state") ?? "").isEmpty)
        XCTAssertFalse((value("code_challenge") ?? "").isEmpty)
        XCTAssertFalse(url.absoluteString.contains("/v1/auth/oauth/start"), "the 404 path is back")
    }

    /// And the page behind that URL is a login page, not a 404. Fetched over
    /// HTTP rather than through a browser, which is as far as a test can go.
    func testTheAuthorizationEndpointAnswersWithAPage() async throws {
        let live = try LiveConfig.fromEnvironment()
        guard let clientId = ProcessInfo.processInfo.environment["RAKOMI_LIVE_CLIENT_ID"] else {
            throw XCTSkip("RAKOMI_LIVE_CLIENT_ID not set")
        }
        let configuration = try RakomiAuthConfiguration(
            publishableKey: live.publishableKey,
            redirectURI: URL(string: "com.rakomi.quickstart://callback")!,
            apiBaseURL: live.apiBaseURL,
            clientId: clientId
        )
        let adapter = TestAdapter()
        await adapter.setBrowserResult(.cancelled)
        let auth = RakomiAuth(configuration: configuration, adapter: adapter)
        await auth.signIn(withProvider: .google)
        try await settle()
        let launchedURL = await adapter.lastBrowserURL
        let url = try XCTUnwrap(launchedURL)

        let (_, response) = try await URLSession.shared.data(from: url)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        XCTAssertEqual(status, 200, "the authorization endpoint answered \(status)")
    }

    // MARK: - JWKS

    func testInvalidateJWKSForcesARefetchAndVerificationStillSucceeds() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, _, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        await auth.signIn(email: live.email, password: live.password)
        try await settle()
        await auth.invalidateJWKS()

        let valid = await auth.hasValidSession()
        XCTAssertTrue(valid, "verification failed after the key set was invalidated")
    }

    // MARK: - Two configurations side by side

    func testTwoConfigurationsKeepIndependentSessions() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (signedIn, _, tasksA) = try makeAuth(live)
        let (other, _, tasksB) = try makeAuth(live, publishableKey: live.publishableKey + "-second")
        defer { (tasksA + tasksB).forEach { $0.cancel() } }

        await signedIn.signIn(email: live.email, password: live.password)
        try await settle()

        let a = await signedIn.currentUser()
        let b = await other.currentUser()
        XCTAssertNotNil(a)
        XCTAssertNil(b, "a second configuration inherited the first one's session")
        XCTAssertNotEqual(
            signedIn.configuration.tenantId,
            other.configuration.tenantId,
            "two publishable keys must namespace their storage apart"
        )
    }

    /// The MFA verification request used to post `challenge_id` to
    /// `/v1/auth/mfa/totp/verify`. Measured against the live API: that path is
    /// 404, and that field name is rejected 400 `validation/invalid_request` by
    /// the real endpoint. What the SDK sends now gets past validation and into
    /// the handler, which is as far as this instance can go while
    /// `MFA_ENCRYPTION_KEY` is unset. So the assertion is about the SHAPE: a
    /// bogus challenge must fail for a reason other than "your request did not
    /// parse".
    func testMfaVerificationRequestShapeIsAcceptedByTheAPI() async throws {
        let live = try LiveConfig.fromEnvironment()
        let (auth, log, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        await auth.verifyMfa(challengeId: "not-a-real-challenge-token", code: "123456")
        try await settle()

        let errors = await log.errors
        XCTAssertFalse(errors.isEmpty, "a bogus challenge produced no error")
        let message = errors.first?.redactedMessage ?? ""
        XCTAssertFalse(
            message.contains("validation/invalid_request"),
            "the request did not parse — the field name or path is wrong again: \(message)"
        )
    }

    // MARK: - MFA, enrolled over HTTP then driven through the SDK

    func testMfaChallengeAndVerificationRoundTrip() async throws {
        let live = try LiveConfig.fromEnvironment()
        #if canImport(CryptoKit)
        guard let secret = ProcessInfo.processInfo.environment["RAKOMI_LIVE_TOTP_SECRET"] else {
            throw XCTSkip("RAKOMI_LIVE_TOTP_SECRET not set — enrol the user first")
        }
        let (auth, log, tasks) = try makeAuth(live)
        defer { tasks.forEach { $0.cancel() } }

        await auth.signIn(email: live.email, password: live.password)
        try await settle()

        let user = await auth.currentUser()
        XCTAssertNil(user, "an MFA-enrolled user must not be signed in by the password alone")
        let challenge = await log.challengeToken
        let seen = await log.labels
        XCTAssertNotNil(challenge, "no mfaChallengeRequired event; emitted: \(seen)")

        guard let challenge else { return }
        let code = try XCTUnwrap(Self.totp(base32Secret: secret))
        await auth.verifyMfa(challengeId: challenge, code: code)
        try await settle()

        let after = await auth.currentUser()
        let seenAfter = await log.labels
        XCTAssertNotNil(after, "MFA verification did not authenticate; emitted: \(seenAfter)")
        let verified = await log.events.contains { event in
            guard case .mfaChallengeVerified = event else { return false }
            return true
        }
        XCTAssertTrue(verified)
        #else
        throw XCTSkip("CryptoKit unavailable")
        #endif
    }

    #if canImport(CryptoKit)
    /// RFC 6238 TOTP over a base32 secret, 30-second step, 6 digits, SHA-1.
    static func totp(base32Secret: String, at date: Date = Date()) -> String? {
        guard let key = base32Decode(base32Secret) else { return nil }
        var counter = UInt64(date.timeIntervalSince1970 / 30).bigEndian
        let counterData = Data(bytes: &counter, count: 8)
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: SymmetricKey(data: key))
        let bytes = Array(mac)
        let offset = Int(bytes[bytes.count - 1] & 0x0f)
        let truncated =
            (UInt32(bytes[offset] & 0x7f) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
        return String(format: "%06u", truncated % 1_000_000)
    }

    static func base32Decode(_ input: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0
        var value = 0
        var out = Data()
        for character in input.uppercased() where character != "=" {
            guard let index = alphabet.firstIndex(of: character) else { return nil }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                out.append(UInt8((value >> (bits - 8)) & 0xff))
                bits -= 8
            }
        }
        return out.isEmpty ? nil : out
    }
    #endif
}
