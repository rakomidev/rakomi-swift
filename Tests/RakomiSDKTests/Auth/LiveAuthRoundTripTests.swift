// End-to-end probe against a running API.
//
// Skipped unless all four variables below are set, so an ordinary `swift test`
// and every CI run pass it over. It exists because the two defects that made
// the SDK unable to authenticate at all — the publishable key sent in a header
// nothing reads, and camelCase decoding of a snake_case wire — were both
// invisible to a suite that never talked to a server. The unit suites now pin
// each of them; this one is what validates that the pins describe the real API.
//
//   RAKOMI_LIVE_API_BASE_URL   e.g. https://localhost:13001
//   RAKOMI_LIVE_PUBLISHABLE_KEY
//   RAKOMI_LIVE_EMAIL
//   RAKOMI_LIVE_PASSWORD

import XCTest

@testable import RakomiSDK

private actor StateRecorder {
    var states: [String] = []
    func record(_ state: AuthState) {
        switch state {
        case .loading: states.append("loading")
        case .signedOut: states.append("signedOut")
        case .authenticated: states.append("authenticated")
        case .error(let err): states.append("error(\(err.errorDescription ?? ""))")
        }
    }
}

final class LiveAuthRoundTripTests: XCTestCase {

    private struct LiveEnvironment {
        let apiBaseURL: URL
        let publishableKey: String
        let email: String
        let password: String
    }

    private func liveEnvironment() throws -> LiveEnvironment {
        let env = ProcessInfo.processInfo.environment
        guard
            let base = env["RAKOMI_LIVE_API_BASE_URL"], let url = URL(string: base),
            let key = env["RAKOMI_LIVE_PUBLISHABLE_KEY"],
            let email = env["RAKOMI_LIVE_EMAIL"],
            let password = env["RAKOMI_LIVE_PASSWORD"]
        else {
            throw XCTSkip("live API environment not configured")
        }
        return LiveEnvironment(apiBaseURL: url, publishableKey: key, email: email, password: password)
    }

    func testPasswordSignInRefreshAndSignOut() async throws {
        let live = try liveEnvironment()
        let configuration = try RakomiAuthConfiguration(
            publishableKey: live.publishableKey,
            redirectURI: URL(string: "com.rakomi.livetest://callback")!,
            apiBaseURL: live.apiBaseURL
        )
        // No issuer or audience override: tokens carry the platform issuer and
        // audience whatever host served them, which is what the defaults expect.
        let auth = RakomiAuth(configuration: configuration, adapter: TestAdapter())

        // Record what the SDK emits, so a failure names the reason instead of
        // only reporting that no user appeared.
        let recorder = StateRecorder()
        let observer = Task {
            for await state in auth.authStateChanges() { await recorder.record(state) }
        }
        defer { observer.cancel() }

        await auth.signIn(email: live.email, password: live.password)

        // The state stream is consumed by a separate task; give it a moment to
        // drain before reporting what it saw.
        try await Task.sleep(nanoseconds: 300_000_000)
        let user = await auth.currentUser()
        let emitted = await recorder.states
        XCTAssertNotNil(user, "sign-in did not reach the authenticated state; emitted: \(emitted)")
        XCTAssertEqual(user?.email, live.email)

        // A token the SDK will hand to a caller — it has already been verified
        // against the live JWKS by this point.
        let token = try await auth.getToken()
        XCTAssertEqual(token.split(separator: ".").count, 3)

        try await auth.refreshTokens()
        let stillValid = await auth.hasValidSession()
        XCTAssertTrue(stillValid)

        await auth.signOut()
        let afterSignOut = await auth.currentUser()
        XCTAssertNil(afterSignOut)
    }
}
