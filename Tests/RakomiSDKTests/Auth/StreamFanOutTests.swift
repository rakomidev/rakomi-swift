// Every subscriber to `authStateChanges()` / `events()` must see every value.
//
// Both used to hand out one shared AsyncStream. A probe over ten emissions with
// two consumers scored 3 and 7 — the sequence was split, not broadcast, which is
// what an AsyncStream does by construction. The SDK itself subscribes three
// times (RakomiProvider, RakomiSignInForm, RakomiAuthUIKitObserver.attach), so
// an app listening for its own purposes took transitions away from the SDK's UI.

import XCTest

@testable import RakomiSDK

private actor Collector<T: Sendable> {
    var values: [T] = []
    func append(_ v: T) { values.append(v) }
    var count: Int { values.count }
}

final class StreamFanOutTests: XCTestCase {

    private func makeAuth() throws -> RakomiAuth {
        let configuration = try RakomiAuthConfiguration(
            publishableKey: "pk_test_fanout",
            redirectURI: URL(string: "fanout://callback")!,
            apiBaseURL: URL(string: "https://api.example.test")!
        )
        return RakomiAuth(configuration: configuration, adapter: TestAdapter())
    }

    func testEveryStateSubscriberSeesEveryTransition() async throws {
        let auth = try makeAuth()
        let a = Collector<String>()
        let b = Collector<String>()

        let t1 = Task { for await s in auth.authStateChanges() { await a.append(label(s)) } }
        let t2 = Task { for await s in auth.authStateChanges() { await b.append(label(s)) } }
        defer {
            t1.cancel()
            t2.cancel()
        }
        try await Task.sleep(nanoseconds: 150_000_000)

        for _ in 0..<5 { await auth.controller.emit(.signedOut) }
        try await Task.sleep(nanoseconds: 300_000_000)

        // 5 emissions + the replayed `loading` each subscriber starts from.
        let av = await a.count
        let bv = await b.count
        XCTAssertEqual(av, 6, "subscriber A missed transitions")
        XCTAssertEqual(bv, 6, "subscriber B missed transitions")
    }

    func testALateStateSubscriberLearnsTheCurrentState() async throws {
        let auth = try makeAuth()
        await auth.controller.emit(.signedOut)

        let late = Collector<String>()
        let t = Task { for await s in auth.authStateChanges() { await late.append(label(s)) } }
        defer { t.cancel() }
        try await Task.sleep(nanoseconds: 200_000_000)

        let seen = await late.values
        XCTAssertEqual(seen.first, "signedOut", "a subscriber that arrives after a transition must still learn it")
    }

    func testEventSubscribersAllSeeAnEventAndDoNotReplayOldOnes() async throws {
        let auth = try makeAuth()

        // Emitted before anyone subscribes: events are discrete, not state.
        await auth.controller.emitEvent(.tokenRefreshed)

        let a = Collector<String>()
        let b = Collector<String>()
        let t1 = Task { for await e in auth.events() { await a.append(eventLabel(e)) } }
        let t2 = Task { for await e in auth.events() { await b.append(eventLabel(e)) } }
        defer {
            t1.cancel()
            t2.cancel()
        }
        try await Task.sleep(nanoseconds: 150_000_000)

        await auth.controller.emitEvent(.mfaChallengeVerified)
        try await Task.sleep(nanoseconds: 300_000_000)

        let av = await a.values
        let bv = await b.values
        XCTAssertEqual(av, ["mfaChallengeVerified"])
        XCTAssertEqual(bv, ["mfaChallengeVerified"])
    }

    func testCancellingOneSubscriberDoesNotStarveTheOther() async throws {
        let auth = try makeAuth()
        let survivor = Collector<String>()

        let doomed = Task { for await _ in auth.authStateChanges() {} }
        let t = Task { for await s in auth.authStateChanges() { await survivor.append(label(s)) } }
        defer { t.cancel() }
        try await Task.sleep(nanoseconds: 150_000_000)

        doomed.cancel()
        try await Task.sleep(nanoseconds: 150_000_000)

        for _ in 0..<3 { await auth.controller.emit(.signedOut) }
        try await Task.sleep(nanoseconds: 300_000_000)

        let count = await survivor.count
        XCTAssertEqual(count, 4, "the remaining subscriber must still receive every transition")
    }

    private func label(_ state: AuthState) -> String {
        switch state {
        case .loading: return "loading"
        case .signedOut: return "signedOut"
        case .authenticated: return "authenticated"
        case .error: return "error"
        }
    }

    private func eventLabel(_ event: AuthEvent) -> String {
        switch event {
        case .signedIn: return "signedIn"
        case .signedOut: return "signedOut"
        case .tokenRefreshed: return "tokenRefreshed"
        case .mfaChallengeRequired: return "mfaChallengeRequired"
        case .mfaChallengeVerified: return "mfaChallengeVerified"
        case .sessionRevoked: return "sessionRevoked"
        case .userUpdated: return "userUpdated"
        }
    }
}
