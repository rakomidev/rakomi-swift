// `getToken()` while hydration is in flight.
//
// `hydrate()` used to set its "already done" flag and return before the first
// pass had produced any state. `getToken()`'s `loading` branch is "hydrate, then
// ask again", so a second caller hydrated to a no-op, saw `loading` again, and
// recursed — forever, at one actor hop per turn. Observed in the quickstart: a
// screen that calls `getToken()` on appear sat on a spinner indefinitely while
// the provider was still mounting.

import XCTest

@testable import RakomiSDK

/// A storage layer that takes its time, so hydration is genuinely IN FLIGHT
/// when the second caller arrives. With an instant adapter there is no window
/// and the race cannot be reproduced — the first version of this test passed
/// against the defect it was written for.
private actor SlowAdapter: RakomiNativeAdapter {
    private let inner = TestAdapter()
    private let delay: UInt64

    init(delayNanoseconds: UInt64) { self.delay = delayNanoseconds }

    func storageRead(key: String) async -> String? {
        try? await Task.sleep(nanoseconds: delay)
        return await inner.storageRead(key: key)
    }
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
    func supportsNativePasskey() async -> Bool { await inner.supportsNativePasskey() }
    nonisolated var connectivityStream: AsyncStream<ConnectivityState> { inner.connectivityStream }
    nonisolated var lifecycleStream: AsyncStream<AppLifecycleEvent> { inner.lifecycleStream }
    nonisolated func now() -> Date { Date() }
}

final class HydrationRaceTests: XCTestCase {

    private func configuration() throws -> RakomiAuthConfiguration {
        try RakomiAuthConfiguration(
            publishableKey: "pk_test_hydration",
            redirectURI: URL(string: "hydration://callback")!,
            apiBaseURL: URL(string: "https://api.example.test")!
        )
    }

    /// The regression. `getToken()` arriving DURING hydration must reach a
    /// verdict; before the fix it recursed at one actor hop per turn and never
    /// returned. The bounded wait is the assertion.
    func testGetTokenWhileHydratingTerminates() async throws {
        let controller = RakomiAuthController(
            configuration: try configuration(),
            adapter: SlowAdapter(delayNanoseconds: 1_000_000_000)
        )

        let hydrating = Task { await controller.hydrate() }
        try await Task.sleep(nanoseconds: 200_000_000)  // hydration is now in flight

        let asking = Task<String?, Never> {
            do { return try await controller.getToken() } catch { return nil }
        }
        let deadline = Task<String?, Never> {
            try? await Task.sleep(nanoseconds: 8_000_000_000)
            return "timed-out"
        }

        let outcome = await withTaskGroup(of: String?.self, returning: String?.self) { group in
            group.addTask { await asking.value }
            group.addTask { await deadline.value }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
        asking.cancel()
        deadline.cancel()
        await hydrating.value

        XCTAssertNotEqual(
            outcome,
            "timed-out",
            "getToken did not return while hydration was in flight"
        )
        XCTAssertNil(outcome, "there is no stored session, so no token should come back")
    }

    /// A second `hydrate()` must wait for the first pass, not return early. The
    /// state it leaves behind is therefore settled, never still `loading`.
    func testConcurrentHydrationsBothSeeASettledState() async throws {
        let controller = RakomiAuthController(
            configuration: try configuration(),
            adapter: SlowAdapter(delayNanoseconds: 500_000_000)
        )

        let first = Task { await controller.hydrate() }
        try await Task.sleep(nanoseconds: 100_000_000)
        await controller.hydrate()

        let state = await controller.currentState()
        if case .loading = state {
            XCTFail("the second hydrate returned while the state was still loading")
        }
        await first.value
    }
}
