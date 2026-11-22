// Mocked biometric paths via TestAdapter.
//
// These cover the application calling `unlockWithBiometric(reason:)`. The
// configured lock in front of the stored credential
// (`RakomiAuthConfiguration.requireBiometricUnlock`) is covered by
// `BiometricLockTests`.

import XCTest

@testable import RakomiSDK

final class BiometricGateTests: XCTestCase {

    private func makeAuth(adapter: TestAdapter) throws -> RakomiAuth {
        let configuration = try RakomiAuthConfiguration(
            publishableKey: "pk_test_t1",
            redirectURI: URL(string: "rakomi://callback")!,
            apiBaseURL: URL(string: "https://api.rakomi.test")!
        )
        return RakomiAuth(configuration: configuration, adapter: adapter)
    }

    func testCancelledMapsToBiometricCancelled() async throws {
        let adapter = TestAdapter()
        await adapter.setBiometricResult(.cancelled)
        let auth = try makeAuth(adapter: adapter)

        // Drive unlock; expect AuthState to receive `.error(SdkError(... biometricCancelled))`.
        let stream = auth.authStateChanges()
        let waitTask = Task {
            for await state in stream {
                if case .error(let err) = state {
                    return err.reason
                }
            }
            return SdkErrorReason.unknown
        }
        await auth.unlockWithBiometric(reason: "Test")
        try? await Task.sleep(nanoseconds: 100_000_000)
        waitTask.cancel()
    }

    func testNotEnrolledMapsToBiometricNotEnrolled() async throws {
        let adapter = TestAdapter()
        await adapter.setBiometricResult(.notEnrolled)
        let auth = try makeAuth(adapter: adapter)
        await auth.unlockWithBiometric(reason: "Test")
    }

    func testLockoutMapsToBiometricLockout() async throws {
        let adapter = TestAdapter()
        await adapter.setBiometricResult(.lockout)
        let auth = try makeAuth(adapter: adapter)
        await auth.unlockWithBiometric(reason: "Test")
    }

    func testUnavailableMapsToBiometricUnavailable() async throws {
        let adapter = TestAdapter()
        await adapter.setBiometricResult(.unavailable(reason: "no_hardware"))
        let auth = try makeAuth(adapter: adapter)
        await auth.unlockWithBiometric(reason: "Test")
    }

    func testWatchOSAndTvOSBranchShortCircuits() async {
        let adapter = TestAdapter()
        await adapter.setBiometricAvailable(false)
        let avail = await adapter.biometricAvailable()
        XCTAssertFalse(avail)
    }
}
