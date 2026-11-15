// Biometric lock in front of the stored credential.
//
// With `requireBiometricUnlock` on, hydration, `getToken()` and the refresh
// path must not read or use the stored refresh token until a biometric prompt
// has succeeded within `freshAuthWindow`. A denied prompt yields no token and a
// typed `biometricError`. With the lock off, nothing prompts.
//
// The refresh is driven through the injectable DPoP transport, so the tests can
// observe whether the stored refresh token was ever presented, without a network.

import XCTest

@testable import RakomiSDK

/// Records every refresh token it is handed and answers 500 (a transient
/// failure that keeps the stored credential in place).
private actor RecordingTransport: DpopRefreshTransport {
    private(set) var presented: [String] = []

    func sendRefresh(refreshToken: String, dpopProof: String?) async throws -> DpopRefreshHTTPResult {
        presented.append(refreshToken)
        return DpopRefreshHTTPResult(
            statusCode: 500,
            body: Data(),
            dpopNonce: nil,
            useDpopNonceChallenge: false,
            dpopProofRejected: false
        )
    }

    func tokens() -> [String] { presented }
}

final class BiometricLockTests: XCTestCase {

    private let storedRefreshToken = "rt_stored_credential"

    private func configuration(lock: Bool, window: TimeInterval = 30) throws -> RakomiAuthConfiguration {
        try RakomiAuthConfiguration(
            publishableKey: "pk_test_biolock",
            redirectURI: URL(string: "biolock://callback")!,
            apiBaseURL: URL(string: "https://api.example.test")!,
            freshAuthWindow: window,
            requireBiometricUnlock: lock
        )
    }

    /// A controller with a stored refresh token and a DPoP-bound session whose
    /// refresh goes through `transport`.
    private func makeController(
        lock: Bool,
        biometric: BiometricResult,
        window: TimeInterval = 30
    ) async throws -> (RakomiAuthController, TestAdapter, RecordingTransport) {
        let config = try configuration(lock: lock, window: window)
        let adapter = TestAdapter()
        await adapter.setBiometricResult(biometric)
        _ = await adapter.storageWrite(
            key: StorageKeys.refreshToken(tenantId: config.tenantId),
            value: storedRefreshToken
        )
        let controller = RakomiAuthController(configuration: config, adapter: adapter)
        let session = try await controller.enableDpop(prover: CryptoKitDpopProver(preferSecureEnclave: false))
        await session.observeTokenType("DPoP", attachedProof: true)
        let transport = RecordingTransport()
        await controller.setDpopTransport(transport)
        return (controller, adapter, transport)
    }

    // MARK: - Lock on, prompt denied → no credential use, typed error

    func testLockOnDeniedGetTokenReturnsNoTokenAndNeverUsesStoredCredential() async throws {
        let (controller, adapter, transport) = try await makeController(lock: true, biometric: .cancelled)

        do {
            let token = try await controller.getToken()
            XCTFail("a denied biometric prompt must not yield a token, got \(token)")
        } catch let err as SdkError {
            XCTAssertEqual(err.code, .biometricError)
            XCTAssertEqual(err.reason, .biometricCancelled)
        }

        let presented = await transport.tokens()
        XCTAssertEqual(presented, [], "the stored refresh token was used without a successful biometric prompt")
        let prompts = await adapter.biometricRequestCount
        XCTAssertGreaterThanOrEqual(prompts, 1, "the lock never prompted")
    }

    func testLockOnDeniedHydrateSurfacesBiometricErrorAndNeverUsesStoredCredential() async throws {
        let (controller, adapter, transport) = try await makeController(lock: true, biometric: .lockout)

        await controller.hydrate()

        let state = await controller.currentState()
        guard case .error(let err) = state else {
            return XCTFail("expected a biometric error state, got \(state)")
        }
        XCTAssertEqual(err.code, .biometricError)
        XCTAssertEqual(err.reason, .biometricLockout)
        let presented = await transport.tokens()
        XCTAssertEqual(presented, [])
        let prompts = await adapter.biometricRequestCount
        XCTAssertEqual(prompts, 1)
        // The credential is kept: a later successful unlock can still use it.
        let stored = await adapter.storageRead(
            key: StorageKeys.refreshToken(tenantId: controller.configuration.tenantId)
        )
        XCTAssertEqual(stored, storedRefreshToken)
    }

    func testLockOnDeniedRefreshNeverUsesStoredCredential() async throws {
        let (controller, _, transport) = try await makeController(lock: true, biometric: .notEnrolled)

        do {
            _ = try await controller.refresh(force: true)
            XCTFail("refresh must fail closed when the biometric prompt is denied")
        } catch let err as SdkError {
            XCTAssertEqual(err.code, .biometricError)
            XCTAssertEqual(err.reason, .biometricNotEnrolled)
        }
        let presented = await transport.tokens()
        XCTAssertEqual(presented, [])
    }

    // MARK: - Lock on, prompt succeeds → credential is used

    func testLockOnSuccessfulPromptUsesStoredCredentialAndHonoursFreshWindow() async throws {
        let (controller, adapter, transport) = try await makeController(lock: true, biometric: .success)

        await controller.hydrate()
        var presented = await transport.tokens()
        XCTAssertEqual(presented, [storedRefreshToken])
        var prompts = await adapter.biometricRequestCount
        XCTAssertEqual(prompts, 1)

        // Inside the fresh-auth window a second refresh does not prompt again.
        _ = try? await controller.refresh(force: true)
        presented = await transport.tokens()
        XCTAssertEqual(presented, [storedRefreshToken, storedRefreshToken])
        prompts = await adapter.biometricRequestCount
        XCTAssertEqual(prompts, 1, "a refresh inside the fresh-auth window must not prompt again")
    }

    func testLockOnZeroWindowPromptsOnEveryCredentialUse() async throws {
        let (controller, adapter, transport) = try await makeController(lock: true, biometric: .success, window: 0)

        await controller.hydrate()
        _ = try? await controller.refresh(force: true)

        let prompts = await adapter.biometricRequestCount
        XCTAssertEqual(prompts, 2)
        let presented = await transport.tokens()
        XCTAssertEqual(presented.count, 2)
    }

    func testUnlockWithBiometricAfterDenialRetriesHydration() async throws {
        // A zero window: the unlock prompt itself must carry hydration through,
        // not merely the window.
        let config = try configuration(lock: true, window: 0)
        let adapter = TestAdapter()
        await adapter.setBiometricResult(.cancelled)
        _ = await adapter.storageWrite(
            key: StorageKeys.refreshToken(tenantId: config.tenantId),
            value: storedRefreshToken
        )
        let auth = RakomiAuth(configuration: config, adapter: adapter)
        let session = try await auth.controller.enableDpop(prover: CryptoKitDpopProver(preferSecureEnclave: false))
        await session.observeTokenType("DPoP", attachedProof: true)
        let transport = RecordingTransport()
        await auth.controller.setDpopTransport(transport)

        await auth.hydrate()
        var presented = await transport.tokens()
        XCTAssertEqual(presented, [])

        await adapter.setBiometricResult(.success)
        await auth.unlockWithBiometric(reason: "Unlock")

        presented = await transport.tokens()
        XCTAssertEqual(presented, [storedRefreshToken], "a successful unlock must retry hydration")
        let prompts = await adapter.biometricRequestCount
        XCTAssertEqual(prompts, 2, "the unlock prompt counts as fresh; hydration must not prompt a second time")
    }

    // MARK: - Lock off → unchanged

    func testLockOffNeverPromptsAndUsesStoredCredential() async throws {
        let (controller, adapter, transport) = try await makeController(lock: false, biometric: .cancelled)

        await controller.hydrate()
        _ = try? await controller.refresh(force: true)

        let prompts = await adapter.biometricRequestCount
        XCTAssertEqual(prompts, 0)
        let presented = await transport.tokens()
        XCTAssertEqual(presented, [storedRefreshToken, storedRefreshToken])
    }

    func testLockIsOffByDefault() throws {
        let config = try RakomiAuthConfiguration(
            publishableKey: "pk_test_biolock",
            redirectURI: URL(string: "biolock://callback")!
        )
        XCTAssertFalse(config.requireBiometricUnlock)
    }
}
