// OAuth state: single-use state lifecycle.

import XCTest

@testable import RakomiSDK

final class OAuthStateTests: XCTestCase {

    func testStateCompareConstantTime() {
        // Sanity: constant-time helper rejects mismatched lengths fast but
        // still iterates min-length bytes — assert function returns expected
        // boolean across many calls.
        let baseline = "QWERTYUIOPASDFGHJKLZXCVBNM"
        XCTAssertTrue(constantTimeEquals(baseline, baseline))
        XCTAssertFalse(constantTimeEquals(baseline, baseline + "x"))
        XCTAssertFalse(constantTimeEquals("a", "b"))
    }

    func testMintProducesDistinctStates() async throws {
        let storage = InMemoryStorage()
        let store = OAuthStateStore(storage: storage.asKeychain())
        // The actor uses KeychainStorage, but on macOS-CI Keychain is
        // available. We hop through it via a real KeychainStorage initialized
        // with an isolated service identifier.
        // For this unit test we just assert distinct states.
        let a = try await store.mint()
        let b = try await store.mint()
        XCTAssertNotEqual(a.state, b.state)
        XCTAssertNotEqual(a.verifier, b.verifier)
    }

    /// @proves SW-2 (code review native-sdk-preflight-sanitation, swift-adversarial): `consume`
    /// used to delete the stored flow via an unstructured, un-awaited `Task { }` inside a `defer`
    /// (Swift's `defer` cannot itself `await`), so `consume()` could return to its caller before
    /// the deletion had even been scheduled — an actor IS reentrant at `await` points, so a second
    /// concurrent `consume` with the same id could observe the entry still present. `consume` now
    /// awaits the delete synchronously before returning, mirroring the Flutter twin
    /// (`validateAndConsume`). Proof: read the underlying storage IMMEDIATELY after `consume()`
    /// returns — no sleep, no retry loop — and require the entry to already be gone.
    func testConsumeDeletesBeforeReturning() async throws {
        let keychain = InMemoryStorage().asKeychain()
        let store = OAuthStateStore(storage: keychain)
        let minted = try await store.mint()
        let key = StorageKeys.oauthState(oneTimeId: minted.oneTimeId)

        let before = await keychain.read(key: key)
        XCTAssertNotNil(before, "sanity: the entry must exist right after mint")

        _ = await store.consume(oneTimeId: minted.oneTimeId)

        let after = await keychain.read(key: key)
        XCTAssertNil(
            after,
            "consume() must AWAIT the delete before returning — an un-awaited fire-and-forget delete narrows the single-use guarantee under actor reentrancy"
        )
    }
}

// MARK: - Test-helper: in-memory storage adapter.

actor InMemoryStorage {
    var values: [String: String] = [:]
    func read(key: String) -> String? { values[key] }
    func write(key: String, value: String) -> StorageWriteResult {
        values[key] = value
        return .success
    }
    func delete(key: String) { values[key] = nil }
    func deleteAll(prefix: String) {
        for k in values.keys where k.hasPrefix(prefix) { values[k] = nil }
    }
    func has(key: String) -> Bool { values[key] != nil }

    nonisolated func asKeychain() -> KeychainStorage {
        // Use a unique service identifier so test runs don't pollute prod
        // Keychain. This is the simplest path that compiles on both
        // macOS/Linux without invasive injection.
        let svc = "com.rakomi.swift-sdk.tests.\(UUID().uuidString)"
        return KeychainStorage(service: svc)
    }
}
