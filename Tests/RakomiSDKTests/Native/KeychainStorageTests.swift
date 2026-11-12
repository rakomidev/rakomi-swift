// Keychain storage tests.

import XCTest

@testable import RakomiSDK

final class KeychainStorageTests: XCTestCase {

    func testRefreshTokenKeyNamespacing() {
        let key = StorageKeys.refreshToken(tenantId: "tenant_abc")
        XCTAssertEqual(key, "rakomi.v1.refresh_token.tenant_abc")
    }

    func testJWKSKeyNamespacing() {
        let key = StorageKeys.jwks(tenantId: "tenant_abc")
        XCTAssertTrue(key.hasPrefix("rakomi.v1."))
    }

    func testHasCanonicalPrefix() {
        XCTAssertTrue(StorageKeys.hasCanonicalPrefix("rakomi.v1.refresh_token.foo"))
        XCTAssertFalse(StorageKeys.hasCanonicalPrefix("evil.rakomi.v1.x"))
        XCTAssertFalse(StorageKeys.hasCanonicalPrefix("rakomi.v2.x"))
    }

    func testFreshInstallPurge() async {
        let adapter = TestAdapter()
        // Pre-seed: refresh token from prior install + Keychain has lifecycle id
        // but UserDefaults marker missing → post-uninstall reinstall.
        _ = await adapter.storageWrite(
            key: StorageKeys.refreshToken(tenantId: "t1"),
            value: "old_refresh"
        )
        _ = await adapter.storageWrite(
            key: StorageKeys.lifecycleId(tenantId: "t1"),
            value: "old_lifecycle_id"
        )
        // UserDefaults intentionally NOT seeded.

        let configuration = try! RakomiAuthConfiguration(
            publishableKey: "pk_test_t1",
            redirectURI: URL(string: "rakomi://callback")!,
            apiBaseURL: URL(string: "https://api.rakomi.test")!
        )
        let auth = RakomiAuth(configuration: configuration, adapter: adapter)
        await auth.hydrate()

        // After hydration the refresh token must be purged (post-uninstall).
        let snapshot = await adapter.storageSnapshot()
        XCTAssertNil(snapshot[StorageKeys.refreshToken(tenantId: "t1")])
        // Lifecycle id is rewritten + UserDefaults marker now set.
        XCTAssertNotNil(snapshot[StorageKeys.lifecycleId(tenantId: "t1")])
    }

    func testKeychainWriteFailsCleanlyOnUnknownKey() async {
        // Smoke test that adapter accepts arbitrary string + key without
        // throwing. (KeychainStorage real backend is exercised in CI on
        // macOS; here we use TestAdapter which is in-memory.)
        let adapter = TestAdapter()
        let result = await adapter.storageWrite(key: "rakomi.v1.test.x", value: "value")
        if case .failed = result { XCTFail("InMemory store must succeed") }
    }
}
