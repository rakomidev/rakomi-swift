// Fresh-install/reinstall purge sweep — value comparison, not merely presence.
//
// Code review native-sdk-preflight-sanitation, finding SW-1 (swift-adversarial): hydrate()'s
// fresh-install detection used to compare the Keychain lifecycle id and the UserDefaults marker
// for PRESENCE only ("is each key set?"), never for VALUE ("do the two ids actually match?"). The
// Flutter twin (`_freshInstallSweep`, provider.dart) got the value-comparison fix in the SAME
// sanitation commit that also corrected the Swift comment to honestly disclose the gap — the code
// itself was left unfixed. A marker present-but-WRONG (anything able to write UserDefaults, which
// is NOT secure storage, can store an arbitrary non-null value) fully suppressed the purge under
// the old presence-only logic; these tests prove the purge now fires on a value MISMATCH, not only
// on outright absence, mirroring Flutter's `constantTimeStringEquals(keychainId, markerId)` check.

import XCTest

@testable import RakomiSDK

final class FreshInstallSweepTests: XCTestCase {

    private func makeAuth(adapter: TestAdapter) throws -> RakomiAuth {
        let configuration = try RakomiAuthConfiguration(
            publishableKey: "pk_test_t1",
            redirectURI: URL(string: "rakomi://callback")!,
            apiBaseURL: URL(string: "https://api.rakomi.test")!
        )
        return RakomiAuth(configuration: configuration, adapter: adapter)
    }

    /// @proves SW-1: a Keychain lifecycle id PRESENT alongside a UserDefaults marker that is also
    /// PRESENT but holds a DIFFERENT value (the "anything able to write UserDefaults" attack this
    /// finding names) MUST still trigger the post-uninstall purge — a mismatched-but-present marker
    /// must not suppress it the way the old presence-only check did.
    func testMismatchedPresentMarkerStillTriggersPurge() async throws {
        let adapter = TestAdapter()
        let auth = try makeAuth(adapter: adapter)
        let tenantId = auth.controller.configuration.tenantId

        let lifecycleKey = StorageKeys.lifecycleId(tenantId: tenantId)
        let markerKey = StorageKeys.lifecycleIdMarker(tenantId: tenantId)
        // A namespaced probe key (NOT the refresh-token key — hydrate()'s step 3 would otherwise
        // attempt a real network refresh against a non-resolvable test host, making this test slow
        // and network-dependent for a concern this test does not need to exercise) that MUST be
        // gone after a real purge — the observable proof the purge branch actually fired.
        let probeKey = "\(storageNamespace).probe.\(tenantId)"

        // Simulate Keychain residue surviving an uninstall/reinstall, PLUS a UserDefaults marker
        // that is present but does NOT match — the exact case the presence-only check missed.
        _ = await adapter.storageWrite(key: lifecycleKey, value: "stale-keychain-id")
        await adapter.userDefaultsWrite(key: markerKey, value: "mismatched-marker-value")
        _ = await adapter.storageWrite(key: probeKey, value: "should-be-purged")

        await auth.controller.hydrate()

        let probeAfter = await adapter.storageRead(key: probeKey)
        XCTAssertNil(
            probeAfter,
            "the purge must have removed every rakomi.v1.-namespaced entry, including this unrelated probe key"
        )

        let lifecycleAfter = await adapter.storageRead(key: lifecycleKey)
        XCTAssertNotEqual(
            lifecycleAfter,
            "stale-keychain-id",
            "a fresh lifecycle id must be minted after a purge, never the stale surviving one"
        )
    }

    /// @proves SW-1 negative control: a Keychain lifecycle id whose VALUE genuinely matches the
    /// UserDefaults marker (a normal warm hydration, not a reinstall) must NOT purge — the fix must
    /// not turn every hydrate() into a purge.
    func testMatchingMarkerDoesNotPurge() async throws {
        let adapter = TestAdapter()
        let auth = try makeAuth(adapter: adapter)
        let tenantId = auth.controller.configuration.tenantId

        let lifecycleKey = StorageKeys.lifecycleId(tenantId: tenantId)
        let markerKey = StorageKeys.lifecycleIdMarker(tenantId: tenantId)
        // See the sibling test above for why this is a plain probe key, never the refresh-token key.
        let probeKey = "\(storageNamespace).probe.\(tenantId)"

        _ = await adapter.storageWrite(key: lifecycleKey, value: "same-id")
        await adapter.userDefaultsWrite(key: markerKey, value: "same-id")
        _ = await adapter.storageWrite(key: probeKey, value: "still-here")

        await auth.controller.hydrate()

        let probeAfter = await adapter.storageRead(key: probeKey)
        XCTAssertEqual(
            probeAfter,
            "still-here",
            "a matching pair (normal warm start) must NOT trigger the post-uninstall purge"
        )

        let lifecycleAfter = await adapter.storageRead(key: lifecycleKey)
        XCTAssertEqual(
            lifecycleAfter,
            "same-id",
            "an already-matching lifecycle id must be left untouched, not re-minted"
        )
    }
}
