// Keychain storage namespacing.
//
// All keys MUST follow `rakomi.v1.<purpose>.<tenantId>[.<extra>]`.
// `v1` is reserved for future migration. Migration recipe:
//
//   1. Add a `v2` namespaced key in parallel (Sources/.../v2.<purpose>...).
//   2. On read, prefer v2; if v2 missing AND v1 present → re-write to v2 + delete v1.
//   3. After ≥1 release with parallel reads, drop v1 read path.
//
// This is the Apple-platforms equivalent of RN's `secureStore` namespacing
// and Flutter's `rakomi.v1.<purpose>.<tenantId>` pattern.

import Foundation

public enum StorageKeys {
    // The enum container and `keychainService` below are the only two
    // members that stay public. `Native/KeychainStorage.swift`'s
    // `public init(service: String = StorageKeys.keychainService, ...)` uses
    // `keychainService` as a default-argument expression, and a public
    // init's default value must be at least as accessible as the init
    // itself. Every other member below is internal — not part of the
    // public API surface.

    /// Service identifier for Keychain `kSecAttrService`. Consumer apps
    /// MAY share this across an app group via `keychainAccessGroup`.
    public static let keychainService = "com.rakomi.swift-sdk"

    /// Refresh token key: `rakomi.v1.refresh_token.<tenantId>`.
    static func refreshToken(tenantId: String) -> String {
        return "\(storageNamespace).refresh_token.\(tenantId)"
    }

    /// Cached JWKS key: `rakomi.v1.jwks.<tenantId>`.
    static func jwks(tenantId: String) -> String {
        return "\(storageNamespace).jwks.\(tenantId)"
    }

    /// JWKS ETag key: `rakomi.v1.jwks_etag.<tenantId>`.
    static func jwksETag(tenantId: String) -> String {
        return "\(storageNamespace).jwks_etag.\(tenantId)"
    }

    /// OAuth state (single-use, keyed by one-time-id):
    /// `rakomi.v1.oauth.state.<oneTimeId>`.
    static func oauthState(oneTimeId: String) -> String {
        return "\(storageNamespace).oauth.state.\(oneTimeId)"
    }

    /// PKCE verifier (single-use, keyed by one-time-id):
    /// `rakomi.v1.oauth.verifier.<oneTimeId>`.
    /// ⚠ UNWIRED: no call site in `Sources/` — the PKCE verifier is
    /// currently persisted under a different key scheme. Internal — not
    /// part of the public API surface.
    static func pkceVerifier(oneTimeId: String) -> String {
        return "\(storageNamespace).oauth.verifier.\(oneTimeId)"
    }

    /// Lifecycle id (post-uninstall purge marker):
    /// `rakomi.v1.lifecycle_id.<tenantId>`.
    static func lifecycleId(tenantId: String) -> String {
        return "\(storageNamespace).lifecycle_id.\(tenantId)"
    }

    /// Lifecycle id MARKER in UserDefaults (cleared on uninstall):
    /// `rakomi.v1.lifecycle_id_marker.<tenantId>`.
    static func lifecycleIdMarker(tenantId: String) -> String {
        return "\(storageNamespace).lifecycle_id_marker.\(tenantId)"
    }

    /// Clock-skew offset (ms) captured from server `Date` header:
    /// `rakomi.v1.clock_skew_ms.<tenantId>`.
    static func clockSkewMs(tenantId: String) -> String {
        return "\(storageNamespace).clock_skew_ms.\(tenantId)"
    }

    /// Last system-browser auth timestamp (fresh-auth window):
    /// `rakomi.v1.fresh_auth.<tenantId>`.
    static func freshAuthTimestamp(tenantId: String) -> String {
        return "\(storageNamespace).fresh_auth.\(tenantId)"
    }

    /// Tenant-scoped prefix used for fresh-install purge sweep.
    /// ⚠ UNWIRED + the `tenantId` parameter is unused in the body — the
    /// returned prefix is namespace-wide (`rakomi.v1.`), not tenant-scoped
    /// as the doc comment claims. No call site in `Sources/`. Internal —
    /// not part of the public API surface.
    static func tenantPrefix(tenantId: String) -> String {
        return "\(storageNamespace)."
    }

    /// Returns true iff `key` has the canonical `rakomi.v1.` prefix —
    /// used by the cross-tenant purge to confirm exact-prefix-match — a
    /// substring match would let the purge reach keys outside the namespace.
    /// ⚠ UNWIRED in production: no call site in `Sources/`. The
    /// cross-tenant purge this doc comment describes does not currently
    /// call it.
    static func hasCanonicalPrefix(_ key: String) -> Bool {
        return key.hasPrefix("\(storageNamespace).")
    }
}
