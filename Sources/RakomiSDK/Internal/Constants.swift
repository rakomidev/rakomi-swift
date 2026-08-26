// Named constants. No magic numbers.

import Foundation

/// Default refresh leadtime: refresh tokens automatically when within 60s
/// of `expiresAt`. Matches RN/Flutter `kDefaultRefreshLeadtime`.
let defaultRefreshLeadtime: TimeInterval = 60

/// Default value carried by `RakomiAuthConfiguration.freshAuthWindow`.
/// ⚠ NOT WIRED — no code path reads it, so it gates and skips nothing.
/// KEPT public: a public init's default-argument expression must be at
/// least as accessible as the init itself —
/// `RakomiAuthConfiguration.init(freshAuthWindow:)` defaults to this
/// symbol, so narrowing it to `internal` fails to compile for an external
/// caller ("referenced from a default argument value"), independent of
/// whether the field itself does anything.
public let defaultFreshAuthWindow: TimeInterval = 30

/// Maximum JWKS payload accepted from `/.well-known/jwks.json`.
/// Defensive cap — anomalous-large responses are rejected as
/// `SdkError(reason:.network, errorMessage: "jwks_oversize")`.
let maxJWKSResponseBytes: Int = 16 * 1024

/// JWKS cache TTL — fetched JWKS valid for 24h before refetch.
let jwksCacheTTL: TimeInterval = 24 * 60 * 60

/// Refresh retry backoff envelope: 2s, 8s, 30s. Matches RN/Flutter SDK.
let refreshBackoffSeconds: [TimeInterval] = [2, 8, 30]

/// Maximum absolute clock-skew (±5 min) accepted before falling back to
/// online verification. Defense against spoofed device clocks.
let maxAcceptableClockSkew: TimeInterval = 5 * 60

/// OFFLINE_STALE watchdog cycle limit (3 cycles → forced re-auth), so an
/// unverifiable session cannot be extended indefinitely while offline.
let offlineStaleMaxCycles: Int = 3

/// PKCE code verifier byte length (RFC 7636 §4.1: 43..128 base64url chars
/// → 32 random bytes encoded gives 43 chars).
let pkceVerifierBytes: Int = 32

/// OAuth `state` parameter byte length (32 bytes random, base64url-encoded).
let oauthStateBytes: Int = 32

/// SDK version exposed to USER-AGENT and SBOM components.
let rakomiSDKVersion: String = "0.1.0"

/// Default JWKS path appended to `apiBaseURL`.
/// ⚠ UNWIRED: `RakomiAuthConfiguration.init` hardcodes the literal
/// `.well-known/jwks.json` path instead of referencing this constant —
/// nothing in the module reads it. Internal — not part of the public API
/// surface.
let defaultJWKSPath: String = "/.well-known/jwks.json"

/// Storage namespace prefix. v1 is reserved for future migration.
let storageNamespace: String = "rakomi.v1"

/// User-Agent identifying the SDK on outbound API requests.
let rakomiUserAgent: String = "RakomiSwiftSDK/\(rakomiSDKVersion)"
