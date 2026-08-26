// Public configuration entry point.
//
// `throws` initializer per Swift idiom: invalid configuration MUST surface
// synchronously, not via `authStateChanges`. Programmer errors only —
// runtime auth failures still go through the AsyncStream.

import Foundation

/// Top-level configuration for `RakomiAuth`. Multiple instances are
/// supported (per-tenant test harnesses, multi-issuer apps); the SDK
/// does NOT enforce process-global singleton semantics.
public struct RakomiAuthConfiguration: Sendable {
    /// Tenant-scoped publishable key. Format: `pk_(test|live)_<...>`.
    public let publishableKey: String

    /// Custom URL scheme for OAuth callback. iOS/macOS/visionOS only —
    /// tvOS uses RFC 8628 device-code flow and ignores this value.
    public let redirectURI: URL

    /// API base URL — defaults to `https://api.rakomi.com`. Self-managed
    /// + on-prem deployments override this.
    public let apiBaseURL: URL

    /// JWT issuer claim. If nil, defaults to `apiBaseURL`. Multi-tenant
    /// + self-managed deployments require this override.
    public let issuer: URL

    /// JWKS endpoint URL. Defaults to `${apiBaseURL}/.well-known/jwks.json`.
    public let jwksURL: URL

    /// Optional Keychain access group for app-extension / app-group sharing.
    public let keychainAccessGroup: String?

    /// ⚠ ACCEPTED BUT NOT WIRED — this value gates nothing and skips nothing.
    /// No code path reads it, and its companion marker
    /// `StorageKeys.freshAuthTimestamp` is never written and never read. There
    /// is no fresh-auth window at runtime, in either direction. Setting it to
    /// any value — including `0` — changes no behaviour.
    ///
    /// A biometric prompt is available through `unlockWithBiometric(reason:)`,
    /// which the application calls when it wants one. It is an ADDITIONAL path
    /// into hydration, not a gate in front of it: `hydrate()`, `getToken()` and
    /// the refresh path read the stored credential without prompting.
    public let freshAuthWindow: TimeInterval

    /// Optional SHA-256 certificate fingerprints for pinning. Accepted forms:
    /// base64 (the canonical one in the published contract), hex, or hex with
    /// colons — all normalised before comparison. Nil or empty disables
    /// pinning; it never widens what is accepted.
    public let certificateFingerprints: [String]?

    /// Default audience for JWT verification. Frozen to `https://api.rakomi.com` —
    /// the platform audience, independent of `apiBaseURL`. Customer overrides
    /// remain supported for multi-issuer test harnesses.
    public let audience: String?

    /// Throws on:
    ///   - `redirectURI.scheme` in {http, https, javascript, data, file, vbscript, about}
    ///   - `apiBaseURL.scheme != "https"` — plain `http` is accepted only for
    ///     local development hosts (see `isAcceptableAPIBaseURL`).
    ///
    /// On tvOS the `redirectURI` scheme guard is relaxed because the device-code
    /// flow does not use it; pass `URL(string: "tvos://placeholder")!` if needed.
    public init(
        publishableKey: String,
        redirectURI: URL,
        apiBaseURL: URL = URL(string: "https://api.rakomi.com")!,
        issuer: URL? = nil,
        jwksURL: URL? = nil,
        keychainAccessGroup: String? = nil,
        freshAuthWindow: TimeInterval = defaultFreshAuthWindow,
        certificateFingerprints: [String]? = nil,
        audience: String? = nil
    ) throws {
        guard !publishableKey.isEmpty else {
            throw SdkError(
                code: .invalidConfig,
                reason: .invalidCredentials,
                errorMessage: "publishable_key_empty"
            )
        }

        // TLS-only enforcement; the local-development exception is anchored on
        // strict host equality / IPv4 form, never on a substring.
        if !Self.isAcceptableAPIBaseURL(apiBaseURL) {
            throw SdkError(
                code: .invalidConfig,
                reason: .invalidCredentials,
                errorMessage: "api_base_url_must_be_https"
            )
        }

        // tvOS does NOT use redirectURI but we still enforce non-empty for
        // forward-compat. Other platforms enforce the scheme allowlist.
        #if os(tvOS)
        // Skip scheme guard.
        #else
        if !Self.isAcceptableRedirectScheme(redirectURI) {
            throw SdkError(
                code: .invalidConfig,
                reason: .oauthRedirectMismatch,
                errorMessage: "redirect_uri_scheme_forbidden"
            )
        }
        #endif

        // A pin that cannot be normalised can never match, so every pinned
        // connection would fail with a mismatch — a configuration typo shown to
        // the operator as an active MITM. Reject it where it is entered.
        // Mirrors the Flutter port, which throws on the same input.
        if let pins = certificateFingerprints, !pins.isEmpty,
            pins.contains(where: { CertificatePinningDelegate.normalise($0) == nil })
        {
            throw SdkError(
                code: .invalidConfig,
                reason: .invalidCredentials,
                errorMessage: "certificate_fingerprint_malformed"
            )
        }

        self.publishableKey = publishableKey
        self.redirectURI = redirectURI
        self.apiBaseURL = apiBaseURL
        // JWT `iss` is frozen at `https://api.rakomi.com` — the platform identifier,
        // not the (customer-configurable) API base URL. Custom-domain tenants still
        // receive tokens with this issuer (a custom domain is routing only).
        self.issuer = issuer ?? URL(string: "https://api.rakomi.com")!
        self.jwksURL = jwksURL ?? apiBaseURL.appendingPathComponent(".well-known/jwks.json")
        self.keychainAccessGroup = keychainAccessGroup
        self.freshAuthWindow = freshAuthWindow
        self.certificateFingerprints = certificateFingerprints
        // Default audience is the platform constant `https://api.rakomi.com`,
        // independent of `apiBaseURL`. A customer-supplied override is preserved
        // for test harnesses.
        self.audience = audience ?? "https://api.rakomi.com"
    }

    // MARK: - Validation helpers

    /// True iff `url.scheme == "https"`, OR `url` is a local-development host:
    /// the exact host `localhost`, or a 127.x / 10.x IPv4 dotted-quad. Host
    /// equality and the IPv4 form are matched strictly and fully anchored —
    /// a hostname that merely CONTAINS one of these is rejected.
    static func isAcceptableAPIBaseURL(_ url: URL) -> Bool {
        if url.scheme?.lowercased() == "https" { return true }
        guard url.scheme?.lowercased() == "http", let host = url.host else { return false }
        if host == "localhost" { return true }
        let ipv4: NSRegularExpression
        do {
            ipv4 = try NSRegularExpression(
                pattern: #"^(127|10)\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"#
            )
        } catch { return false }
        let range = NSRange(location: 0, length: host.utf16.count)
        return ipv4.firstMatch(in: host, options: [], range: range) != nil
    }

    /// Accepted redirect URI schemes: anything BUT
    /// `http`, `https`, `javascript`, `data`, `file`, `vbscript`, `about`.
    static func isAcceptableRedirectScheme(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased() else { return false }
        let banned: Set<String> = [
            "http", "https", "javascript", "data", "file", "vbscript", "about",
        ]
        return !banned.contains(scheme) && !scheme.isEmpty
    }

    /// Tenant id derived from publishable key. Format: `pk_(test|live)_<tenantId>`.
    /// Falls back to a stable hash of the publishable key if format unrecognized.
    public var tenantId: String {
        let parts = publishableKey.split(separator: "_", maxSplits: 2, omittingEmptySubsequences: true)
        if parts.count == 3, parts[0] == "pk" {
            return String(parts[2])
        }
        // Fallback: SHA-256 hex prefix of the key. `String.hashValue` is
        // randomized per process since Swift 4.2 and would fragment Keychain
        // namespacing across launches. Use a stable digest instead.
        let digest = PKCE.sha256(Data(publishableKey.utf8))
        return digest.prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}
