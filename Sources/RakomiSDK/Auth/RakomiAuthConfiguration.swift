// Public configuration entry point.
//
// `throws` initializer per Swift idiom: invalid configuration MUST surface
// synchronously, not via `authStateChanges`. Programmer errors only —
// runtime auth failures still go through the AsyncStream.

import Foundation

/// Default expected `iss`/`aud` when a caller derives neither from its own
/// configuration. Mirrors `rakomi_flutter`'s `kRakomiPlatformIssuerDefault`/
/// `kRakomiPlatformAudienceDefault` and `@rakomi/react-native`'s
/// `RAKOMI_PLATFORM_ISSUER_DEFAULT`/`RAKOMI_PLATFORM_AUDIENCE_DEFAULT`
/// (`packages/react-native/src/internal/token-runtime.ts`).
let kRakomiPlatformIssuerDefault = URL(string: "https://api.rakomi.com")!
let kRakomiPlatformAudienceDefault = "https://api.rakomi.com"

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

    /// JWT issuer claim. Defaults to a value DERIVED from `apiBaseURL` (see
    /// `deriveDefaultIssuer(from:)`) — a tenant that has bound its own custom
    /// domain as its issuer host is issued tokens whose `iss` is that host
    /// (RFC 8414 §3.3), not a shared platform constant. A PLATFORM host
    /// (`isPlatformHost(_:)` — `rakomi.com`/any subdomain of it, or a
    /// local-dev host) always degrades to the frozen platform constant
    /// instead, since the server's issuer identity is frozen there in every
    /// environment. Multi-issuer test harnesses override it explicitly.
    public let issuer: URL

    /// Override where signing keys are read from. `nil` (the default) reads
    /// the `jwks_uri` named in the expected issuer's discovery document, so
    /// only that issuer's keys are trusted. Rare in production (a JWKS proxy).
    public let jwksURL: URL?

    /// OAuth client id for the browser sign-in flow (RFC 6749 §2.2). Required
    /// for `signIn(withProvider:)`, which is an authorization-code exchange with
    /// PKCE against the tenant's hosted login; the publishable key identifies the
    /// tenant and is not a substitute for it.
    ///
    /// The client must be a PUBLIC client — a native app cannot keep a secret —
    /// and must have this configuration's `redirectURI` registered on it, byte
    /// for byte. Leave it `nil` if the app signs in with a password only: the
    /// prebuilt sign-in form then renders no provider buttons, rather than
    /// offering an action that cannot complete.
    public let clientId: String?

    /// Scopes requested on the browser flow. Defaults to `openid profile email`.
    public let scope: String

    /// Optional Keychain access group for app-extension / app-group sharing.
    public let keychainAccessGroup: String?

    /// Whether this configuration can start a browser sign-in at all.
    public var supportsBrowserSignIn: Bool {
        guard let clientId else { return false }
        return !clientId.isEmpty
    }

    /// How long, in seconds, a successful biometric prompt keeps the biometric
    /// lock open. Read only when `requireBiometricUnlock` is `true`; with the
    /// lock off it has no effect.
    ///
    /// Inside the window, hydration and token refreshes use the stored
    /// credential without prompting again. Once it has elapsed, the next
    /// operation that needs the stored credential prompts first. `0` prompts
    /// on every such operation. A successful `unlockWithBiometric(reason:)`
    /// also opens the window.
    public let freshAuthWindow: TimeInterval

    /// Optional SHA-256 certificate fingerprints for pinning. Accepted forms:
    /// base64 (the canonical one in the published contract), hex, or hex with
    /// colons — all normalised before comparison. Nil or empty disables
    /// pinning; it never widens what is accepted.
    public let certificateFingerprints: [String]?

    /// Default audience for JWT verification. Frozen to
    /// `kRakomiPlatformAudienceDefault` (`https://api.rakomi.com`) — the
    /// platform audience, independent of `apiBaseURL`: Rakomi user-flow
    /// access tokens never vary `aud` with the resolved per-tenant `iss`
    /// (confirmed server-side). Customer overrides remain supported for
    /// multi-issuer test harnesses.
    public let audience: String?

    /// Opt-in biometric lock. Defaults to `false`, which keeps the stored
    /// credential usable without a prompt.
    ///
    /// When `true`, the SDK shows the system biometric prompt BEFORE it reads
    /// or uses the stored refresh credential: on `hydrate()` (cold start),
    /// on `getToken()` when it has to restore or refresh the session, and on
    /// every refresh — unless a biometric prompt already succeeded within
    /// `freshAuthWindow`. An access token already held in memory after a
    /// successful unlock is returned without prompting.
    ///
    /// A cancelled, failed or unavailable prompt yields no token: `getToken()`
    /// and `refreshTokens()` throw an `SdkError` with code `.biometricError`
    /// (reason `.biometricCancelled`, `.biometricLockout`,
    /// `.biometricNotEnrolled` or `.biometricUnavailable`), and hydration
    /// settles on `AuthState.error` with that error. The stored credential is
    /// kept, so a later `getToken()` or `unlockWithBiometric(reason:)` can
    /// retry. Hydration prompts only when a stored credential exists.
    public let requireBiometricUnlock: Bool

    /// Reason shown in the system biometric dialog when the lock prompts.
    public let biometricPromptReason: String

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
        clientId: String? = nil,
        scope: String = "openid profile email",
        keychainAccessGroup: String? = nil,
        freshAuthWindow: TimeInterval = defaultFreshAuthWindow,
        certificateFingerprints: [String]? = nil,
        audience: String? = nil,
        requireBiometricUnlock: Bool = false,
        biometricPromptReason: String = defaultBiometricPromptReason
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
        // Default expected `iss` is DERIVED from `apiBaseURL`, not unconditionally
        // hardcoded to the platform constant: a tenant that has bound its own custom
        // domain as its issuer host is issued tokens whose `iss` is that host (RFC
        // 8414 §3.3) — a custom domain is NOT routing-only. A PLATFORM host
        // (`isPlatformHost(_:)`), by contrast, always expects the frozen platform
        // constant regardless of which platform host `apiBaseURL` names — the
        // server's own issuer identity is frozen there in every environment, so
        // deriving the expectation from the host itself would reject every real
        // token a staging/dev deployment mints. See `deriveDefaultIssuer(from:)`'s
        // doc comment for the exact host classification.
        self.issuer = issuer ?? Self.deriveDefaultIssuer(from: apiBaseURL)
        self.jwksURL = jwksURL
        self.clientId = clientId
        self.scope = scope
        self.keychainAccessGroup = keychainAccessGroup
        self.freshAuthWindow = freshAuthWindow
        self.certificateFingerprints = certificateFingerprints
        // Default audience is the frozen platform constant
        // `kRakomiPlatformAudienceDefault`, independent of `apiBaseURL` — Rakomi
        // user-flow access tokens never vary `aud` with the resolved per-tenant
        // `iss` (confirmed server-side). A customer-supplied override is preserved
        // for test harnesses.
        self.audience = audience ?? kRakomiPlatformAudienceDefault
        self.requireBiometricUnlock = requireBiometricUnlock
        self.biometricPromptReason = biometricPromptReason
    }

    // MARK: - Issuer derivation

    /// True iff `host` is a PLATFORM host — the server's own JWT issuer
    /// identity is FROZEN to `kRakomiPlatformIssuerDefault` in every
    /// environment (dev, staging, prod alike), so any base URL resolving to
    /// one of these hosts MUST expect the frozen constant, never a value
    /// derived from the host itself.
    ///
    /// - `rakomi.com` or any subdomain of it (`api.rakomi.com`,
    ///   `accounts.rakomi.com`, an environment-qualified `api.` subdomain, …)
    ///   — matched on a DNS LABEL boundary
    ///   (`host == "rakomi.com" || host.hasSuffix(".rakomi.com")`), NEVER by
    ///   substring: `evilrakomi.com` and `rakomi.com.evil.net` must both be
    ///   REJECTED as platform hosts (see the should-FAIL tests).
    /// - `localhost` / `127.0.0.1` / `::1` — the local dev API also mints
    ///   under the same frozen issuer identity.
    ///
    /// `host` is compared lowercase — defensive, since `URL.host` already
    /// lowercases, but this function must not assume that stays true forever.
    static func isPlatformHost(_ host: String) -> Bool {
        let h = host.lowercased()
        if h == "localhost" || h == "127.0.0.1" || h == "::1" { return true }
        return h == "rakomi.com" || h.hasSuffix(".rakomi.com")
    }

    /// Derive the default expected `iss` for offline verification from
    /// [apiBaseURL] — the value this configuration was constructed with.
    ///
    /// **A PLATFORM host** ([isPlatformHost]) always expects
    /// [kRakomiPlatformIssuerDefault] — the server's issuer identity is
    /// frozen there regardless of which platform host the app happens to be
    /// pointed at, so deriving the expectation from the host itself would
    /// reject every real token a staging/dev deployment mints.
    ///
    /// **Any other host** (a tenant's bound custom domain) expects
    /// `baseURL` itself; the derived value strips query/fragment and a
    /// trailing slash so `https://host/env` and `https://host/env/` compare
    /// equal — the ONE leniency this comparison allows, never a
    /// prefix/suffix match. Falls back to [kRakomiPlatformIssuerDefault]
    /// when `baseURL` carries no scheme or host — construction never throws
    /// on this path since `apiBaseURL` was already validated by
    /// `isAcceptableAPIBaseURL` above. Mirrors `rakomi_flutter`'s
    /// `deriveDefaultIssuer` and `@rakomi/react-native`'s
    /// `deriveDefaultIssuer`
    /// (`packages/react-native/src/internal/token-runtime.ts`).
    static func deriveDefaultIssuer(from baseURL: URL) -> URL {
        guard let scheme = baseURL.scheme, let host = baseURL.host, !host.isEmpty else {
            return kRakomiPlatformIssuerDefault
        }
        if isPlatformHost(host) {
            return kRakomiPlatformIssuerDefault
        }
        var authority = host
        if let port = baseURL.port {
            authority += ":\(port)"
        }
        var path = baseURL.path
        if path.count > 1, path.hasSuffix("/") {
            path.removeLast()
        } else if path == "/" {
            path = ""
        }
        guard let derived = URL(string: "\(scheme)://\(authority)\(path)") else {
            return kRakomiPlatformIssuerDefault
        }
        return derived
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

    /// Tenant id derived from the publishable key. A real, dashboard-issued key never carries a
    /// parseable tenant id, so this resolves via a stable hash of the whole key — every call site
    /// hits that path.
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
