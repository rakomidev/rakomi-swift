# RakomiSDK Changelog

## Stability policy

- `0.x` releases follow **additive-only** API evolution. Adapter / public-surface
  shape MAY change between `0.x` minors only when a clear `MIGRATION.md`
  entry accompanies the release.
- Breaking changes within `0.x` lead to a `0.(x+1).0` bump.
- `1.0` promises **full SemVer** including no breaking adapter changes within
  a major; breaking changes go to `2.0`.
- **Every entry below states the API version this release targets** (`API version: /v1`) — this SDK
  is versioned independently of the Rakomi API and of every other Rakomi SDK, pinned to the API
  surface it was built and tested against.

## [Unreleased] — first public release

> Not yet published. The version number and release date of the first public
> release are still to be set; this section is renamed to that version at
> publication time.

API version: /v1

### Added

- Public `RakomiAuth` actor with `signIn`, `signUp`, `signOut`,
  `signIn(withProvider:)`, `verifyMfa`, `getToken`, `refreshTokens`,
  `hasValidSession`, `unlockWithBiometric`, `handleCallbackURL`,
  `startDeviceAuthorization`.
- Sealed `AuthState` envelope (`loading` / `signedOut` / `authenticated` / `error`)
  surfaced via `authStateChanges` AsyncStream.
- Fine-grained `AuthEvent` AsyncStream for analytics consumers.
- Pre-built SwiftUI views: `RakomiProvider` (ViewModifier), `RakomiAuthGate`,
  `RakomiSignInForm`, `RakomiSignInButton`, `RakomiUserAvatar`,
  `RakomiDeviceCodeView`, `RakomiAppleSignInButton`.
- `RakomiNativeAdapter` protocol seam with `DefaultRakomiNativeAdapter` wiring
  Keychain, `ASWebAuthenticationSession`, `LAContext`, `NWPathMonitor`,
  `UIApplication`/`NSApplication`/`WKExtension` lifecycle.
- RFC 8252-compliant OAuth/PKCE state machine with system browser only.
- RFC 8628 device-code flow on tvOS via `RakomiDeviceCodeView`.
- Offline RS256 JWT verification with cached JWKS (24h TTL, ETag-aware,
  `kid`-miss-driven refresh, payload size cap 16KB).
- Constant-time state comparison, anchored loopback dev-bypass, fresh-install
  Keychain purge, JWT/Bearer redaction in error messages.
- iOS 16 / macOS 13 / watchOS 9 / tvOS 16 / visionOS 1.0 minimum deployment
  targets. SPM-only distribution.

### Security

- RS256 signature verification; all security-relevant random values come from
  the platform CSPRNG (`SecRandomCopyBytes`).
- `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for refresh tokens
  (no iCloud Keychain sync).
- Zero production runtime dependencies (CRA Reg. 2024/2847 supply-chain
  posture).
- Public API surface reviewed and narrowed before this release; no public
  behaviour changed.

### Vulnerability disclosure

- `security@rakomi.com` is the coordinated-disclosure inbox. The disclosure
  process and the timelines we commit to are described in `SECURITY.md`.
