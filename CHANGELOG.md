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

## [Unreleased]

API version: /v1

### Changed

- **Breaking: a browser sign-in session refreshes at the token endpoint.** The API
  no longer refreshes a session issued to an OAuth client at `/v1/auth/refresh`, so
  the SDK records which client made the session (stored with the refresh token,
  kept across launches, cleared on sign-out) and refreshes it at the published
  `token_endpoint` with `grant_type=refresh_token` and that `client_id` (a DPoP
  proof, when bound, names the token endpoint). Password, MFA, magic link, native
  Sign in with Apple and device-code sessions keep `/v1/auth/refresh`.
- **Breaking: `completeSignIn(accessToken:refreshToken:expiresIn:oauthClientId:)`**
  takes a required `oauthClientId`: the `client_id` the tokens were issued to at
  the token endpoint, or `nil` for tokens from a `/v1/auth/*` endpoint. Existing
  calls no longer compile until they pass it.
- **Breaking: `DpopRefreshTransport.sendRefresh` takes `endpoint: RefreshEndpoint`**
  (`.firstParty` or `.tokenEndpoint(url, clientId:)`) and `DpopRefresh.refresh`
  takes `endpoint:` in place of `tokenEndpoint:`. A custom transport must post to
  the endpoint it is given.
- `AuthorizationServerMetadata` carries the published `revocationEndpoint`.

### Fixed

- `signOut()` ends the server session. It posted the refresh token to
  `/v1/auth/logout`, which authenticates with the access token instead. A first-party session now calls
  `/v1/auth/logout` with its access token (`DPoP` and a proof when bound); a browser
  sign-in session revokes its refresh token at the published RFC 7009
  `revocation_endpoint` with its `client_id`. Local sign-out never waits on either.
- **tvOS device-code sign-in no longer stops at the first pending poll.**
  `DeviceCode` read the polling state from an `error` member, but
  `/v1/auth/oauth/device/token` answers RFC 8628 §3.5 states as RFC 9457
  problem+json (HTTP 400) with the state in `code`
  (`oauth/authorization_pending`, `oauth/slow_down`, `oauth/access_denied`,
  `oauth/expired_token`). Every pending answer ended the flow with
  `device_token_status_400`; the SDK now reads `code`. A `slow_down` answer
  raises the polling interval by 5 seconds (RFC 8628 §3.5) instead of
  doubling it.

## [0.2.0] - 2026-10-06

API version: /v1

This release contains breaking changes; see `MIGRATION.md` for the 0.1 → 0.2 upgrade steps.

### Changed

- **Breaking: signing keys are read from the expected issuer's own `jwks_uri`.**
  `RakomiAuthConfiguration.jwksURL` is now optional and `nil` by default: keys
  come from the issuer's discovery document (OAuth 2.0 Authorization Server
  Metadata first, then OpenID Connect Discovery, both path-aware), so a key
  published by any other issuer is never trusted. RS256, PS256 and ES256
  (P-256) are accepted, the token header must name the same `alg` as its key,
  and a token without an `iss` claim is rejected.
- **Breaking: `signUp` takes a required `consent` parameter.** The API requires the
  `consent` flag, and without it registration was rejected
  `400 validation/invalid_request` for every caller. It has no default: consent is an
  act the application witnesses, and the SDK cannot supply it on the person's behalf.
  Existing `signUp` calls no longer compile until they pass it.
- **Breaking: `User.emailVerified` is `Bool?`.** An absent `email_verified` claim used
  to arrive as `false`, so an app showed "not verified" for accounts that are verified —
  the platform's access token carries the claim on some paths and omits it on others.
  `nil` now means "not stated"; code that read it as a `Bool` must handle `nil`.

### Fixed

- **A temporary failure during refresh no longer signs the user out.** A server error, `429`,
  `408` or a dropped connection keeps the session, the stored refresh
  token and any DPoP key binding; the typed error now carries the HTTP status (`httpStatus`) and
  the server's `Retry-After` (`retryAfter`), and no further refresh is sent until that delay has
  passed (at most two minutes). A temporary failure at app launch keeps the stored credential and
  the next `getToken()` tries again. Only a definitive rejection — a bare `401`, a `4xx`
  naming the grant or the client as invalid (`invalid_grant`, `invalid_client`,
  `invalid_token`, `unauthorized_client`, `access_denied`), or a `403` whose `code` is
  `auth/user_blocked` or `auth/pending_parental_consent` — ends the session; a `403` without
  one of those codes no longer does, and a `400 invalid_grant` now does. A `2xx` the SDK cannot
  read also ends the session, and the refresh token is not sent again: the server has already
  consumed it, and presenting it again would count as reuse.
- **Offline JWT verification hardcoded `RakomiAuthConfiguration.issuer` to the frozen platform
  constant regardless of the SDK's own configured `apiBaseURL`.** Now that a tenant's issuer can be
  its own bound custom-domain host, the default `issuer` is derived FROM `apiBaseURL`
  (`RakomiAuthConfiguration.deriveDefaultIssuer(from:)`, RFC 8414 §3.3 style, trailing-slash
  normalized, tenant-path-suffix aware) instead of hardcoded — mirrors the same generalization
  `@rakomi/react-native` shipped for `expectedIssuer`. A PLATFORM host (`isPlatformHost(_:)` —
  `rakomi.com` or any subdomain of it, or a local-dev host) ALWAYS expects the frozen constant
  regardless of which platform host `apiBaseURL` names — the server's own issuer identity is frozen
  there in every environment, so deriving the expectation from the host itself would reject every
  real token a staging/dev deployment mints; only a genuinely different (custom-domain) host
  expects `apiBaseURL` itself. `audience` stays the frozen platform constant (confirmed
  server-side: user-flow token `aud` never varies with the resolved per-tenant `iss`). **Zero
  behaviour change for a platform-hosted tenant, on ANY platform host** (proven by a dedicated
  should-PASS/backward-compat test pair driven through the real `JWTVerifier.verify` with a real
  RS256 signature, plus should-FAIL plants for a confusable non-platform host such as
  `evilrakomi.com`). The persisted JWKS cache Keychain slot (`StorageKeys.jwks`/`jwksETag`) is now
  also scoped per-host (in addition to per-tenant), so a tenant's issuer-host change across app
  upgrades never silently reuses a stale cross-host JWKS document as "fresh".
- Sign-in could not succeed against the API at all, for four independent reasons, each
  now pinned by its own test.
  - The tenant publishable key was sent as `X-Rakomi-Publishable-Key`, a header the API
    does not read. Every first-party auth request was answered `401` before its body was
    considered. It now travels as `X-API-Key`, the header the other Rakomi SDKs send.
  - Token responses were decoded with camelCase property names against a snake_case wire,
    so a successful response decoded to nothing and surfaced as `response_decode_failed`.
    `/v1/auth/login`, `/v1/auth/refresh`, `/v1/auth/mfa/verify-login` and the device-code
    token endpoint now share one explicitly mapped envelope.
  - A key set containing any key this SDK does not verify with — an EC key alongside the
    RSA signing keys — failed to decode in full, so no signature could be verified.
    Unusable entries are now ignored, as RFC 7517 §5 requires.
  - Transport failures escaped as bare `URLError`s past every `SdkError` handler and were
    reported as an unexplained sign-in failure. They are mapped to
    `SdkError(code: .networkError)`.
- Browser sign-in reaches a login page. `signIn(withProvider:)` called
  `/v1/auth/oauth/start` and `/v1/auth/oauth/callback`, neither of which exists,
  so a provider button on the prebuilt form led to a 404 in the browser sheet. It
  is now the standard authorization-code exchange with PKCE: the endpoints come
  from the server's `/.well-known/oauth-authorization-server` document rather
  than being constructed — the host that serves the API is not the host that
  renders the login page — and the code is exchanged form-encoded at the
  published token endpoint.
- `RakomiAuthConfiguration` takes `clientId` and `scope`. Browser sign-in is an
  authorization-code exchange and needs a public OAuth client; the publishable
  key identifies the tenant and is not a substitute for one.
- A configuration that cannot start a browser sign-in no longer offers it.
  `signIn(withProvider:)` reports the new `not_configured` reason without opening
  a browser, and `RakomiSignInForm` renders no provider buttons.
- Every subscriber to `authStateChanges()` and `events()` now gets its own
  stream. Both used to hand out ONE `AsyncStream`, which has a single consumer by
  construction, so two listeners split the sequence between them instead of both
  seeing it — measured at 3 and 7 over ten emissions. The SDK subscribes three
  times itself (`RakomiProvider`, `RakomiSignInForm`,
  `RakomiAuthUIKitObserver.attach`), so an app that listened for its own purposes
  took transitions away from the SDK's own UI. A new state subscriber is handed
  the current state; events are not replayed.
- `getToken()` no longer re-enters itself while hydration is in flight. Its
  `loading` branch is "hydrate, then ask again", and `hydrate()` used to return
  the moment its "already done" flag was set — before the first pass had produced
  a state — so the second caller hydrated to a no-op, saw `loading` again and
  recursed. `hydrate()` now awaits the pass in progress, and `getToken()` reads
  the settled state once instead of asking again.
- Errors from the API carry the server's own code and detail. `mapErrorStatus`
  parsed both and then discarded them for every status but 403, so a rejected
  request reported `http_400` and nothing about which field was refused.
- `RakomiAppleSignInButton` reports failures. A cancelled sheet, an unexpected
  credential type and a missing identity token all returned silently, leaving the
  app on the signed-out screen with nothing to show; cancellation is now
  distinguishable from a provider error.
- The JWT verification tests read the wall clock while their fixture is signed once with a
  one-hour expiry, so a bare `swift test` failed two cases on any checkout older than the last
  regeneration. They now take their clock from the fixture's own `iat`.
- The MFA step of a password sign-in posted to a path that does not exist, with a field
  name the API does not accept. It now posts `mfa_challenge_token` to
  `/v1/auth/mfa/verify-login`, and reads the challenge out of the login response's
  `next_step`/`mfa_challenge_token` rather than a `nextAction`/`challengeId` pair that was
  never on the wire.
- `signUp` claimed to sign the new account in. Registration returns no tokens — the
  address has to be verified first — so it now settles on `signedOut` and says so.
- `RakomiAuthConfiguration.issuer`'s documentation said it defaults to `apiBaseURL`; it
  defaults to the platform issuer, which is what the code has always done.

### Security

- **Opt-in biometric lock in front of the stored credential.** New
  `RakomiAuthConfiguration(requireBiometricUnlock:biometricPromptReason:)`
  (default `false`, no change for existing apps). When on, the SDK prompts
  BEFORE it reads or uses the stored refresh credential — on `hydrate()`, on
  `getToken()` when it has to restore or refresh the session, and on every
  refresh — unless a prompt succeeded within `freshAuthWindow`. A cancelled,
  failed or unavailable prompt yields no token: a typed `SdkError` with code
  `.biometricError`, and the stored credential is kept for a retry.
  `freshAuthWindow` previously had no effect and is now the length of that
  window. Previously the only biometric path was `unlockWithBiometric(reason:)`,
  which the app had to call itself; it was not a gate, and `hydrate()` /
  `getToken()` used the stored credential without prompting. Apps that turn
  the lock on see a prompt on cold start and when a refresh needs the stored
  credential outside the window.

## [0.1.0] - 2026-08-26

API version: /v1

First public release.

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
