# Migrating RakomiSDK

Every minor release on the `0.x` line that changes the public API has a section here.

## 0.2 → next release

### `completeSignIn` takes a required `oauthClientId`

The API refreshes a session issued to an OAuth client only at the token endpoint, with that
client named, so the SDK has to know where tokens you hand it came from:

```swift
// 0.2
try await controller.completeSignIn(accessToken: at, refreshToken: rt, expiresIn: ttl)

// next: tokens from your own authorization-code exchange at /oauth/token
try await controller.completeSignIn(accessToken: at, refreshToken: rt, expiresIn: ttl, oauthClientId: clientId)
// next: tokens from a /v1/auth/* endpoint (password, MFA, magic link, OTP, device code)
try await controller.completeSignIn(accessToken: at, refreshToken: rt, expiresIn: ttl, oauthClientId: nil)
```

A browser sign-in session stored by 0.2 has no client recorded and is refused at its next
refresh; the person signs in again once.

### A custom `DpopRefreshTransport` posts to the endpoint it is given

`sendRefresh(refreshToken:dpopProof:)` is now `sendRefresh(refreshToken:endpoint:dpopProof:)`:
`.firstParty` is `POST /v1/auth/refresh` (JSON), `.tokenEndpoint(url, clientId:)` is a
form-encoded `grant_type=refresh_token` with that `client_id` at `url`. `DpopRefresh.refresh`
takes `endpoint:` in place of `tokenEndpoint:`.

## 0.1 → 0.2

Update the package requirement:

```swift
.package(url: "https://github.com/rakomidev/rakomi-swift", from: "0.2.0")
```

### `signUp` takes a required `consent` argument

`/v1/auth/register` requires the person's consent, and the SDK cannot give it on their behalf. Pass
what your sign-up screen collected:

```swift
// 0.1
await auth.signUp(email: email, password: password)

// 0.2
await auth.signUp(email: email, password: password, consent: termsAccepted)
```

`signUp` no longer reports an authenticated session: registration returns no tokens until the
address is verified, so it settles on `signedOut`.

### Signing keys come from the issuer's own `jwks_uri`

`RakomiAuthConfiguration.jwksURL` is now optional and `nil` by default. The SDK reads the issuer's
discovery document and verifies tokens only against the keys it names. If you set `jwksURL` to a key
set published by a different issuer, tokens from your issuer will no longer verify — remove the
override or point it at your issuer's key set. A token without an `iss` claim is rejected.

### `User.emailVerified` is `Bool?`

An absent `email_verified` claim is now `nil` instead of `false`. Treat `nil` as "unknown", not as
"not verified":

```swift
if user.emailVerified == false { showVerifyBanner() }
```

### Browser and provider sign-in need `clientId`

`RakomiAuthConfiguration` takes `clientId` (your public OAuth client) and `scope`. Without `clientId`,
`signIn(withProvider:)` reports `not_configured` without opening a browser and `RakomiSignInForm`
renders no provider buttons.

### Refresh failures

Only a definitive rejection (a bare `401`, or `invalid_grant`, `invalid_client`, `invalid_token`,
`unauthorized_client`, `access_denied`) signs the user out. A transient failure surfaces as a typed
`SdkError` with `httpStatus` and `retryAfter` while the session is kept; if your app treated every
refresh error as "signed out", check the error before clearing your own state.
