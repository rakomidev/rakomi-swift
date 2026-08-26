# RakomiSDK — Native Swift SDK for Apple Platforms

> Authentication for iOS, macOS, tvOS, and visionOS apps.
> RFC 8252-compliant OAuth/PKCE via system browser, RFC 8628 device-code
> flow on tvOS, native Sign in with Apple, biometric unlock, MFA TOTP,
> offline-tolerant token refresh, SwiftUI integration. Zero third-party
> runtime dependencies.
>
> **watchOS scope:** the package declares watchOS 9 as a deployment target and
> compiles for it, but ships **no interactive sign-in flow** on watchOS —
> `ASWebAuthenticationSession` is unavailable there, and biometric unlock
> reports unavailable on watchOS unconditionally. A watchOS app can link the
> SDK; authentication must be carried out on a paired device. The companion
> auth path is a follow-up, not a shipped feature.

## Quickstart (<15 lines)

```swift
import SwiftUI
import RakomiSDK

@main
struct DemoApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .rakomi(configuration: try! RakomiAuthConfiguration(
                    publishableKey: "pk_test_acme",
                    redirectURI: URL(string: "myapp://callback")!
                ))
        }
    }
}

struct ContentView: View {
    var body: some View {
        RakomiAuthGate(
            signedIn: { user in RakomiUserAvatar() },
            signedOut: { RakomiSignInForm() }
        )
    }
}
```

## What this SDK gives you

- **EU-based operator**: Rakomi is operated by CRE8EVE Sp. z o.o., incorporated
  in Poland; primary infrastructure and database hosting are in the EU. The
  sub-processor list, processing locations and transfer safeguards are set out
  in the Data Processing Agreement, which is the authoritative source — this
  README makes no transfer determination.
- **Multi-tenant by design**: tenant binding via JWT claims, NOT scope strings;
  cross-tenant lookup returns 404 (NEVER 403).
- **Open standards**: OAuth 2.0 / PKCE / RFC 8252 / RFC 8628 / OIDC-ready /
  OAuth 2.1-ready (PKCE-mandatory, no implicit, no password-grant for new clients).
- **Zero supply-chain bloat**: ZERO third-party runtime dependencies. Apple
  frameworks (`AuthenticationServices`, `LocalAuthentication`, `CryptoKit`,
  `Security`, `Network`, `BackgroundTasks`) cover the entire surface.
- **Privacy considerations (RFC 6973)**: SDK does NOT log tokens, does NOT
  collect device telemetry by default, does NOT phone home.
- **No cookies / no CSRF in SDK**: Bearer tokens only.

## OIDC vs OAuth 2.0 in Rakomi

We issue OAuth 2.0 access tokens RS256-signed with `kid` header. Token
lifetimes: access ~15 min, refresh ~7 days. `id_token` landing for OIDC
relying-party scenarios is a future release — out of scope for 0.1.

## Tenant scope vs OAuth scopes

Tenant binding lives in the JWT claims (`tenant_id`), not in OAuth `scope`
strings. Multi-tenant clients pass their tenant via `publishableKey` on the
SDK configuration; the API server enforces tenant isolation at the row-level
security layer.

## Why no third-party runtime deps

Per CRA Reg. 2024/2847 ("product with digital elements") and NIS2
supply-chain posture: every additional runtime dependency is a 10-year
disclosure liability. Apple's frameworks are sufficient for our entire
auth surface (`SecRandomCopyBytes` for CSPRNG, `CryptoKit` for SHA-256,
`Security` framework for Keychain + RS256 verification,
`AuthenticationServices` for system browser + Sign in with Apple).

## OAuth 2.1 readiness

- PKCE S256 mandatory (no `plain` fallback).
- Implicit grant: not used.
- Password grant: not used for new clients.
- Refresh-token rotation: server-side (consumed via `/v1/auth/refresh`).

## Custom URL scheme caveats

This SDK uses custom URL schemes (`myapp://callback`). Universal Links /
Associated Domains migration is planned and does not ship today.
Until then, ensure your scheme is unique to your app's bundle identifier
to avoid scheme-hijack on a multi-tenant device.

## Provisioning & code-signing

- **iOS**: register your `CFBundleURLTypes` URL scheme in `Info.plist`.
- **Sign in with Apple**: enable the `com.apple.developer.applesignin`
  capability in your Apple Developer team.
- **macOS sandboxed apps**: declare `com.apple.security.network.client` in
  your `.entitlements`.

```xml
<!-- Info.plist (iOS) -->
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array><string>myapp</string></array>
  </dict>
</array>
```

## Transport security

`RakomiAuthConfiguration(apiBaseURL:)` requires `https://`. Exactly one
exception exists, for local development, and the initializer throws without it:
an `http://` URL is accepted only when the host is exactly `localhost`, or a
dotted-quad IPv4 address in `127.0.0.0/8` or `10.0.0.0/8`. Any other `http://`
URL is rejected before a configuration is constructed.

⚠ `10.0.0.0/8` is a **private LAN range, not loopback** — traffic to it leaves
the device. Treat that exception as a development convenience only, and never
point a production build at a plaintext `http://` address.

Optional certificate pinning (`certificateFingerprints`) applies to the
`https://` requests the SDK issues.

## Threat model — residual risks NOT mitigated by SDK alone

- **Jailbroken iOS device**: Keychain extraction tools bypass
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Consumer apps SHOULD
  detect jailbreak.
- **Device PIN bypass**: out of SDK scope.
- **Screen-overlay / clickjacking**: out of SDK scope.
- **Keylogger**: out of SDK scope.
- **App-switcher screenshot leak**: consumer app's responsibility (apply
  privacy overlay on `applicationWillResignActive`).
- **MITM on managed networks**: corporate proxies intercepting TLS.
  Mitigation: optional `certificateFingerprints` SHA-256 pinning.

## Compliance posture

- **CRA (Reg. 2024/2847)**: coordinated vulnerability disclosure via
  `security@rakomi.com`. The disclosure process, the timelines we commit to and
  the record-keeping are described in `SECURITY.md`.
- **GDPR Art. 17 (right to erasure)**: `signOut()` clears local state;
  fresh-install purge clears post-uninstall residue.
- **GDPR Art. 25 (privacy by design)**: non-blocking mount, no telemetry,
  no token logging, Keychain namespacing, secure defaults.
- **GDPR Art. 32 (technical measures)**: Keychain encryption-at-rest with
  `AfterFirstUnlockThisDeviceOnly`, RS256, CSPRNG via `SecRandomCopyBytes`,
  HTTPS required for the API base URL with a development-only `http://`
  exception (see "Transport security" below), redacted error strings.
- **NIS2 supply-chain**: ZERO third-party runtime dependencies; coordinated
  vulnerability disclosure — see `SECURITY.md`.
- **PSD2/PSD3**: the SDK can carry a TOTP factor (possession) and a biometric
  factor (inherence), when the API operator configures factor binding. Whether a
  given deployment satisfies strong customer authentication is a determination
  for the operator and their supervisor — the SDK does not make it and certifies
  nothing.
- **NIST SP 800-63B AAL2 candidate**: MAY meet AAL2 when API operator
  configures factor binding; SDK does not certify AAL2 unilaterally.

## Audit logging

The `events` AsyncStream emits fine-grained `AuthEvent` values. Consumer
apps SHOULD wire selected events into their audit log pipeline:

| Event | Audit significance |
|---|---|
| `signedIn(User)` | high |
| `signedOut(reason)` | high |
| `mfaChallengeVerified` | high |
| `sessionRevoked` | high |
| `mfaChallengeRequired` | medium |
| `userUpdated` | medium |
| `tokenRefreshed` | low |

The SDK does NOT auto-forward events to any analytics sink — consumer-pull
only.

## EUDI Wallet roadmap

`SocialProviderExtension.eudiWallet` exists as a forward-compat factory hook
for the EUDI Wallet provider mandate (Reg. 2024/1183 implementing acts,
end of 2026). Today this is a placeholder; the actual integration ships in a
follow-up release.

## tvOS authentication flow

tvOS does NOT support `ASWebAuthenticationSession` (Apple restriction —
TV is a shared-screen device). The tvOS flow uses **OAuth 2.0 Device
Authorization Grant (RFC 8628)**:

```swift
// On tvOS
let start = try await RakomiAuth.shared.startDeviceAuthorization()
// Display start.userCode + start.verificationURI to the user;
// they enter the code on their phone/computer at https://rakomi.com/device.
// SDK polls in the background and transitions to `.authenticated` on approval.
```

`RakomiDeviceCodeView` (SwiftUI) does the display + polling automatically.

## Distribution

```
.package(url: "https://github.com/rakomidev/rakomi-swift", from: "0.1.0")
```

Add `RakomiSDK` to your target's dependencies. Releases on this repository are tagged with bare
SemVer (`X.Y.Z`, no prefix) — e.g. `0.1.0` — matching the `from:` version above.

## Development

This repository is a release snapshot of the Rakomi Swift SDK — tests and maintainer
tooling are not included here.

```sh
swift build -Xswiftc -warnings-as-errors
```

Found a bug or have a feature request? Please open an issue or pull request on this
repository's issue tracker.

## Publisher webhooks

`verifyPublisherWebhook` verifies Rakomi publisher-app webhook deliveries (Standard Webhooks
HMAC-SHA256, replay defence, key-rotation tolerance). See the canonical
[publisher-webhook receiver contract](https://docs.rakomi.dev/guides/publisher-webhooks/).

## License

MIT. See `LICENSE`.
