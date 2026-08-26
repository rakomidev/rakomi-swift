# Examples — watchOSDemo

watchOS does NOT support `ASWebAuthenticationSession` directly — primary
authentication is via the paired iPhone (`WCSession`). This package ships
the **build target only**; the runtime auth path is deferred to a
companion-auth flow that is planned but does not ship today.

Until then, the watchOS demo shows a placeholder:

```swift
import SwiftUI
import RakomiSDK

struct ContentView: View {
  var body: some View {
    VStack {
      Text("Sign in with iPhone")
      RakomiSignInButton(provider: .apple)
    }
  }
}
```

Refresh-token persistence + biometric short-circuit (`SdkErrorReason.biometricUnavailable`)
already work as documented in the acceptance criteria.
