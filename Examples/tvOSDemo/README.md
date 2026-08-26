# Examples — tvOSDemo

Demonstrates the **RFC 8628 device-code flow** on Apple TV.
Use `RakomiDeviceCodeView()` instead of `RakomiSignInForm()`:

```swift
import SwiftUI
import RakomiSDK

@main struct TVDemoApp: App {
  var body: some Scene {
    WindowGroup {
      ContentView()
        .rakomi(configuration: try! RakomiAuthConfiguration(
          publishableKey: "pk_test_acme",
          // tvOS does not use redirectURI — placeholder accepted.
          redirectURI: URL(string: "tvos://placeholder")!
        ))
    }
  }
}

struct ContentView: View {
  var body: some View {
    RakomiAuthGate(
      signedIn: { user in Text("Signed in as \(user.displayName ?? "—")") },
      signedOut: { RakomiDeviceCodeView() }
    )
  }
}
```

The view displays the user-facing code + verification URI (`https://rakomi.com/device`)
and polls the device-token endpoint until the user approves on their phone.
