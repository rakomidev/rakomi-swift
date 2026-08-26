# Examples — iOSDemo

Single-screen iOS demo for `RakomiSDK`. Demonstrates `RakomiProvider`,
`RakomiAuthGate`, `RakomiSignInForm`, `RakomiUserAvatar` end-to-end.

> **Note**: the Xcode project files (`*.xcodeproj/`)
> are best authored in Xcode itself rather than as text — `project.pbxproj`
> is generator-tied to the Xcode version on disk. Run:
>
> ```
> # On macOS with Xcode 15.4+ installed
> cd Examples/iOSDemo
> swift package init --type executable --name iOSDemo
> # Then `open Package.swift` in Xcode and add an iOS app target.
> ```
>
> Until the Xcode project is generated, the iOS Simulator portion of the
> CI matrix runs `xcodebuild test -scheme RakomiSDK` against the SDK's
> own test target which exercises the iOS-conditional code paths via
> `#if canImport(...)` guards.

## Quickstart

```swift
import SwiftUI
import RakomiSDK

@main struct DemoApp: App {
  var body: some Scene {
    WindowGroup {
      ContentView()
        .rakomi(configuration: try! RakomiAuthConfiguration(
          publishableKey: "pk_test_acme",
          redirectURI: URL(string: "rakomidemo://callback")!
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

## Info.plist requirements

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array><string>rakomidemo</string></array>
  </dict>
</array>
```

## Sign in with Apple capability

In your Xcode target → Signing & Capabilities, enable the
`Sign in with Apple` capability. The auto-generated `iOSDemo.entitlements`
will include `com.apple.developer.applesignin = ['Default']`.

## Signing in

The demo signs in through the ordinary end-user flow. It has no privileged
bootstrap path, and it must never acquire one.
