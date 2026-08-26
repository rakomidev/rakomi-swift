// UIKit/AppKit notification bridge.

import Foundation

extension Notification.Name {
    /// Posted on auth-state transitions for UIKit/AppKit consumers.
    /// SwiftUI consumers SHOULD use `authStateChanges` AsyncStream directly.
    public static let rakomiAuthStateChanged = Notification.Name("com.rakomi.swift-sdk.authStateChanged")
}

/// Keys carried in `Notification.userInfo` by `.rakomiAuthStateChanged`.
///
/// This payload is deliberately CREDENTIAL-FREE. `NotificationCenter.default`
/// is process-global and the notification name is a public constant, so
/// anything linked into the host app — an analytics SDK, an ad network, a
/// crash reporter — receives every post. Tokens are therefore NEVER carried
/// here; obtain one only via `await auth.getToken()`, which is access-
/// controlled by holding the `RakomiAuth` instance.
public enum RakomiAuthNotificationKey {
    /// `String` — one of `loading`, `signedOut`, `authenticated`, `error`.
    public static let state = "com.rakomi.swift-sdk.state"
    /// `String` — the authenticated user's id. Present only for `authenticated`.
    public static let userId = "com.rakomi.swift-sdk.userId"
    /// `String` — the error's stable, cross-SDK wire reason (snake_case), the
    /// vocabulary the parity check covers. NOT the Swift case name.
    public static let errorReason = "com.rakomi.swift-sdk.errorReason"
}

public enum RakomiAuthUIKitObserver {
    /// Forward state transitions into NotificationCenter for UIKit/AppKit
    /// consumers. Returns a Task handle the consumer can cancel on view
    /// teardown.
    ///
    /// ⚠ The notification carries NO tokens — see `RakomiAuthNotificationKey`.
    /// `object` is `nil` by design; read `userInfo`.
    @discardableResult
    public static func attach(_ auth: RakomiAuth) -> Task<Void, Never> {
        return Task {
            for await state in auth.authStateChanges() {
                NotificationCenter.default.post(
                    name: .rakomiAuthStateChanged,
                    object: nil,
                    userInfo: userInfo(for: state)
                )
            }
        }
    }

    /// Credential-free projection of `AuthState`. Internal-but-testable: the
    /// property under test is that no token value can appear here for ANY
    /// state, and that is a property of this function alone.
    static func userInfo(for state: AuthState) -> [String: String] {
        switch state {
        case .loading:
            return [RakomiAuthNotificationKey.state: "loading"]
        case .signedOut:
            return [RakomiAuthNotificationKey.state: "signedOut"]
        case .authenticated(let user, _):
            return [
                RakomiAuthNotificationKey.state: "authenticated",
                RakomiAuthNotificationKey.userId: user.id,
            ]
        case .error(let error):
            return [
                RakomiAuthNotificationKey.state: "error",
                RakomiAuthNotificationKey.errorReason: error.reason.wire,
            ]
        }
    }
}
