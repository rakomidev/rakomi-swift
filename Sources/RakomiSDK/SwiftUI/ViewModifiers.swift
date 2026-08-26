// Convenience SwiftUI sugar.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
extension View {
    /// Render `content` only when authenticated, with the current user passed in.
    public func rakomiAuthenticated<Content: View>(
        @ViewBuilder _ content: @escaping (User) -> Content
    ) -> some View {
        modifier(_RakomiAuthenticatedModifier(content: content))
    }

    /// Render `content` only when signed-out.
    public func rakomiUnauthenticated<Content: View>(
        @ViewBuilder _ content: @escaping () -> Content
    ) -> some View {
        modifier(_RakomiUnauthenticatedModifier(content: content))
    }
}

@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
private struct _RakomiAuthenticatedModifier<Inner: View>: ViewModifier {
    @Environment(RakomiAuthEnvironment.self) private var env
    let content: (User) -> Inner

    func body(content base: Content) -> some View {
        Group {
            if case .authenticated(let user, _) = env.state {
                content(user)
            } else {
                base.opacity(0).accessibilityHidden(true)
            }
        }
    }
}

@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
private struct _RakomiUnauthenticatedModifier<Inner: View>: ViewModifier {
    @Environment(RakomiAuthEnvironment.self) private var env
    let content: () -> Inner

    func body(content base: Content) -> some View {
        Group {
            if case .signedOut = env.state {
                content()
            } else {
                base.opacity(0).accessibilityHidden(true)
            }
        }
    }
}
#endif
