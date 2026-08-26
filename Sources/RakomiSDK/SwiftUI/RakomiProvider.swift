// RakomiProvider ViewModifier.
//
// Used as `.rakomi(configuration:...)` modifier on the app's root view.
// First frame MUST emit `AuthState.loading` synchronously; Keychain
// hydration runs via `.task {... }`.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
public struct RakomiProvider: ViewModifier {
    let configuration: RakomiAuthConfiguration
    @State private var environment = RakomiAuthEnvironment()

    public init(configuration: RakomiAuthConfiguration) {
        self.configuration = configuration
    }

    public func body(content: Content) -> some View {
        content
            .environment(environment)
            .task {
                let auth = RakomiAuth(configuration: configuration)
                RakomiAuth._setDefault(auth)
                environment.auth = auth
                await auth.hydrate()
                let stream = auth.authStateChanges()
                for await state in stream {
                    environment.state = state
                    environment.user = state.user
                }
            }
            #if canImport(SwiftUI)
        .onOpenURL { url in
            Task {
                if let auth = environment.auth {
                    await auth.handleCallbackURL(url)
                }
            }
        }
            #endif
    }
}

@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
extension View {
    /// Install the Rakomi auth environment + deep-link listener.
    public func rakomi(configuration: RakomiAuthConfiguration) -> some View {
        modifier(RakomiProvider(configuration: configuration))
    }
}
#endif
