// Pre-built social sign-in button.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
public struct RakomiSignInButton: View {
    @Environment(RakomiAuthEnvironment.self) private var env
    let provider: SocialProvider

    public init(provider: SocialProvider) {
        self.provider = provider
    }

    public var body: some View {
        Button {
            Task {
                guard let auth = env.auth else { return }
                await auth.signIn(withProvider: provider)
            }
        } label: {
            HStack {
                Image(systemName: iconName(for: provider))
                Text("Continue with \(provider.displayName)")
            }
            .frame(maxWidth: .infinity)
        }
        .accessibilityLabel("Continue with \(provider.displayName)")
        .accessibilityIdentifier("rakomi.signInButton.\(provider.wire)")
        .accessibilityAddTraits(.isButton)
    }

    private func iconName(for provider: SocialProvider) -> String {
        // SF Symbol that exists across platforms; consumer apps can override
        // via `branding:` parameter (planned).
        return "person.crop.circle"
    }
}
#endif
