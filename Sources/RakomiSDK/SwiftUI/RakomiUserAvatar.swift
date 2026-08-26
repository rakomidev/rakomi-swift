// Pre-built user avatar.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
public struct RakomiUserAvatar: View {
    @Environment(RakomiAuthEnvironment.self) private var env

    let formatExpiry: ((Date) -> String)?

    public init(formatExpiry: ((Date) -> String)? = nil) {
        self.formatExpiry = formatExpiry
    }

    public var body: some View {
        Group {
            if let user = env.user {
                AvatarView(user: user, expiryHelp: expiryHelp)
            } else {
                Image(systemName: "person.crop.circle")
                    .resizable().scaledToFit()
            }
        }
        .accessibilityIdentifier("rakomi.userAvatar")
    }

    private var expiryHelp: String? {
        guard case .authenticated(_, let session) = env.state else { return nil }
        if let format = formatExpiry { return format(session.expiresAt) }
        return session.expiresAt.formatted(date: .abbreviated, time: .shortened)
    }
}

@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
private struct AvatarView: View {
    let user: User
    let expiryHelp: String?

    var body: some View {
        Group {
            if let avatarURL = user.avatarURL {
                AsyncImage(url: avatarURL) { phase in
                    switch phase {
                    case .success(let image):
                        image.resizable().scaledToFit()
                    default:
                        Image(systemName: "person.crop.circle.fill").resizable().scaledToFit()
                    }
                }
            } else {
                Image(systemName: "person.crop.circle.fill").resizable().scaledToFit()
            }
        }
        .clipShape(Circle())
        .accessibilityLabel(user.displayName ?? user.email ?? "User avatar")
        #if os(iOS) || os(macOS) || os(visionOS)
        .help(expiryHelp ?? "")
        #endif
    }
}
#endif
