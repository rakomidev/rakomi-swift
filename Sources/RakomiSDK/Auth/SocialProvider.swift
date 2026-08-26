// Social provider registry.
//
// Implemented as `enum` with `String` raw values. Intentionally NOT `@frozen`
// — additive future values (e.g. EUDI Wallet post-2026 mandate) must not
// break consumer-side `switch` exhaustiveness in 0.x.

import Foundation

/// Identity providers Rakomi supports for OAuth federation. Wire values
/// MUST match the server-side `provider` query parameter on
/// `/v1/auth/oauth/callback?provider={...}`.
public enum SocialProvider: String, Sendable, CaseIterable, Codable {
    case google
    case github
    case microsoft
    case apple
    case discord
    case facebook
    case slack
    case twitter
    case gitlab
    case linkedin

    /// Wire-level value sent on the OAuth start / callback URL.
    public var wire: String { rawValue }

    /// Human-friendly display name for prebuilt sign-in buttons.
    public var displayName: String {
        switch self {
        case .google: return "Google"
        case .github: return "GitHub"
        case .microsoft: return "Microsoft"
        case .apple: return "Apple"
        case .discord: return "Discord"
        case .facebook: return "Facebook"
        case .slack: return "Slack"
        case .twitter: return "X (Twitter)"
        case .gitlab: return "GitLab"
        case .linkedin: return "LinkedIn"
        }
    }
}

/// Forward-compat factory hook for additive providers (e.g. EUDI Wallet
/// post-2026 mandate). Returns nil today; consumer cannot construct a
/// non-listed provider in 0.x. In a future minor release this becomes the
/// extension point — `RakomiAuth.shared.signIn(withCustomProvider:...)`
/// will accept `SocialProviderExtension` values.
public struct SocialProviderExtension: Sendable, Hashable {
    public let wire: String
    public let displayName: String

    public init(wire: String, displayName: String) {
        self.wire = wire
        self.displayName = displayName
    }

    /// EUDI Wallet placeholder — not wired yet.
    public static let eudiWallet = SocialProviderExtension(
        wire: "eudi_wallet",
        displayName: "EUDI Wallet"
    )
}
