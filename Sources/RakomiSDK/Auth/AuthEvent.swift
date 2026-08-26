// Fine-grained AuthEvent for analytics consumers.
//
// Source-of-truth is the `RakomiAuthController` actor; emitted via
// `RakomiAuth.shared.events` AsyncStream. Consumer-pull only — SDK MUST
// NOT auto-forward to any analytics sink.

import Foundation

/// Discrete event fired during the auth lifecycle. Purpose: feeding analytics
/// pipelines (Mixpanel, Datadog, Amplitude) without forcing them onto
/// `authStateChanges` which is the primary state surface.
public enum AuthEvent: Sendable, Equatable {
    case signedIn(User)
    case signedOut(reason: SdkErrorReason?)
    case tokenRefreshed
    case mfaChallengeRequired(challengeId: String)
    case mfaChallengeVerified
    case sessionRevoked
    case userUpdated(User)

    /// Audit-significance hint (per README "Audit logging" sub-section,
    /// Used by consumer apps that wire `events` into their
    /// audit log pipeline.
    public var auditSignificance: AuditSignificance {
        switch self {
        case .signedIn, .signedOut, .sessionRevoked, .mfaChallengeVerified:
            return .high
        case .mfaChallengeRequired, .userUpdated:
            return .medium
        case .tokenRefreshed:
            return .low
        }
    }

    public enum AuditSignificance: String, Sendable {
        case low, medium, high
    }
}

/// Severity tag for `AuthEvent` consumers that want to bucket diagnostics.
public enum AuthEventSeverity: String, Sendable {
    case info
    case warning
    case error
}
