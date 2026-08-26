// Error taxonomy.
//
// Mirrors `@rakomi/react-native`'s `AuthError` and `rakomi_flutter`'s
// `SdkErrorCode` + `SdkErrorReason` 1:1 — wire-level enum raw values are
// asserted by a parity test and the `error_reason_parity` CI step.
//
// Errors NEVER throw across the public async API surface — they are emitted
// via `authStateChanges` as `AuthState.error(SdkError(...))`. Programmer
// errors (assertion violations on construction, e.g. invalid redirect URI
// scheme) DO throw synchronously via the `RakomiAuthConfiguration` initializer.

import Foundation

/// Top-level SDK error code. 1:1 parity with RN's `AuthError.code`
/// literal-union and Flutter's `SdkErrorCode` enum.
public enum SdkErrorCode: String, Sendable, CaseIterable {
    case refreshFailed
    case oauthCallbackError
    case tenantSuspended
    case csrfMismatch
    case codeExchangeFailed
    case signInFailed
    case invalidConfig
    case networkError
    case providerError
    case biometricError
    case storageError
    case rateLimited
    case invalidCredentials
    case mfaStepUpRequired
    case mfaStepUpUnavailable
    case unknown

    /// Wire-level uppercase form (used in JSON serialization, logging,
    /// parity fixtures). Mirrors Flutter `SdkErrorCodeWire.wire`.
    public var wire: String {
        switch self {
        case .refreshFailed: return "REFRESH_FAILED"
        case .oauthCallbackError: return "OAUTH_CALLBACK_ERROR"
        case .tenantSuspended: return "TENANT_SUSPENDED"
        case .csrfMismatch: return "CSRF_MISMATCH"
        case .codeExchangeFailed: return "CODE_EXCHANGE_FAILED"
        case .signInFailed: return "SIGN_IN_FAILED"
        case .invalidConfig: return "INVALID_CONFIG"
        case .networkError: return "NETWORK_ERROR"
        case .providerError: return "PROVIDER_ERROR"
        case .biometricError: return "BIOMETRIC_ERROR"
        case .storageError: return "STORAGE_ERROR"
        case .rateLimited: return "RATE_LIMITED"
        case .invalidCredentials: return "INVALID_CREDENTIALS"
        case .mfaStepUpRequired: return "MFA_STEP_UP_REQUIRED"
        case .mfaStepUpUnavailable: return "MFA_STEP_UP_UNAVAILABLE"
        case .unknown: return "UNKNOWN"
        }
    }
}

/// Discriminating sub-reason. Combined with [SdkErrorCode] gives the full
/// error taxonomy. Wire values match RN + Flutter byte-for-byte (parity-asserted).
public enum SdkErrorReason: String, Sendable, CaseIterable {
    // OAuth flow reasons (RN + Flutter parity)
    case oauthUserCancelled
    case oauthLocked
    case oauthStateMismatch
    case oauthRedirectMismatch
    case oauthMissingParams
    case oauthProviderError
    // Biometric gate reasons
    case biometricCancelled
    case biometricLockout
    case biometricNotEnrolled
    case biometricUnavailable
    // Session lifecycle
    case sessionExpired
    case sessionRevoked
    // Refresh failure detail
    case refreshExpired
    case refreshRevoked
    case refreshNetwork
    // MFA step-up partition
    case mfaStepUpRequired
    case mfaStepUpUnavailable
    // Validation / format
    case invalidCredentials
    case rateLimited
    // tvOS device-code flow (RFC 8628) — additive over RN/Flutter; Swift-side
    // additions are forward-compatible, parity test soft-warns on RN/Flutter
    // missing reasons.
    case deviceCodeAuthorizationPending
    case deviceCodeSlowDown
    case deviceCodeAccessDenied
    case deviceCodeExpired
    // RFC 9449 DPoP-on-refresh three-class taxonomy.
    // Mirrors RN's
    // `DpopRefreshErrorClass` ('dpop_prover_unavailable' / 'invalid_dpop_proof' /
    // 'invalid_refresh_token'). These are DISTINCT classes so a spike of
    // `invalid_dpop_proof` vs `invalid_refresh_token` is the operator's
    // signal for a staged server-side rollout.
    case dpopProverUnavailable
    case invalidDpopProof
    case invalidRefreshToken
    // Generic
    case network
    case unknown

    /// Wire-level snake_case form (used in JSON, logging, parity fixtures).
    public var wire: String {
        switch self {
        case .oauthUserCancelled: return "oauth_user_cancelled"
        case .oauthLocked: return "oauth_locked"
        case .oauthStateMismatch: return "oauth_state_mismatch"
        case .oauthRedirectMismatch: return "oauth_redirect_mismatch"
        case .oauthMissingParams: return "oauth_missing_params"
        case .oauthProviderError: return "oauth_provider_error"
        case .biometricCancelled: return "biometric_cancelled"
        case .biometricLockout: return "biometric_lockout"
        case .biometricNotEnrolled: return "biometric_not_enrolled"
        case .biometricUnavailable: return "biometric_unavailable"
        case .sessionExpired: return "session_expired"
        case .sessionRevoked: return "session_revoked"
        case .refreshExpired: return "refresh_expired"
        case .refreshRevoked: return "refresh_revoked"
        case .refreshNetwork: return "refresh_network"
        case .mfaStepUpRequired: return "mfa_step_up_required"
        case .mfaStepUpUnavailable: return "mfa_step_up_unavailable"
        case .invalidCredentials: return "invalid_credentials"
        case .rateLimited: return "rate_limited"
        case .deviceCodeAuthorizationPending: return "device_code_authorization_pending"
        case .deviceCodeSlowDown: return "device_code_slow_down"
        case .deviceCodeAccessDenied: return "device_code_access_denied"
        case .deviceCodeExpired: return "device_code_expired"
        case .dpopProverUnavailable: return "dpop_prover_unavailable"
        case .invalidDpopProof: return "invalid_dpop_proof"
        case .invalidRefreshToken: return "invalid_refresh_token"
        case .network: return "network"
        case .unknown: return "unknown"
        }
    }
}

/// Sealed SDK error envelope. Always emitted via `authStateChanges` —
/// never thrown across the public async API. Conforms to `LocalizedError` so
/// `Error.localizedDescription` resolves to a redacted i18n-aware message.
public struct SdkError: Error, Sendable, LocalizedError, Equatable {
    public let code: SdkErrorCode
    public let reason: SdkErrorReason
    public let errorMessage: String?
    public let providerError: String?

    public init(
        code: SdkErrorCode = .unknown,
        reason: SdkErrorReason,
        errorMessage: String? = nil,
        providerError: String? = nil
    ) {
        self.code = code
        self.reason = reason
        self.errorMessage = errorMessage
        self.providerError = providerError
    }

    // MARK: - Redaction

    /// JWT compact-form regex. Non-anchored to catch embedded tokens in
    /// wrapped messages: a token embedded mid-message must still be redacted.
    private static let jwtShape = try! NSRegularExpression(
        pattern: #"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"#
    )
    private static let bearerShape = try! NSRegularExpression(
        pattern: #"Bearer\s+[A-Za-z0-9_\-\.]+"#,
        options: [.caseInsensitive]
    )

    /// Apply both regex passes to redact JWTs/Bearer tokens to `[redacted]`.
    private static func redact(_ input: String) -> String {
        let range = NSRange(location: 0, length: input.utf16.count)
        let stage1 = jwtShape.stringByReplacingMatches(
            in: input,
            options: [],
            range: range,
            withTemplate: "[redacted]"
        )
        let stage1Range = NSRange(location: 0, length: stage1.utf16.count)
        return bearerShape.stringByReplacingMatches(
            in: stage1,
            options: [],
            range: stage1Range,
            withTemplate: "[redacted]"
        )
    }

    /// Public for `LocalizedError.errorDescription`. Redacts JWTs/Bearer
    /// tokens to literal `[redacted]` before any caller-visible string.
    public var redactedMessage: String {
        guard let m = errorMessage else { return "" }
        return Self.redact(m)
    }

    public var errorDescription: String? {
        let parts: [String] = [
            "code=\(code.wire)",
            "reason=\(reason.wire)",
            errorMessage != nil ? "message=\(redactedMessage)" : nil,
            providerError.map { "provider=\(Self.redact($0))" },
        ].compactMap { $0 }
        return "SdkError(\(parts.joined(separator: ", ")))"
    }
}
