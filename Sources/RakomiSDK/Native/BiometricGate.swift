// Biometric gate via LAContext.
//
// Calls `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,...)`
// BEFORE retrieving tokens from Keychain. SDK does NOT use
// `kSecAttrAccessControl` with `.biometryAny` — gives more control over the
// prompt UX. Maps `LAError.Code` cases to `BiometricResult` at this boundary.
//
// NOTE: Native platform passkey (`ASAuthorizationPlatformPublicKeyCredentialProvider`)
// is not wired in this release.

import Foundation

#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

public actor BiometricGate {
    public init() {}

    public func available() -> Bool {
        #if canImport(LocalAuthentication) && (os(iOS) || os(macOS) || os(visionOS))
        let ctx = LAContext()
        var error: NSError?
        return ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        #else
        // watchOS / tvOS / Linux — biometric unavailable.
        return false
        #endif
    }

    public func request(reason: String) async -> BiometricResult {
        #if canImport(LocalAuthentication) && (os(iOS) || os(macOS) || os(visionOS))
        let ctx = LAContext()
        var canEvalErr: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canEvalErr) else {
            if let code = canEvalErr.flatMap({ LAError.Code(rawValue: $0.code) }) {
                return Self.mapLAErrorCode(code)
            }
            return .unavailable(reason: "cannot_evaluate")
        }
        return await withCheckedContinuation { (continuation: CheckedContinuation<BiometricResult, Never>) in
            ctx.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { success, evalErr in
                if success {
                    continuation.resume(returning: .success)
                } else if let code = (evalErr as? LAError)?.code {
                    continuation.resume(returning: Self.mapLAErrorCode(code))
                } else {
                    continuation.resume(returning: .unavailable(reason: "evaluate_failed"))
                }
            }
        }
        #else
        _ = reason
        return .unavailable(reason: "platform_no_biometric")
        #endif
    }

    #if canImport(LocalAuthentication)
    static func mapLAErrorCode(_ code: LAError.Code) -> BiometricResult {
        switch code {
        case .userCancel, .systemCancel, .appCancel:
            return .cancelled
        case .biometryLockout:
            return .lockout
        case .biometryNotEnrolled:
            return .notEnrolled
        case .biometryNotAvailable:
            return .unavailable(reason: "biometry_not_available")
        case .passcodeNotSet:
            return .unavailable(reason: "passcode_not_set")
        case .authenticationFailed:
            return .cancelled
        default:
            return .unavailable(reason: "la_error_\(code.rawValue)")
        }
    }
    #endif
}
