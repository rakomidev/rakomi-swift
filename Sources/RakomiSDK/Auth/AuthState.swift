// Sealed AuthState envelope.
//
// Mirrors RN/Flutter `AuthState` step-for-step:
// `loading` → `signedOut` → `authenticated(User, Session)` → `error(SdkError)`.

import Foundation

/// Top-level authentication state surface. Emitted via the
/// `RakomiAuth.shared.authStateChanges` AsyncStream. Never thrown.
public enum AuthState: Sendable, Equatable {
    case loading
    case signedOut
    case authenticated(User, Session)
    case error(SdkError)

    public static func == (lhs: AuthState, rhs: AuthState) -> Bool {
        switch (lhs, rhs) {
        case (.loading, .loading), (.signedOut, .signedOut):
            return true
        case (.authenticated(let lu, let ls), .authenticated(let ru, let rs)):
            return lu == ru && ls == rs
        case (.error(let le), .error(let re)):
            return le == re
        default:
            return false
        }
    }

    public var isAuthenticated: Bool {
        if case .authenticated = self { return true }
        return false
    }

    public var user: User? {
        if case .authenticated(let u, _) = self { return u }
        return nil
    }

    public var session: Session? {
        if case .authenticated(_, let s) = self { return s }
        return nil
    }
}
