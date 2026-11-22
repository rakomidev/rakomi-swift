// Refresh-failure classification and Retry-After parsing.
//
// One definition for both refresh paths (Bearer and DPoP-bound), and the same
// rules the other Rakomi SDKs apply, so every SDK agrees on which refresh
// failures end a session and which only delay it:
//
// - Definitive (the session is over; clear it, never retry): a 4xx carrying an
//   RFC 6749 §5.2 `error` of `invalid_grant`, `invalid_client`, `invalid_token`,
//   `unauthorized_client` or `access_denied`, or one of this API's own
//   session-ending codes (`invalid_refresh_token`, `session_expired`,
//   `token_reuse_detected`, `race_condition_detected`, and the 403s
//   `user_blocked` and `pending_parental_consent`), or a bare 401. A 2xx the
//   SDK cannot read is also the end of the session: the server consumed the
//   presented refresh token, and presenting it again would be a reuse, which
//   revokes every session of the user.
// - Transient (keep the session and the stored credential, retry later): a 5xx,
//   429 or 408, or a transport failure.
// - Anything else (for example a 403 with no session-ending code, which a proxy
//   in front of the API can produce) is not definitive: the session is kept and
//   the request is not retried automatically.

import Foundation

enum RefreshFailure {
    /// Upper bound on how long a server-supplied `Retry-After` may hold refresh
    /// attempts back, so a misconfigured or hostile server cannot park a session
    /// indefinitely.
    static let maxRetryAfter: TimeInterval = 120

    private static let definitiveErrors: Set<String> = [
        "invalid_grant",
        "invalid_client",
        "invalid_token",
        "unauthorized_client",
        "access_denied",
        // The API's own codes (`auth/…`, namespace dropped) for a refresh it
        // refused because the session is gone. The 401s are definitive by status
        // already; `user_blocked` and `pending_parental_consent` arrive as a
        // 403, and the server has revoked the session before answering.
        "invalid_refresh_token",
        "session_expired",
        "token_reuse_detected",
        "race_condition_detected",
        "user_blocked",
        "pending_parental_consent",
    ]

    /// `true` for a status that says "try again later": any 5xx, 429, 408.
    static func isTransientStatus(_ status: Int) -> Bool {
        status >= 500 || status == 429 || status == 408
    }

    /// `true` when a refresh rejection means the session is over.
    static func isDefinitiveRejection(status: Int, oauthError: String?) -> Bool {
        guard (400..<500).contains(status), !isTransientStatus(status) else { return false }
        if let oauthError, definitiveErrors.contains(oauthError) { return true }
        return status == 401
    }

    /// The error code a token-endpoint body names: the RFC 6749 §5.2 `error`
    /// string, else the API's problem+json `code`, else a nested `error.code`.
    /// A leading `auth/` namespace is dropped and the result lower-cased; `nil`
    /// when the body names none.
    static func oauthError(from body: Data) -> String? {
        guard let payload = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else { return nil }
        let nested = (payload["error"] as? [String: Any])?["code"] as? String
        guard let raw = (payload["error"] as? String) ?? (payload["code"] as? String) ?? nested else {
            return nil
        }
        var code = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if code.hasPrefix("auth/") { code.removeFirst("auth/".count) }
        return code.isEmpty ? nil : code
    }

    /// Parse a `Retry-After` header (RFC 9110 §10.2.3) into seconds from `now`.
    /// Both forms are accepted: delta-seconds and an HTTP-date. An absent or
    /// unparseable value yields `nil` — a backoff is never invented.
    static func parseRetryAfter(_ header: String?, now: Date) -> TimeInterval? {
        guard let value = header?.trimmingCharacters(in: .whitespaces), !value.isEmpty else { return nil }
        if value.allSatisfy({ $0.isASCII && $0.isNumber }) {
            return TimeInterval(value)
        }
        guard let date = retryAfterDateFormatter.date(from: value) else { return nil }
        return max(0, date.timeIntervalSince(now))
    }

    /// The transient error both refresh paths surface: the session is kept.
    static func transientError(
        reason: SdkErrorReason,
        message: String,
        httpStatus: Int?,
        retryAfter: TimeInterval?
    ) -> SdkError {
        SdkError(
            code: .refreshFailed,
            reason: reason,
            errorMessage: message,
            httpStatus: httpStatus,
            retryAfter: retryAfter
        )
    }

    /// `true` for a refresh failure after which the stored credential is still
    /// in place and a later attempt may succeed.
    static func keepsSession(_ err: SdkError) -> Bool {
        guard err.code == .refreshFailed else { return false }
        switch err.reason {
        case .refreshNetwork, .network: return true
        case .unknown: return err.httpStatus != nil
        default: return false
        }
    }
}

private let retryAfterDateFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "GMT")
    f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    return f
}()
