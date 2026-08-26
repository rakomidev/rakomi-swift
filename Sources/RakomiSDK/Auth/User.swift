// User + Session models.
//
// `User.claims` is an open-ended forward-compat slot carrying roles,
// metadata and `org_id`. The SDK does NOT impose
// schema on `claims`.

import Foundation

/// Type-erased JSON value for forward-compatible JWT claim storage.
/// Sendable + Hashable + Codable to round-trip arbitrary RFC 7519 claims
/// without forcing the SDK to know the tenant schema.
public enum AnyClaim: Sendable, Hashable, Codable {
    case string(String)
    case int(Int64)
    case double(Double)
    case bool(Bool)
    case array([AnyClaim])
    case object([String: AnyClaim])
    case null

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
            return
        }
        if let v = try? c.decode(Bool.self) {
            self = .bool(v)
            return
        }
        if let v = try? c.decode(Int64.self) {
            self = .int(v)
            return
        }
        if let v = try? c.decode(Double.self) {
            self = .double(v)
            return
        }
        if let v = try? c.decode(String.self) {
            self = .string(v)
            return
        }
        if let v = try? c.decode([AnyClaim].self) {
            self = .array(v)
            return
        }
        if let v = try? c.decode([String: AnyClaim].self) {
            self = .object(v)
            return
        }
        throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unsupported claim type")
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let v): try c.encode(v)
        case .int(let v): try c.encode(v)
        case .double(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }

    /// Convenience accessor: best-effort `String` view of the claim.
    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }
}

/// Authenticated user. `claims` is the raw JWT payload — forward-compatible
/// with later additions (roles, metadata, `org_id`).
public struct User: Sendable, Hashable, Codable {
    public let id: String
    public let email: String?
    public let emailVerified: Bool
    public let displayName: String?
    public let avatarURL: URL?
    /// Raw JWT payload — open-ended forward-compat slot.
    public let claims: [String: AnyClaim]

    public init(
        id: String,
        email: String? = nil,
        emailVerified: Bool = false,
        displayName: String? = nil,
        avatarURL: URL? = nil,
        claims: [String: AnyClaim] = [:]
    ) {
        self.id = id
        self.email = email
        self.emailVerified = emailVerified
        self.displayName = displayName
        self.avatarURL = avatarURL
        self.claims = claims
    }
}

/// Active authenticated session.
public struct Session: Sendable, Hashable, Codable {
    public let accessToken: String
    public let refreshToken: String?
    public let expiresAt: Date
    public let tokenType: String
    public let scope: String?
    public let tenantId: String

    public init(
        accessToken: String,
        refreshToken: String?,
        expiresAt: Date,
        tokenType: String = "Bearer",
        scope: String? = nil,
        tenantId: String
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
        self.tokenType = tokenType
        self.scope = scope
        self.tenantId = tenantId
    }

    /// True iff `now` is within `leadtime` of `expiresAt` — used by the
    /// refresh decision in `RakomiAuthController`.
    public func isStale(now: Date = Date(), leadtime: TimeInterval) -> Bool {
        return now.addingTimeInterval(leadtime) >= expiresAt
    }
}
