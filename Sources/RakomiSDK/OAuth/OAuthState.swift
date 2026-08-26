// Single-use OAuth state lifecycle.
//
// `state` is 32 random bytes (CSPRNG), base64url-encoded, persisted to
// Keychain under `rakomi.v1.oauth.state.<oneTimeId>`, validated on
// callback (constant-time compare), deleted post-validation regardless
// of outcome (single-use enforcement).

import Foundation

/// Authority over OAuth `state` + `verifier` pairs. Owned by `RakomiAuth`.
public actor OAuthStateStore {
    let storage: KeychainStorage
    let now: () -> Date

    public init(storage: KeychainStorage, now: @escaping () -> Date = Date.init) {
        self.storage = storage
        self.now = now
    }

    /// Mint a fresh `state` + PKCE pair, persist them, return the bundle.
    public func mint() async throws -> OAuthFlowState {
        let stateBytes = try secureRandomBytes(count: oauthStateBytes)
        let state = base64URLEncode(stateBytes)
        let oneTimeIdBytes = try secureRandomBytes(count: 16)
        let oneTimeId = base64URLEncode(oneTimeIdBytes)
        let pkce = try PKCE.generate()
        let createdAt = now()

        let bundle = StoredFlow(
            state: state,
            verifier: pkce.verifier,
            challenge: pkce.challenge,
            createdAt: createdAt
        )
        let encoded = try JSONEncoder().encode(bundle)
        guard let json = String(data: encoded, encoding: .utf8) else {
            throw SdkError(
                code: .storageError,
                reason: .unknown,
                errorMessage: "oauth_state_encode_failed"
            )
        }
        let res = await storage.write(key: StorageKeys.oauthState(oneTimeId: oneTimeId), value: json)
        if case .failed(let err) = res { throw err }

        return OAuthFlowState(
            oneTimeId: oneTimeId,
            state: state,
            verifier: pkce.verifier,
            challenge: pkce.challenge
        )
    }

    /// Consume a stored flow by `oneTimeId`. Returns nil on miss; deletes
    /// the entry regardless of outcome (single-use), AWAITED before this
    /// function returns — never fire-and-forget. `defer` cannot itself
    /// `await` in Swift, so the delete is awaited explicitly before
    /// returning, closing the single-use guarantee against a second
    /// concurrent `consume(oneTimeId:)` call with the same id (a
    /// duplicate/replayed deep-link delivery). Mirrors the Flutter twin
    /// (`validateAndConsume`), which awaits both deletes synchronously
    /// before returning.
    public func consume(oneTimeId: String) async -> StoredFlow? {
        let key = StorageKeys.oauthState(oneTimeId: oneTimeId)
        let stored = await storage.read(key: key)
        await storage.delete(key: key)
        guard let json = stored,
            let data = json.data(using: .utf8),
            let bundle = try? JSONDecoder().decode(StoredFlow.self, from: data)
        else { return nil }
        return bundle
    }

    /// Validate `incomingState` against `stored.state` constant-time.
    public func validate(incomingState: String, stored: StoredFlow) -> Bool {
        return constantTimeEquals(incomingState, stored.state)
    }
}

public struct OAuthFlowState: Sendable, Equatable {
    public let oneTimeId: String
    public let state: String
    public let verifier: String
    public let challenge: String
}

public struct StoredFlow: Sendable, Equatable, Codable {
    public let state: String
    public let verifier: String
    public let challenge: String
    public let createdAt: Date
}
