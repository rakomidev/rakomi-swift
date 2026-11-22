// RFC 8414 authorization-server metadata.
//
// The host that serves the API is not necessarily the host that renders the
// hosted login page, and a native app must send the SYSTEM BROWSER to the second
// one. Guessing `<apiBaseURL>/oauth/authorize` produces a JSON API response
// rather than a login form, so the endpoints are discovered rather than
// constructed — the same discipline the other Rakomi SDKs follow.

import Foundation

/// The endpoints the browser flow, the refresh of its session and its
/// revocation need, as the authorization server publishes them.
public struct AuthorizationServerMetadata: Sendable, Equatable, Decodable {
    public let issuer: String
    public let authorizationEndpoint: URL
    public let tokenEndpoint: URL
    /// RFC 7009 revocation endpoint (RFC 8414 `revocation_endpoint`); `nil` when
    /// the server publishes none.
    public let revocationEndpoint: URL?

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case revocationEndpoint = "revocation_endpoint"
    }
}

/// Fetches and caches the metadata document for one configuration.
///
/// The cache is per-instance and has no expiry: the endpoints of an
/// authorization server do not move within the lifetime of an app launch, and a
/// stale value would be corrected by the next launch. `invalidate()` exists for
/// a caller that knows otherwise.
actor AuthorizationServerMetadataCache {
    private let httpClient: HTTPClient
    private let apiBaseURL: URL
    private var cached: AuthorizationServerMetadata?

    init(httpClient: HTTPClient, apiBaseURL: URL) {
        self.httpClient = httpClient
        self.apiBaseURL = apiBaseURL
    }

    func metadata() async throws -> AuthorizationServerMetadata {
        if let cached { return cached }
        let fetched: AuthorizationServerMetadata
        do {
            fetched = try await httpClient.get(
                path: "/.well-known/oauth-authorization-server",
                as: AuthorizationServerMetadata.self
            )
        } catch let error as SdkError {
            throw error
        } catch {
            throw SdkError(
                code: .invalidConfig,
                reason: .notConfigured,
                errorMessage: "authorization_server_metadata_unavailable"
            )
        }
        cached = fetched
        return fetched
    }

    func invalidate() {
        cached = nil
    }

    /// Replace the cached document (tests only).
    func seed(_ metadata: AuthorizationServerMetadata) {
        cached = metadata
    }
}
