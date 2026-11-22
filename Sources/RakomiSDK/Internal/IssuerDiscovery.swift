// Issuer → jwks_uri resolution.
//
// Each issuer publishes its own signing keys at the `jwks_uri` its discovery
// document names, so keys are resolved from the issuer the client expects —
// never from a fixed JWKS path. A key of a different issuer is then never in
// the set a token is checked against.

import Foundation

enum IssuerDiscovery {
    /// Discovery document URLs to try for `issuer`, in order: OAuth 2.0
    /// Authorization Server Metadata (RFC 8414 §3.1, well-known segment
    /// inserted before the issuer path), then OpenID Connect Discovery 1.0 §4
    /// (well-known segment appended to the issuer). `discoveryOrigin` fetches
    /// the same paths from another origin; the document's `issuer` must still
    /// equal `issuer`.
    static func discoveryURLs(issuer: URL, discoveryOrigin: URL?) -> [URL] {
        let source = discoveryOrigin ?? issuer
        guard let scheme = source.scheme, let host = source.host else { return [] }
        var origin = "\(scheme)://\(host)"
        if let port = source.port { origin += ":\(port)" }
        var path = issuer.path
        if path.hasSuffix("/") { path.removeLast() }
        return [
            URL(string: "\(origin)/.well-known/oauth-authorization-server\(path)"),
            URL(string: "\(origin)\(path)/.well-known/openid-configuration"),
        ].compactMap { $0 }
    }

    /// Read `jwks_uri` from a discovery document fetched for `issuer`. Its
    /// `issuer` must equal the expected one exactly (one trailing slash is the
    /// only leniency); `jwks_uri` must be https (plain http only on localhost).
    static func extractJWKSURI(document: Data, issuer: URL) throws -> URL {
        let object = try? JSONSerialization.jsonObject(with: document) as? [String: Any]
        let expected = issuer.absoluteString.trimmingCharacters(in: ["/"])
        guard let docIssuer = object?["issuer"] as? String,
            docIssuer.trimmingCharacters(in: ["/"]) == expected
        else {
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "jwks_discovery_issuer_mismatch"
            )
        }
        guard let raw = object?["jwks_uri"] as? String, let jwksURI = URL(string: raw),
            let host = jwksURI.host,
            jwksURI.scheme == "https"
                || (jwksURI.scheme == "http" && (host == "localhost" || host == "127.0.0.1"))
        else {
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "jwks_discovery_jwks_uri_invalid"
            )
        }
        return jwksURI
    }

    /// Resolve the `jwks_uri` of `issuer`, trying each discovery form in turn.
    /// A missing document (HTTP 404) moves on to the next form; a document
    /// naming another issuer stops immediately.
    static func resolveJWKSURI(issuer: URL, discoveryOrigin: URL?, session: URLSession) async throws -> URL {
        var lastError: Error?
        for url in discoveryURLs(issuer: issuer, discoveryOrigin: discoveryOrigin) {
            var request = URLRequest(url: url)
            request.timeoutInterval = 10
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue(rakomiUserAgent, forHTTPHeaderField: "User-Agent")
            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await session.data(for: request)
            } catch {
                lastError = error
                continue
            }
            guard let http = response as? HTTPURLResponse else { continue }
            if http.statusCode == 404 { continue }
            guard (200..<300).contains(http.statusCode) else {
                lastError = SdkError(
                    code: .networkError,
                    reason: .network,
                    errorMessage: "jwks_discovery_http_\(http.statusCode)"
                )
                continue
            }
            return try extractJWKSURI(document: data, issuer: issuer)
        }
        if let sdkError = lastError as? SdkError { throw sdkError }
        throw SdkError(
            code: .networkError,
            reason: .network,
            errorMessage: "jwks_discovery_unavailable"
        )
    }

    /// Where to fetch `issuer`'s discovery document from. A platform-family
    /// issuer is served by whichever deployment the client is configured for
    /// (`apiBaseURL`), because every platform deployment mints the same
    /// platform-family issuer; any other issuer is its own origin (`nil`).
    static func discoveryOrigin(for issuer: URL, apiBaseURL: URL) -> URL? {
        guard let host = issuer.host else { return nil }
        return RakomiAuthConfiguration.isPlatformHost(host) ? apiBaseURL : nil
    }
}
