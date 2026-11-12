// Per-host JWKS cache scoping — regression coverage for the same fix
// `flutter-swift-sdks-need-the-same-multi-issuer-offline-verification-fix` applied to
// `rakomi_flutter`'s `JwksCache` and `@rakomi/react-native`'s `TokenRuntime.resolveJwksKey`
// (`packages/react-native/src/internal/token-runtime.ts`): the persisted JWKS storage slot is
// scoped per-host, in addition to per-tenant, so a tenant's issuer-host change across app upgrades
// never silently reuses a stale cross-host JWKS document as "fresh".

import XCTest

@testable import RakomiSDK

final class JWKSCachePerHostTests: XCTestCase {

    override func setUp() {
        super.setUp()
        StubURLProtocol.responses = [:]
        StubURLProtocol.requestCounts = [:]
    }

    private func stubSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: config)
    }

    private func jwksBody(kid: String) -> Data {
        Data(
            #"{"keys":[{"kty":"RSA","kid":"\#(kid)","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}]}"#
                .utf8
        )
    }

    /// Two `JWKSCache` instances for the SAME `tenantId` but DIFFERENT `url` hosts must never read
    /// back each other's persisted document — each fetches, and caches, independently.
    func testTwoHostsSameTenantDoNotShareAPersistedSlot() async throws {
        let storage = KeychainStorage(service: "com.rakomi.swift-sdk.tests.\(UUID())")
        StubURLProtocol.responses["tenant-a.example.com"] = (jwksBody(kid: "kid-a"), 200, [:])
        StubURLProtocol.responses["tenant-b.example.com"] = (jwksBody(kid: "kid-b"), 200, [:])

        let cacheA = JWKSCache(
            storage: storage,
            tenantId: "acme",
            source: .url(URL(string: "https://tenant-a.example.com/.well-known/jwks.json")!),
            session: stubSession()
        )
        let jwksA = try await cacheA.fetch()
        XCTAssertEqual(jwksA.keys.map(\.kid), ["kid-a"])
        XCTAssertEqual(StubURLProtocol.requestCounts["tenant-a.example.com"], 1)

        // A SECOND cache, same tenantId, different url HOST — must fetch its own document over the
        // network rather than reading tenant-a's persisted Keychain slot.
        let cacheB = JWKSCache(
            storage: storage,
            tenantId: "acme",
            source: .url(URL(string: "https://tenant-b.example.com/.well-known/jwks.json")!),
            session: stubSession()
        )
        let jwksB = try await cacheB.fetch()
        XCTAssertEqual(jwksB.keys.map(\.kid), ["kid-b"])
        XCTAssertEqual(StubURLProtocol.requestCounts["tenant-b.example.com"], 1)
    }

    /// Regression guard for the bare (no `.h.<host>`) storage slot a pre-fix persisted cache would
    /// have left behind. Pre-seed it with a document carrying a DIFFERENT `kid` than the live
    /// fixture — if per-host scoping ever regressed to reading this bare slot as "fresh", `fetch()`
    /// below would return the STALE kid instead of triggering the real network fetch.
    func testDoesNotTreatAPreMigrationBareTenantOnlySlotAsFresh() async throws {
        let storage = KeychainStorage(service: "com.rakomi.swift-sdk.tests.\(UUID())")
        let staleJSON = String(data: jwksBody(kid: "stale-bare-slot-kid"), encoding: .utf8)!
        _ = await storage.write(key: StorageKeys.jwks(tenantId: "acme"), value: staleJSON)

        StubURLProtocol.responses["tenant-a.example.com"] = (jwksBody(kid: "kid-fresh"), 200, [:])

        let cache = JWKSCache(
            storage: storage,
            tenantId: "acme",
            source: .url(URL(string: "https://tenant-a.example.com/.well-known/jwks.json")!),
            session: stubSession()
        )
        let jwks = try await cache.fetch()

        // The FRESH, network-fetched kid — never the stale bare-slot one — and the network fetch
        // DID fire, proving the bare slot was never consulted as "fresh".
        XCTAssertEqual(jwks.keys.map(\.kid), ["kid-fresh"])
        XCTAssertEqual(StubURLProtocol.requestCounts["tenant-a.example.com"], 1)
    }
}

/// Minimal `URLProtocol` stub — routes a request by its URL HOST to a canned response, so
/// `JWKSCache.fetch()` can be exercised end to end (real `URLSession`, real per-host storage-key
/// derivation) without a live network call. Registered per-session via
/// `URLSessionConfiguration.protocolClasses`, never process-wide.
final class StubURLProtocol: URLProtocol {
    nonisolated(unsafe) static var responses: [String: (Data, Int, [String: String])] = [:]
    nonisolated(unsafe) static var requestCounts: [String: Int] = [:]

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let host = url.host else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        StubURLProtocol.requestCounts[host, default: 0] += 1
        guard let (data, status, headers) = StubURLProtocol.responses[host] else {
            client?.urlProtocol(self, didFailWithError: URLError(.fileDoesNotExist))
            return
        }
        guard
            let response = HTTPURLResponse(
                url: url,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: headers
            )
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
