// JWKS cache.
//
// Fetch + cache JWKS in Keychain. ETag-aware. 24h TTL. Public `invalidate()`
// for future SSE/CAEP push-based invalidation. `kid`-miss-driven refresh:
// on signature failure with cached JWKS, ONE retry that fetches fresh JWKS
// (bypassing TTL); if signature still fails, surface
// `SdkError(reason:.invalidCredentials, errorMessage: "jwks_kid_miss")`.

import Foundation

#if canImport(Security)
import Security
#endif
#if canImport(Crypto)
import Crypto
#endif

/// The JWS algorithms a Rakomi-issued token may be signed with. `none`, every
/// HMAC variant and anything unlisted are rejected before a key is chosen.
let allowedSigningAlgorithms: Set<String> = ["RS256", "PS256", "ES256"]

/// JSON Web Key (RFC 7517 §4) — an RSA (`n`/`e`) or EC P-256 (`crv`/`x`/`y`)
/// public key.
struct JWK: Sendable, Codable, Equatable {
    let kty: String
    let kid: String?
    let use: String?
    let alg: String?
    let n: String?  // RSA modulus, base64url
    let e: String?  // RSA exponent, base64url
    let crv: String?  // EC curve
    let x: String?  // EC x coordinate, base64url
    let y: String?  // EC y coordinate, base64url

    init(
        kty: String,
        kid: String?,
        use: String?,
        alg: String?,
        n: String? = nil,
        e: String? = nil,
        crv: String? = nil,
        x: String? = nil,
        y: String? = nil
    ) {
        self.kty = kty
        self.kid = kid
        self.use = use
        self.alg = alg
        self.n = n
        self.e = e
        self.crv = crv
        self.x = x
        self.y = y
    }

    /// `true` when this key may verify a Rakomi token signature: it has a
    /// `kid`, names an allowed `alg` itself, `use` is absent or `sig`, and its
    /// type matches the algorithm (RSA for RS256/PS256, EC P-256 for ES256).
    /// The algorithm is bound to the key: a token must name this same `alg`.
    var isAcceptableSigningKey: Bool {
        guard let kid, !kid.isEmpty else { return false }
        if let use, use != "sig" { return false }
        guard let alg, allowedSigningAlgorithms.contains(alg) else { return false }
        if alg == "ES256" { return kty == "EC" && crv == "P-256" && x != nil && y != nil }
        return kty == "RSA" && n != nil && e != nil
    }

    /// Build a `SecKey` (Apple platforms) from RSA modulus + exponent.
    /// Constructs DER ASN.1 PKCS#1 RSAPublicKey then `SecKeyCreateWithData`.
    #if canImport(Security)
    func toSecKey() throws -> SecKey? {
        guard kty == "RSA",
            let n, let e,
            let nData = base64URLDecode(n),
            let eData = base64URLDecode(e)
        else { return nil }

        let der = Self.encodeRSAPublicKeyPKCS1(modulus: nData, exponent: eData)
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: nData.count * 8,
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &error)
    }
    #endif

    /// The uncompressed SEC1 point (`0x04 || x || y`) of an EC P-256 key.
    func p256X963Representation() -> Data? {
        guard kty == "EC", crv == "P-256", let x, let y,
            let xData = base64URLDecode(x), let yData = base64URLDecode(y),
            xData.count == 32, yData.count == 32
        else { return nil }
        return Data([0x04]) + xData + yData
    }

    #if canImport(Crypto) && !canImport(Security)
    func toCryptoPublicKey() throws -> _RSA.Signing.PublicKey {
        guard kty == "RSA",
            let n, let e,
            let nData = base64URLDecode(n),
            let eData = base64URLDecode(e)
        else {
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwk_build_failed"
            )
        }
        let der = JWK.encodeRSAPublicKeyPKCS1(modulus: nData, exponent: eData)
        return try _RSA.Signing.PublicKey(derRepresentation: der)
    }
    #endif

    /// Encode RSA public key as PKCS#1 DER (`SEQUENCE { INTEGER n, INTEGER e }`).
    /// Big-endian unsigned integers; prepend 0x00 if high bit is set.
    static func encodeRSAPublicKeyPKCS1(modulus: Data, exponent: Data) -> Data {
        let modulusInt = encodeASN1Integer(modulus)
        let exponentInt = encodeASN1Integer(exponent)
        let inner = modulusInt + exponentInt
        return encodeASN1Sequence(inner)
    }

    static func encodeASN1Integer(_ data: Data) -> Data {
        var bytes = Data(data)
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        }
        return Data([0x02]) + encodeLength(bytes.count) + bytes
    }

    static func encodeASN1Sequence(_ data: Data) -> Data {
        return Data([0x30]) + encodeLength(data.count) + data
    }

    static func encodeLength(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }
        var n = length
        var bytes: [UInt8] = []
        while n > 0 {
            bytes.insert(UInt8(n & 0xff), at: 0)
            n >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
    }
}

/// One entry of a JWK Set, decoded so that an entry this SDK cannot use does
/// not take the rest of the set down with it.
private struct LenientJWK: Decodable {
    let jwk: JWK?

    init(from decoder: Decoder) throws {
        jwk = try? JWK(from: decoder)
    }
}

struct JWKSet: Sendable, Codable, Equatable {
    let keys: [JWK]

    // Internal — not part of the public API surface. Uses the
    // compiler-synthesized memberwise `init(keys:)`; an explicit init would
    // be byte-identical and is flagged as redundant by
    // `swift format lint --strict` (`UseSynthesizedInitializer`).

    /// RFC 7517 §5: a consumer ignores the members of a JWK Set whose `kty` it
    /// does not understand. This SDK verifies RS256 and models RSA keys only,
    /// and a real key set mixes them with EC keys used for other purposes —
    /// credential issuance, status lists — which carry `crv`/`x`/`y` and no
    /// `n`/`e`. Requiring every entry to be an RSA key made ONE such neighbour
    /// enough to fail the whole set, and with it every signature verification
    /// and therefore every sign-in.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let entries = try container.decode([LenientJWK].self, forKey: .keys)
        keys = entries.compactMap(\.jwk)
    }

    init(keys: [JWK]) {
        self.keys = keys
    }

    /// Find the JWK whose `kid` matches. If `kid == nil` AND there's exactly
    /// one key, return it. Otherwise throw `kid_miss`.
    /// The signing key named `kid`. Only keys allowed to verify a signature
    /// (`JWK.isAcceptableSigningKey`) are ever returned.
    func findKey(kid: String?) throws -> JWK {
        let keys = self.keys.filter(\.isAcceptableSigningKey)
        if let kid {
            if let match = keys.first(where: { $0.kid == kid }) { return match }
            throw SdkError(
                code: .codeExchangeFailed,
                reason: .invalidCredentials,
                errorMessage: "jwks_kid_miss"
            )
        }
        if keys.count == 1, let only = keys.first { return only }
        throw SdkError(
            code: .codeExchangeFailed,
            reason: .invalidCredentials,
            errorMessage: "jwks_kid_required"
        )
    }
}

/// Where a `JWKSCache` reads keys from: an explicit JWKS document URL (a
/// proxy or mirror), or an issuer whose discovery document names its
/// `jwks_uri`, fetched from `discoveryOrigin` when given.
enum JWKSSource: Sendable, Equatable {
    case url(URL)
    case issuer(URL, discoveryOrigin: URL?)
}

actor JWKSCache {
    let storage: KeychainStorage
    let tenantId: String
    let source: JWKSSource
    let session: URLSession
    let now: () -> Date

    private var inMemory: (jwks: JWKSet, fetchedAt: Date, etag: String?)?

    /// The persisted storage slot is scoped to the key source (in addition to
    /// the tenant) — see `StorageKeys.jwks(tenantId:host:)`'s doc comment: the
    /// explicit URL's host, or the discovery origin's host plus the expected
    /// issuer, so keys persisted for another issuer are never reused. `nil`
    /// only for an empty host; the bare tenant-only slot is then used as a
    /// defensive fallback rather than throwing.
    private var host: String? {
        switch source {
        case .url(let url):
            guard let h = url.host, !h.isEmpty else { return nil }
            return h
        case .issuer(let issuer, let discoveryOrigin):
            guard let h = (discoveryOrigin ?? issuer).host, !h.isEmpty else { return nil }
            let encoded = issuer.absoluteString.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
            return "\(h).i.\(encoded)"
        }
    }

    /// The JWKS document URL: the explicit override, or the expected issuer's
    /// discovered `jwks_uri`.
    private func currentJWKSURL() async throws -> URL {
        switch source {
        case .url(let url):
            return url
        case .issuer(let issuer, let discoveryOrigin):
            return try await IssuerDiscovery.resolveJWKSURI(
                issuer: issuer,
                discoveryOrigin: discoveryOrigin,
                session: session
            )
        }
    }

    init(
        storage: KeychainStorage,
        tenantId: String,
        source: JWKSSource,
        // NO DEFAULT, deliberately. `URLSession.shared` carries no delegate and
        // therefore cannot be pinned, so a default here would silently opt a
        // caller out of pinning while the integrator believes it is on. Making
        // the parameter required is what turns "every session comes from
        // `makeRakomiURLSession`" from a comment into a property.
        session: URLSession,
        now: @escaping () -> Date = Date.init
    ) {
        self.storage = storage
        self.tenantId = tenantId
        self.source = source
        self.session = session
        self.now = now
    }

    /// Fetch JWKS, honouring TTL and ETag. Pass `force: true` to bypass TTL
    /// (used by `kid`-miss-driven refresh).
    func fetch(force: Bool = false) async throws -> JWKSet {
        if !force, let cached = inMemory, now().timeIntervalSince(cached.fetchedAt) < jwksCacheTTL {
            return cached.jwks
        }
        if !force, let restored = await restoreFromKeychain() {
            inMemory = restored
            if now().timeIntervalSince(restored.fetchedAt) < jwksCacheTTL {
                return restored.jwks
            }
        }

        var request = URLRequest(url: try await currentJWKSURL())
        request.timeoutInterval = 10
        request.setValue(rakomiUserAgent, forHTTPHeaderField: "User-Agent")
        if let etag = inMemory?.etag {
            request.setValue(etag, forHTTPHeaderField: "If-None-Match")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let urlError as URLError {
            // Same reason as the sibling wrap in HTTPClient: an unwrapped
            // URLError escapes every `catch let ... as SdkError` on the way out
            // and is reported to the app as an unexplained failure.
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "jwks_url_error_\(urlError.code.rawValue)"
            )
        }
        guard let http = response as? HTTPURLResponse else {
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "jwks_response_not_http"
            )
        }

        if http.statusCode == 304, let cached = inMemory {
            inMemory = (cached.jwks, now(), cached.etag)
            await persistToKeychain()
            return cached.jwks
        }

        guard (200..<300).contains(http.statusCode) else {
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "jwks_http_\(http.statusCode)"
            )
        }

        guard data.count <= maxJWKSResponseBytes else {
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "jwks_oversize"
            )
        }

        let parsed: JWKSet
        do {
            parsed = try JSONDecoder().decode(JWKSet.self, from: data)
        } catch {
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "jwks_malformed"
            )
        }
        let etag = http.value(forHTTPHeaderField: "ETag")
        inMemory = (parsed, now(), etag)
        await persistToKeychain()
        return parsed
    }

    /// Wipe in-memory + Keychain copy. Public seam for SSE/CAEP push.
    func invalidate() async {
        inMemory = nil
        await storage.delete(key: StorageKeys.jwks(tenantId: tenantId, host: host))
        await storage.delete(key: StorageKeys.jwksETag(tenantId: tenantId, host: host))
    }

    // MARK: - Persistence

    private func persistToKeychain() async {
        guard let cached = inMemory else { return }
        if let json = try? JSONEncoder().encode(cached.jwks),
            let str = String(data: json, encoding: .utf8)
        {
            _ = await storage.write(key: StorageKeys.jwks(tenantId: tenantId, host: host), value: str)
        }
        if let etag = cached.etag {
            _ = await storage.write(key: StorageKeys.jwksETag(tenantId: tenantId, host: host), value: etag)
        }
    }

    private func restoreFromKeychain() async -> (jwks: JWKSet, fetchedAt: Date, etag: String?)? {
        guard let json = await storage.read(key: StorageKeys.jwks(tenantId: tenantId, host: host)),
            let data = json.data(using: .utf8),
            let jwks = try? JSONDecoder().decode(JWKSet.self, from: data)
        else { return nil }
        let etag = await storage.read(key: StorageKeys.jwksETag(tenantId: tenantId, host: host))
        // We don't store fetchedAt persistently — assume caller will refetch
        // if cached entry is older than expected. Use Date.distantPast to
        // force a refetch path via the TTL check.
        return (jwks, Date.distantPast, etag)
    }
}
