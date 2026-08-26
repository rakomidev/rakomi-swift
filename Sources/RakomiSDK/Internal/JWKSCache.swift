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

/// JSON Web Key (RFC 7517 §4) — RSA public key (kty=RSA only).
struct JWK: Sendable, Codable, Equatable {
    let kty: String
    let kid: String?
    let use: String?
    let alg: String?
    let n: String  // modulus, base64url
    let e: String  // exponent, base64url

    init(kty: String, kid: String?, use: String?, alg: String?, n: String, e: String) {
        self.kty = kty
        self.kid = kid
        self.use = use
        self.alg = alg
        self.n = n
        self.e = e
    }

    /// Build a `SecKey` (Apple platforms) from RSA modulus + exponent.
    /// Constructs DER ASN.1 PKCS#1 RSAPublicKey then `SecKeyCreateWithData`.
    #if canImport(Security)
    func toSecKey() throws -> SecKey? {
        guard kty == "RSA",
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

    #if canImport(Crypto) && !canImport(Security)
    func toCryptoPublicKey() throws -> _RSA.Signing.PublicKey {
        guard kty == "RSA",
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

struct JWKSet: Sendable, Codable, Equatable {
    let keys: [JWK]

    // Internal — not part of the public API surface. Uses the
    // compiler-synthesized memberwise `init(keys:)`; an explicit init would
    // be byte-identical and is flagged as redundant by
    // `swift format lint --strict` (`UseSynthesizedInitializer`).

    /// Find the JWK whose `kid` matches. If `kid == nil` AND there's exactly
    /// one key, return it. Otherwise throw `kid_miss`.
    func findKey(kid: String?) throws -> JWK {
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

actor JWKSCache {
    let storage: KeychainStorage
    let tenantId: String
    let url: URL
    let session: URLSession
    let now: () -> Date

    private var inMemory: (jwks: JWKSet, fetchedAt: Date, etag: String?)?

    init(
        storage: KeychainStorage,
        tenantId: String,
        url: URL,
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
        self.url = url
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

        var request = URLRequest(url: url)
        request.timeoutInterval = 10
        request.setValue(rakomiUserAgent, forHTTPHeaderField: "User-Agent")
        if let etag = inMemory?.etag {
            request.setValue(etag, forHTTPHeaderField: "If-None-Match")
        }

        let (data, response) = try await session.data(for: request)
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

        let parsed = try JSONDecoder().decode(JWKSet.self, from: data)
        let etag = http.value(forHTTPHeaderField: "ETag")
        inMemory = (parsed, now(), etag)
        await persistToKeychain()
        return parsed
    }

    /// Wipe in-memory + Keychain copy. Public seam for SSE/CAEP push.
    func invalidate() async {
        inMemory = nil
        await storage.delete(key: StorageKeys.jwks(tenantId: tenantId))
        await storage.delete(key: StorageKeys.jwksETag(tenantId: tenantId))
    }

    // MARK: - Persistence

    private func persistToKeychain() async {
        guard let cached = inMemory else { return }
        if let json = try? JSONEncoder().encode(cached.jwks),
            let str = String(data: json, encoding: .utf8)
        {
            _ = await storage.write(key: StorageKeys.jwks(tenantId: tenantId), value: str)
        }
        if let etag = cached.etag {
            _ = await storage.write(key: StorageKeys.jwksETag(tenantId: tenantId), value: etag)
        }
    }

    private func restoreFromKeychain() async -> (jwks: JWKSet, fetchedAt: Date, etag: String?)? {
        guard let json = await storage.read(key: StorageKeys.jwks(tenantId: tenantId)),
            let data = json.data(using: .utf8),
            let jwks = try? JSONDecoder().decode(JWKSet.self, from: data)
        else { return nil }
        let etag = await storage.read(key: StorageKeys.jwksETag(tenantId: tenantId))
        // We don't store fetchedAt persistently — assume caller will refetch
        // if cached entry is older than expected. Use Date.distantPast to
        // force a refetch path via the TTL check.
        return (jwks, Date.distantPast, etag)
    }
}
