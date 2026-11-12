// DPoP prover + refresh wiring conformance suite. Self-describing test names so an auditor
// can grep them. The proof shape is matched against `@rakomi/node`'s `createDpopProver`
// oracle (`packages/sdk/src/dpop.ts`): header `{typ:"dpop+jwt", alg:"ES256", jwk:<public-only>}`,
// payload `{htm, htu, iat (seconds int), jti (UUID)}` + optional `nonce`, NO `ath`.

import XCTest

@testable import RakomiSDK

#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Crypto)
import Crypto
#endif

// MARK: - Proof-decode helpers

private struct DecodedProof {
    let header: [String: Any]
    let payload: [String: Any]
    let signature: Data
    let signingInput: Data
}

private func decodeProof(_ jwt: String) throws -> DecodedProof {
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    guard parts.count == 3 else {
        throw XCTSkip("proof JWT not 3 parts: \(parts.count)")
    }
    guard
        let hData = base64URLDecode(parts[0]),
        let pData = base64URLDecode(parts[1]),
        let sData = base64URLDecode(parts[2]),
        let header = try JSONSerialization.jsonObject(with: hData) as? [String: Any],
        let payload = try JSONSerialization.jsonObject(with: pData) as? [String: Any]
    else {
        throw XCTSkip("proof JWT failed to decode")
    }
    let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
    return DecodedProof(header: header, payload: payload, signature: sData, signingInput: signingInput)
}

// MARK: - Fake refresh transport

/// Scripted transport — returns queued `DpopRefreshHTTPResult`s in order, recording
/// the proof presented on each call so tests can assert distinct jti / header presence.
private actor FakeRefreshTransport: DpopRefreshTransport {
    private var queue: [DpopRefreshHTTPResult]
    private(set) var presentedProofs: [String?] = []

    init(_ results: [DpopRefreshHTTPResult]) { self.queue = results }

    func sendRefresh(refreshToken: String, dpopProof: String?) async throws -> DpopRefreshHTTPResult {
        presentedProofs.append(dpopProof)
        if queue.isEmpty {
            return DpopRefreshHTTPResult(
                statusCode: 500,
                body: Data(),
                dpopNonce: nil,
                useDpopNonceChallenge: false,
                dpopProofRejected: false
            )
        }
        return queue.removeFirst()
    }

    func proofs() -> [String?] { presentedProofs }
}

private func okBody(tokenType: String) -> Data {
    let obj: [String: Any] = [
        "accessToken": "at_\(UUID().uuidString)",
        "refreshToken": "rt_next",
        "expiresIn": 3600,
        "tokenType": tokenType,
    ]
    return try! JSONSerialization.data(withJSONObject: obj)
}

private func ok(tokenType: String) -> DpopRefreshHTTPResult {
    DpopRefreshHTTPResult(
        statusCode: 200,
        body: okBody(tokenType: tokenType),
        dpopNonce: nil,
        useDpopNonceChallenge: false,
        dpopProofRejected: false
    )
}

// MARK: - Tests

final class DpopProverTests: XCTestCase {

    /// Use the in-heap residual path deterministically so the suite is green headless
    /// (Secure Enclave is unavailable on CI/simulator). The SE path is exercised only
    /// where `SecureEnclave.isAvailable` (see `testSecureEnclaveBackedWhenAvailable`).
    private func makeProver() throws -> CryptoKitDpopProver {
        try CryptoKitDpopProver(preferSecureEnclave: false)
    }

    private func makeSession(prover: CryptoKitDpopProver) -> DpopSession {
        DpopSession(prover: prover, baseURL: "https://api.rakomi.com")
    }

    // ── bound ⇒ structurally-valid proof ──

    func testBoundProofHasCanonicalStructureAndPinnedAlg() async throws {
        let prover = try makeProver()
        let jwt = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        let d = try decodeProof(jwt)

        // Header: typ + pinned alg + public-only jwk.
        XCTAssertEqual(d.header["typ"] as? String, "dpop+jwt")
        XCTAssertEqual(d.header["alg"] as? String, "ES256", "alg MUST be pinned ES256, never derived")
        let jwk = try XCTUnwrap(d.header["jwk"] as? [String: Any])
        XCTAssertEqual(jwk["kty"] as? String, "EC")
        XCTAssertEqual(jwk["crv"] as? String, "P-256")
        XCTAssertNotNil(jwk["x"] as? String)
        XCTAssertNotNil(jwk["y"] as? String)

        // Payload: htm/htu + seconds-integer iat + UUID jti, NO ath.
        XCTAssertEqual(d.payload["htm"] as? String, "POST")
        XCTAssertEqual(d.payload["htu"] as? String, "https://api.rakomi.com/v1/auth/refresh")
        let iat = try XCTUnwrap(d.payload["iat"] as? Int)
        // iat is seconds since epoch (10-digit), NOT milliseconds (13-digit).
        XCTAssertGreaterThan(iat, 1_600_000_000)
        XCTAssertLessThan(iat, 100_000_000_000, "iat must be SECONDS not milliseconds")
        let jti = try XCTUnwrap(d.payload["jti"] as? String)
        XCTAssertNotNil(UUID(uuidString: jti), "jti must be a UUID")
    }

    func testPublicOnlyJwkHasNoPrivateKeyMaterial() async throws {
        let prover = try makeProver()
        let jwt = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        let d = try decodeProof(jwt)
        let jwk = try XCTUnwrap(d.header["jwk"] as? [String: Any])
        XCTAssertNil(jwk["d"], "jwk MUST be public-only — no private `d` component")
        // Exact key-set pin on the jwk.
        XCTAssertEqual(Set(jwk.keys), Set(["kty", "crv", "x", "y"]))
    }

    func testNoAthClaimOnRefreshProof() async throws {
        let prover = try makeProver()
        let jwt = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        let d = try decodeProof(jwt)
        XCTAssertNil(d.payload["ath"], "refresh proof MUST NOT carry `ath` (no access token at the refresh endpoint)")
    }

    func testNoPIIExactClaimSetPin() async throws {
        let prover = try makeProver()
        // Without nonce: exactly {htm, htu, iat, jti}.
        let jwt = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        XCTAssertEqual(Set(try decodeProof(jwt).payload.keys), Set(["htm", "htu", "iat", "jti"]))
        // With nonce: exactly {htm, htu, iat, jti, nonce}.
        let jwt2 = try await prover.createProof(
            htm: "POST",
            htu: "https://api.rakomi.com/v1/auth/refresh",
            nonce: "n-123"
        )
        let p2 = try decodeProof(jwt2).payload
        XCTAssertEqual(Set(p2.keys), Set(["htm", "htu", "iat", "jti", "nonce"]))
        XCTAssertEqual(p2["nonce"] as? String, "n-123")
    }

    func testSignatureVerifiesWithEmbeddedPublicKey() async throws {
        let prover = try makeProver()
        let jwt = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        let d = try decodeProof(jwt)
        let jwk = try XCTUnwrap(d.header["jwk"] as? [String: Any])
        let x = try XCTUnwrap(base64URLDecode(try XCTUnwrap(jwk["x"] as? String)))
        let y = try XCTUnwrap(base64URLDecode(try XCTUnwrap(jwk["y"] as? String)))
        XCTAssertEqual(x.count, 32)
        XCTAssertEqual(y.count, 32)
        // Reconstruct the P-256 public key from raw x‖y and verify the JOSE R‖S sig.
        let raw = x + y
        let pub = try P256.Signing.PublicKey(rawRepresentation: raw)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: d.signature)
        XCTAssertTrue(
            pub.isValidSignature(sig, for: d.signingInput),
            "ES256 signature must verify under the embedded jwk"
        )
    }

    // ── distinct jti per call (incl. simulated transport retry) ──

    func testTwoProofsHaveDistinctJti() async throws {
        let prover = try makeProver()
        let a = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        let b = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        let ja = try decodeProof(a).payload["jti"] as? String
        let jb = try decodeProof(b).payload["jti"] as? String
        XCTAssertNotNil(ja)
        XCTAssertNotNil(jb)
        XCTAssertNotEqual(ja, jb, "each proof MUST mint a fresh jti")
    }

    // ── stable jkt across refreshes, same instance, RFC 7638 ──

    func testJktHintStableAcrossCallsAndMatchesJwk() async throws {
        let prover = try makeProver()
        let jkt1 = try await prover.jktHint()
        let jkt2 = try await prover.jktHint()
        XCTAssertEqual(jkt1, jkt2, "jkt MUST be stable for the prover's life")

        // Independently recompute RFC 7638 thumbprint from the proof's jwk.
        let jwt = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        let jwk = try XCTUnwrap(try decodeProof(jwt).header["jwk"] as? [String: Any])
        let x = try XCTUnwrap(jwk["x"] as? String)
        let y = try XCTUnwrap(jwk["y"] as? String)
        let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        let expected = base64URLEncode(PKCE.sha256(Data(canonical.utf8)))
        XCTAssertEqual(jkt1, expected, "jktHint MUST equal the RFC 7638 thumbprint of the jwk")
    }

    func testTwoProversHaveDistinctJkt() async throws {
        let a = try makeProver()
        let b = try makeProver()
        let ja = try await a.jktHint()
        let jb = try await b.jktHint()
        XCTAssertNotEqual(ja, jb, "independent keypairs ⇒ distinct jkt")
    }

    // ── Bearer ⇒ NO proof; no/throwing prover ⇒ typed unavailable + ZERO net ──

    func testBearerSessionAttachesNoProof() async throws {
        // No DpopSession (or unbound) ⇒ Bearer refresh, no DPoP header.
        let transport = FakeRefreshTransport([ok(tokenType: "Bearer")])
        let outcome = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: nil
        )
        if case .success(_, let attached) = outcome {
            XCTAssertFalse(attached, "Bearer path attaches no proof")
        } else {
            XCTFail("expected success on Bearer refresh")
        }
        let proofs = await transport.proofs()
        XCTAssertEqual(proofs, [nil], "Bearer refresh MUST present a nil (absent) DPoP header")
    }

    func testUnboundSessionAttachesNoProof() async throws {
        let prover = try makeProver()
        let session = makeSession(prover: prover)  // starts unbound
        let transport = FakeRefreshTransport([ok(tokenType: "Bearer")])
        let outcome = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        if case .success(_, let attached) = outcome {
            XCTAssertFalse(attached)
        } else {
            XCTFail("expected success")
        }
        let proofs = await transport.proofs()
        XCTAssertEqual(proofs, [nil])
    }

    func testThrowingProverSurfacesUnavailableAndMakesZeroNetworkCall() async throws {
        let session = DpopSession(prover: ThrowingProver(), baseURL: "https://api.rakomi.com")
        await session.observeTokenType("DPoP", attachedProof: true)  // force bound
        let transport = FakeRefreshTransport([ok(tokenType: "DPoP")])
        let outcome = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        guard case .failure(let err) = outcome else {
            return XCTFail("throwing prover MUST fail, never silently Bearer")
        }
        XCTAssertEqual(err.reason, .dpopProverUnavailable)
        let attempts = await transport.proofs().count
        XCTAssertEqual(attempts, 0, "ZERO network call when the signer is unavailable")
    }

    // ── bound refresh attaches a structurally-valid proof ──

    func testBoundRefreshAttachesProofAndStaysBound() async throws {
        let prover = try makeProver()
        let session = makeSession(prover: prover)
        await session.observeTokenType("DPoP", attachedProof: true)  // bound at issuance
        let transport = FakeRefreshTransport([ok(tokenType: "DPoP")])
        let outcome = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        guard case .success(_, let attached) = outcome else { return XCTFail("expected success") }
        XCTAssertTrue(attached)
        let proofs = await transport.proofs()
        XCTAssertEqual(proofs.count, 1)
        let proof = try XCTUnwrap(proofs[0])
        let d = try decodeProof(proof)
        XCTAssertEqual(d.payload["htm"] as? String, "POST")
        XCTAssertEqual(d.payload["htu"] as? String, "https://api.rakomi.com/v1/auth/refresh")
        let stillBound = await session.isBound
        XCTAssertTrue(stillBound)
    }

    // ── exactly-one nonce retry; returned twice ⇒ terminal ──

    func testSingleNonceRetryEchoesNonceWithFreshJti() async throws {
        let prover = try makeProver()
        let session = makeSession(prover: prover)
        await session.observeTokenType("DPoP", attachedProof: true)

        let challenge = DpopRefreshHTTPResult(
            statusCode: 401,
            body: Data("{\"error\":\"use_dpop_nonce\"}".utf8),
            dpopNonce: "server-nonce-1",
            useDpopNonceChallenge: true,
            dpopProofRejected: false
        )
        let transport = FakeRefreshTransport([challenge, ok(tokenType: "DPoP")])

        let outcome = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        guard case .success = outcome else { return XCTFail("nonce retry should succeed") }

        let proofs = await transport.proofs()
        XCTAssertEqual(proofs.count, 2, "exactly one retry — two HTTP attempts")
        let first = try decodeProof(try XCTUnwrap(proofs[0]))
        let second = try decodeProof(try XCTUnwrap(proofs[1]))
        XCTAssertNil(first.payload["nonce"], "first attempt carries no nonce")
        XCTAssertEqual(second.payload["nonce"] as? String, "server-nonce-1", "retry echoes the server nonce")
        XCTAssertNotEqual(
            first.payload["jti"] as? String,
            second.payload["jti"] as? String,
            "retry MUST mint a fresh jti"
        )
    }

    func testSecondNonceChallengeIsTerminalInvalidProof() async throws {
        let prover = try makeProver()
        let session = makeSession(prover: prover)
        await session.observeTokenType("DPoP", attachedProof: true)

        let challenge = DpopRefreshHTTPResult(
            statusCode: 401,
            body: Data("{\"error\":\"use_dpop_nonce\"}".utf8),
            dpopNonce: "n",
            useDpopNonceChallenge: true,
            dpopProofRejected: false
        )
        // Returned twice — the retry also gets a challenge ⇒ terminal.
        let transport = FakeRefreshTransport([challenge, challenge])
        let outcome = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        guard case .failure(let err) = outcome else { return XCTFail("a second challenge is terminal") }
        XCTAssertEqual(err.reason, .invalidDpopProof)
        let attempts = await transport.proofs().count
        XCTAssertEqual(attempts, 2, "no THIRD attempt — retry is bounded to one")
    }

    // ── three-class taxonomy ──

    func testProofRejectionMapsToInvalidDpopProof() async throws {
        let prover = try makeProver()
        let session = makeSession(prover: prover)
        await session.observeTokenType("DPoP", attachedProof: true)
        let rejected = DpopRefreshHTTPResult(
            statusCode: 401,
            body: Data("{\"error\":\"invalid_dpop_proof\"}".utf8),
            dpopNonce: nil,
            useDpopNonceChallenge: false,
            dpopProofRejected: true
        )
        let transport = FakeRefreshTransport([rejected])
        let outcome = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        guard case .failure(let err) = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(err.reason, .invalidDpopProof)
    }

    func testGenuineRevocationMapsToInvalidRefreshToken() async throws {
        let prover = try makeProver()
        let session = makeSession(prover: prover)
        await session.observeTokenType("DPoP", attachedProof: true)
        let revoked = DpopRefreshHTTPResult(
            statusCode: 401,
            body: Data("{\"error\":\"invalid_grant\"}".utf8),
            dpopNonce: nil,
            useDpopNonceChallenge: false,
            dpopProofRejected: false
        )
        let transport = FakeRefreshTransport([revoked])
        let outcome = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        guard case .failure(let err) = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(err.reason, .invalidRefreshToken)
    }

    // ── jkt at issuance == jkt at refresh ──

    func testJktAtIssuanceEqualsJktAtRefresh() async throws {
        let prover = try makeProver()
        let session = makeSession(prover: prover)
        // Issuance binds.
        await session.observeTokenType("DPoP", attachedProof: true)
        let issuanceJkt = await session.boundJkt
        XCTAssertNotNil(issuanceJkt)

        // Refresh with the SAME session/prover.
        let transport = FakeRefreshTransport([ok(tokenType: "DPoP")])
        _ = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        let refreshJkt = await session.boundJkt
        XCTAssertEqual(issuanceJkt, refreshJkt, "the bound jkt is continuous across refresh")
        let proverJkt = try await prover.jktHint()
        XCTAssertEqual(issuanceJkt, proverJkt)
    }

    // ── server downgrade ⇒ detector fires, never silent Bearer ──

    func testServerDowngradeFiresDetector() async throws {
        let prover = try makeProver()
        let box = DowngradeBox()
        let session = DpopSession(
            prover: prover,
            baseURL: "https://api.rakomi.com",
            onDowngrade: { reason in box.record(reason) }
        )
        await session.observeTokenType("DPoP", attachedProof: true)  // bound
        // Server now returns Bearer for a proof-bearing refresh.
        let transport = FakeRefreshTransport([ok(tokenType: "Bearer")])
        _ = await DpopRefresh.refresh(
            transport: transport,
            refreshToken: "rt",
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        let downgraded = await session.isDowngraded
        XCTAssertTrue(downgraded)
        XCTAssertEqual(box.value(), .serverReturnedBearer)
    }

    // ── Secure Enclave where available; in-heap residual otherwise ──

    func testSecureEnclaveBackedWhenAvailable() async throws {
        #if canImport(CryptoKit)
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave unavailable on this host — in-heap residual exercised elsewhere")
        }
        let prover = try CryptoKitDpopProver(preferSecureEnclave: true)
        XCTAssertTrue(prover.isSecureEnclaveBacked, "SE-backed prover when the Enclave is available")
        // Still produces a verifiable proof.
        let jwt = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        let d = try decodeProof(jwt)
        XCTAssertEqual(d.header["alg"] as? String, "ES256")
        #else
        throw XCTSkip("CryptoKit unavailable")
        #endif
    }

    func testInHeapResidualProducesValidProofHeadless() async throws {
        let prover = try CryptoKitDpopProver(preferSecureEnclave: false)
        XCTAssertFalse(prover.isSecureEnclaveBacked)
        let jwt = try await prover.createProof(htm: "POST", htu: "https://api.rakomi.com/v1/auth/refresh", nonce: nil)
        XCTAssertEqual(try decodeProof(jwt).header["alg"] as? String, "ES256")
    }
}

// MARK: - Test prover that always throws (signer unavailable)

private struct ThrowingProver: DpopProver {
    func createProof(htm: String, htu: String, nonce: String?) async throws -> String {
        throw DpopProverError("signer unavailable")
    }
    func jktHint() async throws -> String { "jkt-throwing" }
}

/// Thread-safe box capturing the downgrade callback (the callback is `@Sendable`,
/// invoked from the session actor). Uses an NSLock so the captured ref is Sendable.
private final class DowngradeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var reason: DpopDowngradeReason?
    func record(_ r: DpopDowngradeReason) {
        lock.lock()
        reason = r
        lock.unlock()
    }
    func value() -> DpopDowngradeReason? {
        lock.lock()
        defer { lock.unlock() }
        return reason
    }
}
