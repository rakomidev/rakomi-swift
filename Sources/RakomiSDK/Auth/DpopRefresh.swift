// DPoP-aware refresh decision logic.
// Swift port of the React Native SDK's DPoP refresh logic.
//
// Wraps the raw refresh POST with the SDK-side decision logic:
// bound-vs-Bearer attach, the single bounded RFC 9449 §8 nonce
// retry, and the THREE distinct client-side failure classes.
//
// SECURITY invariants (mirror node/RN):
//   - bound + signer fails ⇒ `dpop_prover_unavailable`, and NO proof-less network
//     call is made (never a silent Bearer downgrade).
//   - a fresh `jti` is minted per HTTP attempt (the nonce retry rebuilds the proof;
//     a transport retry rebuilds the proof) — never reused across attempts (would
//     trip server reuse-detection).
//   - the nonce retry re-presents the SAME `refresh_token` (no rotation between
//     attempts) and runs AT MOST once; a second `use_dpop_nonce` is terminal.

import Foundation

/// The raw outcome of one refresh HTTP attempt, normalized so the decision layer is
/// transport-agnostic (and unit-testable without a live `URLSession`).
public struct DpopRefreshHTTPResult: Sendable {
    public let statusCode: Int
    public let body: Data
    /// The `DPoP-Nonce` response header, if present (read case-insensitively).
    public let dpopNonce: String?
    /// `true` if the response signals `use_dpop_nonce` (header or `WWW-Authenticate`
    /// / body `error`). Distinct from a plain nonce header so the decision layer can
    /// bound the retry.
    public let useDpopNonceChallenge: Bool
    /// `true` if the response signals a proof rejection (`invalid_dpop_proof`,
    /// `jti_replay`, or a generic 401 on a presented proof) — distinct, terminal.
    public let dpopProofRejected: Bool

    public init(
        statusCode: Int,
        body: Data,
        dpopNonce: String?,
        useDpopNonceChallenge: Bool,
        dpopProofRejected: Bool
    ) {
        self.statusCode = statusCode
        self.body = body
        self.dpopNonce = dpopNonce
        self.useDpopNonceChallenge = useDpopNonceChallenge
        self.dpopProofRejected = dpopProofRejected
    }
}

/// Transport seam: perform ONE refresh POST with an optional DPoP proof header.
/// Implemented over `HTTPClient` in production; faked in tests.
public protocol DpopRefreshTransport: Sendable {
    func sendRefresh(refreshToken: String, dpopProof: String?) async throws -> DpopRefreshHTTPResult
}

/// Production `DpopRefreshTransport` over the SDK's long-lived `HTTPClient`. POSTs
/// `/v1/auth/refresh`, attaching the `DPoP` proof header when present, and extracts
/// the RFC 9449 §8 nonce / proof-rejection signals from the response.
///
/// Internal — not part of the public API surface. Its own initializer takes
/// `HTTPClient`, which is itself internal; conformance to the public
/// `DpopRefreshTransport` protocol is unaffected, since a type's witness methods
/// only need to be as visible as the type itself.
struct HTTPClientDpopRefreshTransport: DpopRefreshTransport {
    private let httpClient: HTTPClient
    private let path: String

    init(httpClient: HTTPClient, path: String = "/v1/auth/refresh") {
        self.httpClient = httpClient
        self.path = path
    }

    func sendRefresh(refreshToken: String, dpopProof: String?) async throws -> DpopRefreshHTTPResult {
        var headers: [String: String]?
        if let dpopProof { headers = ["DPoP": dpopProof] }
        let (data, http) = try await httpClient.send(
            method: "POST",
            path: path,
            body: ["refresh_token": refreshToken],
            extraHeaders: headers
        )
        return DpopRefreshHTTPResult.from(statusCode: http.statusCode, body: data, headers: http)
    }
}

extension DpopRefreshHTTPResult {
    /// Build a result from a raw `(status, body, response)` — parses the RFC 9449 §8
    /// `DPoP-Nonce` response header (case-insensitive), the `WWW-Authenticate: DPoP
    /// error="use_dpop_nonce"` challenge, and the first-party `code`/`error` body
    /// signals (`invalid_dpop_proof` / `jti_replay`).
    static func from(statusCode: Int, body: Data, headers: HTTPURLResponse) -> DpopRefreshHTTPResult {
        let nonce = headers.value(forHTTPHeaderField: "DPoP-Nonce")
        let wwwAuth = (headers.value(forHTTPHeaderField: "WWW-Authenticate") ?? "").lowercased()
        let payload = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
        let bodyError = ((payload?["error"] as? String) ?? (payload?["code"] as? String) ?? "").lowercased()

        let useNonce = wwwAuth.contains("use_dpop_nonce") || bodyError == "use_dpop_nonce"
        // A proof rejection: the first-party invalid_dpop_proof / jti_replay codes
        // (body) or the RFC 9449 §7.1 invalid_dpop_proof WWW-Authenticate challenge.
        // A generic `invalid_token` is NOT a proof rejection — it maps to the terminal
        // invalid_refresh_token class (parity with node/RN/Flutter; keeps the
        // enforce-flip rollout signal from counting revocations as proof problems).
        let proofRejected =
            !useNonce
            && (bodyError == "invalid_dpop_proof" || bodyError == "jti_replay"
                || wwwAuth.contains("invalid_dpop_proof"))
        return DpopRefreshHTTPResult(
            statusCode: statusCode,
            body: body,
            dpopNonce: nonce,
            useDpopNonceChallenge: useNonce,
            dpopProofRejected: proofRejected
        )
    }
}

/// Decoded success payload (shape the refresh endpoint returns).
public struct DpopRefreshTokens: Sendable, Equatable {
    public let accessToken: String
    public let refreshToken: String?
    public let expiresIn: Int
    public let tokenType: String?

    public init(accessToken: String, refreshToken: String?, expiresIn: Int, tokenType: String?) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.tokenType = tokenType
    }
}

/// Result of the DPoP-aware refresh decision.
public enum DpopRefreshOutcome: Sendable {
    case success(tokens: DpopRefreshTokens, attachedProof: Bool)
    case failure(SdkError)
}

public enum DpopRefresh {
    /// Refresh the access token, attaching a DPoP proof IFF the session is bound.
    /// Performs the single bounded nonce retry and maps every failure into the
    /// three-class taxonomy. On success, re-confirms bound-truth from `token_type`.
    public static func refresh(
        transport: any DpopRefreshTransport,
        refreshToken: String,
        tokenEndpoint: String,
        session: DpopSession?
    ) async -> DpopRefreshOutcome {
        let bound = await session?.isBound == true

        // ── Bearer path — no proof attached. ──
        guard bound, let session else {
            do {
                let http = try await transport.sendRefresh(refreshToken: refreshToken, dpopProof: nil)
                return await finish(http: http, session: session, attachedProof: false)
            } catch {
                return .failure(networkError("refresh failed"))
            }
        }

        // ── Bound path — resolve a proof; a signer failure is terminal, NO Bearer
        //    fallback (TOCTOU pin: the single-flight guard is already set by the
        //    controller BEFORE this async signing begins). ──
        var proof: String
        do {
            proof = try await session.resolveProof(htm: "POST", target: tokenEndpoint)
        } catch {
            return .failure(proverUnavailable("DPoP prover threw"))
        }
        if proof.isEmpty {
            return .failure(proverUnavailable("DPoP prover returned an empty proof"))
        }

        var http: DpopRefreshHTTPResult
        do {
            http = try await transport.sendRefresh(refreshToken: refreshToken, dpopProof: proof)
        } catch {
            return .failure(networkError("refresh failed"))
        }

        // ── Single bounded nonce retry: rebuild the proof (fresh jti) with
        //    the server nonce, re-present the SAME refresh_token. At most once. ──
        if !(200..<300).contains(http.statusCode), http.useDpopNonceChallenge, let nonce = http.dpopNonce,
            !nonce.isEmpty
        {
            var retryProof: String
            do {
                retryProof = try await session.resolveProof(htm: "POST", target: tokenEndpoint, nonce: nonce)
            } catch {
                return .failure(proverUnavailable("DPoP prover threw on nonce retry"))
            }
            if retryProof.isEmpty {
                return .failure(proverUnavailable("DPoP prover returned an empty proof on nonce retry"))
            }
            do {
                http = try await transport.sendRefresh(refreshToken: refreshToken, dpopProof: retryProof)
            } catch {
                return .failure(networkError("refresh failed"))
            }
        }

        return await finish(http: http, session: session, attachedProof: true)
    }

    // MARK: - Result mapping

    private static func finish(
        http: DpopRefreshHTTPResult,
        session: DpopSession?,
        attachedProof: Bool
    ) async -> DpopRefreshOutcome {
        if (200..<300).contains(http.statusCode) {
            guard let tokens = decode(http.body) else {
                return .failure(
                    SdkError(code: .refreshFailed, reason: .invalidRefreshToken, errorMessage: "refresh_decode_failed")
                )
            }
            await session?.observeTokenType(tokens.tokenType, attachedProof: attachedProof)
            return .success(tokens: tokens, attachedProof: attachedProof)
        }
        return .failure(mapFailure(http))
    }

    private static func decode(_ data: Data) -> DpopRefreshTokens? {
        struct Resp: Decodable {
            let accessToken: String
            let refreshToken: String?
            let expiresIn: Int
            let tokenType: String?
        }
        // Tolerate both camelCase and snake_case keys (the refresh endpoint returns
        // camelCase per the existing Resp decode in RakomiAuthController).
        if let r = try? JSONDecoder().decode(Resp.self, from: data) {
            return DpopRefreshTokens(
                accessToken: r.accessToken,
                refreshToken: r.refreshToken,
                expiresIn: r.expiresIn,
                tokenType: r.tokenType
            )
        }
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        let access = (obj["accessToken"] as? String) ?? (obj["access_token"] as? String)
        guard let accessToken = access else { return nil }
        let refresh = (obj["refreshToken"] as? String) ?? (obj["refresh_token"] as? String)
        let expires = (obj["expiresIn"] as? Int) ?? (obj["expires_in"] as? Int) ?? 0
        let type = (obj["tokenType"] as? String) ?? (obj["token_type"] as? String)
        return DpopRefreshTokens(accessToken: accessToken, refreshToken: refresh, expiresIn: expires, tokenType: type)
    }

    /// Map a failed refresh HTTP result into the three-class taxonomy.
    private static func mapFailure(_ http: DpopRefreshHTTPResult) -> SdkError {
        // A proof rejection (or a nonce challenge that survived the single retry — a
        // second `use_dpop_nonce` is a proof problem, not a revocation) is the
        // distinct, rollback-actionable `invalid_dpop_proof` class.
        if http.dpopProofRejected || http.useDpopNonceChallenge {
            return SdkError(code: .refreshFailed, reason: .invalidDpopProof, errorMessage: "invalid_dpop_proof")
        }
        // 5xx ⇒ transport/network class.
        if (500...599).contains(http.statusCode) {
            return networkError("refresh_5xx_\(http.statusCode)")
        }
        // Genuine revocation/expiry (401/403 without a proof signal, or any other
        // terminal auth failure) ⇒ full re-login.
        return SdkError(code: .refreshFailed, reason: .invalidRefreshToken, errorMessage: "invalid_refresh_token")
    }

    private static func proverUnavailable(_ message: String) -> SdkError {
        SdkError(code: .refreshFailed, reason: .dpopProverUnavailable, errorMessage: message)
    }

    private static func networkError(_ message: String) -> SdkError {
        SdkError(code: .refreshFailed, reason: .network, errorMessage: message)
    }
}
