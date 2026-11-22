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
    /// The raw `Retry-After` response header, if present.
    public let retryAfter: String?
    /// The raw `Date` response header, if present (used for clock-skew capture).
    public let serverDate: String?

    public init(
        statusCode: Int,
        body: Data,
        dpopNonce: String?,
        useDpopNonceChallenge: Bool,
        dpopProofRejected: Bool,
        retryAfter: String? = nil,
        serverDate: String? = nil
    ) {
        self.statusCode = statusCode
        self.body = body
        self.dpopNonce = dpopNonce
        self.useDpopNonceChallenge = useDpopNonceChallenge
        self.dpopProofRejected = dpopProofRejected
        self.retryAfter = retryAfter
        self.serverDate = serverDate
    }
}

/// Where a refresh token is presented. The session's origin decides it: the
/// server refreshes a session issued to an OAuth client only at the token
/// endpoint, where the client is named, and answers `/v1/auth/refresh` for such a
/// session like an unknown token.
public enum RefreshEndpoint: Sendable, Equatable {
    /// `POST /v1/auth/refresh` (JSON) — a first-party session: password, MFA,
    /// magic link, native Sign in with Apple, device code.
    case firstParty
    /// RFC 6749 §6 at the published token endpoint (form-encoded,
    /// `grant_type=refresh_token` and `client_id`) — a session issued to an OAuth
    /// client (browser sign-in).
    case tokenEndpoint(URL, clientId: String)

    /// The DPoP `htu` target: the URL the refresh is posted to.
    var proofTarget: String {
        switch self {
        case .firstParty: return "/v1/auth/refresh"
        case .tokenEndpoint(let url, _): return url.absoluteString
        }
    }
}

/// Transport seam: perform ONE refresh POST to `endpoint` with an optional DPoP
/// proof header. Both refresh paths use it — a Bearer refresh passes no proof.
/// Implemented over `HTTPClient` in production; faked in tests.
public protocol DpopRefreshTransport: Sendable {
    func sendRefresh(
        refreshToken: String,
        endpoint: RefreshEndpoint,
        dpopProof: String?
    ) async throws -> DpopRefreshHTTPResult
}

/// Production `DpopRefreshTransport` over the SDK's long-lived `HTTPClient`. POSTs
/// to the endpoint the session belongs to, attaching the `DPoP` proof header when
/// present, and extracts the RFC 9449 §8 nonce / proof-rejection signals from the
/// response.
///
/// Internal — not part of the public API surface. Its own initializer takes
/// `HTTPClient`, which is itself internal; conformance to the public
/// `DpopRefreshTransport` protocol is unaffected, since a type's witness methods
/// only need to be as visible as the type itself.
struct HTTPClientDpopRefreshTransport: DpopRefreshTransport {
    private let httpClient: HTTPClient

    init(httpClient: HTTPClient) {
        self.httpClient = httpClient
    }

    func sendRefresh(
        refreshToken: String,
        endpoint: RefreshEndpoint,
        dpopProof: String?
    ) async throws -> DpopRefreshHTTPResult {
        var headers: [String: String]?
        if let dpopProof { headers = ["DPoP": dpopProof] }
        let (data, http): (Data, HTTPURLResponse)
        switch endpoint {
        case .firstParty:
            (data, http) = try await httpClient.send(
                method: "POST",
                path: "/v1/auth/refresh",
                body: ["refresh_token": refreshToken],
                extraHeaders: headers
            )
        case .tokenEndpoint(let url, let clientId):
            (data, http) = try await httpClient.sendForm(
                url: url,
                fields: [
                    "grant_type": "refresh_token",
                    "refresh_token": refreshToken,
                    "client_id": clientId,
                ],
                extraHeaders: headers
            )
        }
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
            dpopProofRejected: proofRejected,
            retryAfter: headers.value(forHTTPHeaderField: "Retry-After"),
            serverDate: headers.value(forHTTPHeaderField: "Date")
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
    ///
    /// A transient failure (a 5xx, 429 or 408, or a transport failure) is the
    /// `network` class: the session, the stored credential and the key binding
    /// are all kept. A 2xx that cannot be read is `invalidRefreshToken`: the
    /// server consumed the refresh token, and presenting it again would be a
    /// reuse. `now` anchors an HTTP-date `Retry-After`.
    public static func refresh(
        transport: any DpopRefreshTransport,
        refreshToken: String,
        endpoint: RefreshEndpoint,
        session: DpopSession?,
        now: Date = Date()
    ) async -> DpopRefreshOutcome {
        let bound = await session?.isBound == true

        // ── Bearer path — no proof attached. ──
        guard bound, let session else {
            do {
                let http = try await transport.sendRefresh(
                    refreshToken: refreshToken,
                    endpoint: endpoint,
                    dpopProof: nil
                )
                return await finish(http: http, session: session, attachedProof: false, now: now)
            } catch {
                return .failure(networkError("refresh failed"))
            }
        }

        // ── Bound path — resolve a proof; a signer failure is terminal, NO Bearer
        //    fallback (TOCTOU pin: the single-flight guard is already set by the
        //    controller BEFORE this async signing begins). ──
        var proof: String
        do {
            proof = try await session.resolveProof(htm: "POST", target: endpoint.proofTarget)
        } catch {
            return .failure(proverUnavailable("DPoP prover threw"))
        }
        if proof.isEmpty {
            return .failure(proverUnavailable("DPoP prover returned an empty proof"))
        }

        var http: DpopRefreshHTTPResult
        do {
            http = try await transport.sendRefresh(
                refreshToken: refreshToken,
                endpoint: endpoint,
                dpopProof: proof
            )
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
                retryProof = try await session.resolveProof(htm: "POST", target: endpoint.proofTarget, nonce: nonce)
            } catch {
                return .failure(proverUnavailable("DPoP prover threw on nonce retry"))
            }
            if retryProof.isEmpty {
                return .failure(proverUnavailable("DPoP prover returned an empty proof on nonce retry"))
            }
            do {
                http = try await transport.sendRefresh(
                    refreshToken: refreshToken,
                    endpoint: endpoint,
                    dpopProof: retryProof
                )
            } catch {
                return .failure(networkError("refresh failed"))
            }
        }

        return await finish(http: http, session: session, attachedProof: true, now: now)
    }

    // MARK: - Result mapping

    private static func finish(
        http: DpopRefreshHTTPResult,
        session: DpopSession?,
        attachedProof: Bool,
        now: Date
    ) async -> DpopRefreshOutcome {
        if (200..<300).contains(http.statusCode) {
            // A success the SDK cannot read (a truncated body): the server has
            // consumed the presented refresh token. Presenting it again would be
            // a reuse, which revokes every session of the user, so this is the
            // end of the session locally — never retried.
            guard let tokens = decode(http.body) else {
                return .failure(
                    SdkError(
                        code: .refreshFailed,
                        reason: .invalidRefreshToken,
                        errorMessage: "refresh_decode_failed",
                        httpStatus: http.statusCode
                    )
                )
            }
            await session?.observeTokenType(tokens.tokenType, attachedProof: attachedProof)
            return .success(tokens: tokens, attachedProof: attachedProof)
        }
        return .failure(mapFailure(http, now: now))
    }

    private static func decode(_ data: Data) -> DpopRefreshTokens? {
        // The refresh endpoint answers in snake_case, which `APITokenResponse`
        // maps explicitly. The hand-rolled pass below stays as a tolerant
        // fallback for a body that is well-formed JSON but not that envelope.
        if let r = try? JSONDecoder().decode(APITokenResponse.self, from: data),
            let accessToken = r.accessToken
        {
            return DpopRefreshTokens(
                accessToken: accessToken,
                refreshToken: r.refreshToken,
                expiresIn: r.expiresIn ?? 0,
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
    private static func mapFailure(_ http: DpopRefreshHTTPResult, now: Date) -> SdkError {
        // 5xx / 429 / 408 ⇒ transport/network class, whatever the body says — the
        // grant is still good and the key binding stays. Checked first, so a
        // nonce header on an overloaded response never reads as a proof problem.
        if RefreshFailure.isTransientStatus(http.statusCode) {
            return RefreshFailure.transientError(
                reason: .network,
                message: "refresh_transient_\(http.statusCode)",
                httpStatus: http.statusCode,
                retryAfter: RefreshFailure.parseRetryAfter(http.retryAfter, now: now)
            )
        }
        // A proof rejection (or a nonce challenge that survived the single retry — a
        // second `use_dpop_nonce` is a proof problem, not a revocation) is the
        // distinct, rollback-actionable `invalid_dpop_proof` class.
        if http.dpopProofRejected || http.useDpopNonceChallenge {
            return SdkError(code: .refreshFailed, reason: .invalidDpopProof, errorMessage: "invalid_dpop_proof")
        }
        // Genuine revocation/expiry (a bare 401, or a 4xx naming the grant or the
        // client as invalid, or one of the API's session-ending codes such as a
        // 403 `auth/user_blocked`) ⇒ full re-login.
        if RefreshFailure.isDefinitiveRejection(
            status: http.statusCode,
            oauthError: RefreshFailure.oauthError(from: http.body)
        ) {
            return SdkError(
                code: .refreshFailed,
                reason: .invalidRefreshToken,
                errorMessage: "invalid_refresh_token",
                httpStatus: http.statusCode
            )
        }
        // Any other rejection (for example a 403 with no session-ending code, which a proxy
        // in front of the API can produce) does not prove the session is over: it
        // is kept, and not retried automatically.
        return SdkError(
            code: .refreshFailed,
            reason: .unknown,
            errorMessage: "refresh_rejected_\(http.statusCode)",
            httpStatus: http.statusCode
        )
    }

    private static func proverUnavailable(_ message: String) -> SdkError {
        SdkError(code: .refreshFailed, reason: .dpopProverUnavailable, errorMessage: message)
    }

    private static func networkError(_ message: String) -> SdkError {
        SdkError(code: .refreshFailed, reason: .network, errorMessage: message)
    }
}
