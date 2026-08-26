// Auth state machine actor.
//
// Mirrors the RN/Flutter controller step-for-step. Single in-flight refresh
// dedup via stored `Task<Session, Error>?`. JWT signature verification fires
// ONLY on refresh-completion + `hasValidSession()` — NOT on every `getToken()`.

import Foundation

public actor RakomiAuthController {
    public nonisolated let configuration: RakomiAuthConfiguration
    public nonisolated let adapter: any RakomiNativeAdapter
    // Internal — not part of the public API surface. `httpClient` and
    // `jwksCache` are used only within this module. The public
    // JWKS-invalidation seam consumers need is the wrapper
    // `invalidateJWKS()` below (and `RakomiAuth.invalidateJWKS()`), which
    // stays public without needing these properties exposed.
    nonisolated let httpClient: HTTPClient
    public nonisolated let oauthStore: OAuthStateStore
    nonisolated let jwksCache: JWKSCache

    private var current: AuthState = .loading
    private var inFlightRefresh: Task<Session, Error>?
    private var clockSkewMs: Int = 0
    private var hydrated: Bool = false

    // ── DPoP-on-refresh ──
    // ONE session-scoped DPoP handle (one keypair) for the life of the
    // authenticated session. Created at issuance so the server binds
    // `dpop_jkt` to the key it sees at sign-in, then re-used on EVERY refresh — a
    // fresh key on refresh would be a `jkt` mismatch → mass-lockout, the exact
    // failure this design prevents. `nil` ⇒ DPoP not enabled / cold-start unbound;
    // the refresh path is a plain Bearer refresh (the negative branch is real).
    private var dpopSession: DpopSession?
    /// Lazily-built production transport over the long-lived `HTTPClient`.
    private lazy var dpopTransport: any DpopRefreshTransport =
        HTTPClientDpopRefreshTransport(httpClient: httpClient)

    private nonisolated let stateContinuation: AsyncStream<AuthState>.Continuation
    public nonisolated let stateStream: AsyncStream<AuthState>

    private nonisolated let eventContinuation: AsyncStream<AuthEvent>.Continuation
    public nonisolated let eventStream: AsyncStream<AuthEvent>

    public init(
        configuration: RakomiAuthConfiguration,
        adapter: any RakomiNativeAdapter
    ) {
        self.configuration = configuration
        self.adapter = adapter
        self.httpClient = HTTPClient(
            baseURL: configuration.apiBaseURL,
            publishableKey: configuration.publishableKey,
            certificateFingerprints: configuration.certificateFingerprints
        )

        // KeychainStorage created here for OAuth state + JWKS cache.
        let storage = KeychainStorage(accessGroup: configuration.keychainAccessGroup)
        self.oauthStore = OAuthStateStore(storage: storage)
        // The JWKS fetch MUST be pinned on the same fingerprints as the API
        // calls, so the session is passed in explicitly and never left to a
        // pinning-free default: a key set fetched over an unpinned connection
        // would make a forged token verify, defeating the point of pinning.
        self.jwksCache = JWKSCache(
            storage: storage,
            tenantId: configuration.tenantId,
            url: configuration.jwksURL,
            session: makeRakomiURLSession(
                certificateFingerprints: configuration.certificateFingerprints
            )
        )

        var stateCont: AsyncStream<AuthState>.Continuation!
        self.stateStream = AsyncStream<AuthState>(bufferingPolicy: .bufferingNewest(8)) { c in
            stateCont = c
        }
        self.stateContinuation = stateCont

        var eventCont: AsyncStream<AuthEvent>.Continuation!
        self.eventStream = AsyncStream<AuthEvent>(bufferingPolicy: .bufferingNewest(64)) { c in
            eventCont = c
        }
        self.eventContinuation = eventCont
    }

    // MARK: - Hydration

    /// Single hydration pass on cold start. Performs (1) fresh-install
    /// detection → (2) purge if needed → (3) hydration. Hydration MUST NOT
    /// run before purge.
    public func hydrate() async {
        guard !hydrated else { return }
        hydrated = true

        // (1) Fresh-install detection: a Keychain entry survives uninstall on
        // iOS, UserDefaults does not. The pair is compared by VALUE, using a
        // constant-time comparison, not merely for presence — presence alone
        // would let anything able to write UserDefaults suppress the purge by
        // storing an arbitrary non-null marker, and would make the
        // identifier's own unguessability irrelevant, because nothing would
        // ever read it back. UserDefaults is NOT secure storage, so the
        // marker is the half an attacker can reach; the Keychain half is the
        // one they must match.
        let lifecycleKey = StorageKeys.lifecycleId(tenantId: configuration.tenantId)
        let markerKey = StorageKeys.lifecycleIdMarker(tenantId: configuration.tenantId)
        let keychainId = await adapter.storageRead(key: lifecycleKey)
        let markerId = await adapter.userDefaultsRead(key: markerKey)
        let inKeychain = keychainId != nil
        let inDefaults = markerId != nil
        let reinstalled =
            keychainId != nil
            && !(markerId != nil && constantTimeEquals(keychainId!, markerId!))

        if reinstalled {
            // Post-uninstall reinstall — Keychain residue. Purge with EXACT prefix match.
            await adapter.storageDeleteAll(prefix: "\(storageNamespace).")
        }

        // Mint or refresh lifecycle id.
        if !inKeychain || !inDefaults || reinstalled {
            let bytes = (try? secureRandomBytes(count: 16)) ?? Data()
            let id = base64URLEncode(bytes)
            _ = await adapter.storageWrite(key: lifecycleKey, value: id)
            await adapter.userDefaultsWrite(key: markerKey, value: id)
        }

        // (3) Hydrate refresh token / restore last session.
        let refreshKey = StorageKeys.refreshToken(tenantId: configuration.tenantId)
        if let _ = await adapter.storageRead(key: refreshKey) {
            // Try a refresh — best-effort on cold start. If it fails, surface
            // signedOut.
            do {
                let session = try await refresh(force: false)
                let user = try await fetchUserFromToken(session.accessToken)
                emit(.authenticated(user, session))
                eventContinuation.yield(.signedIn(user))
            } catch {
                emit(.signedOut)
            }
        } else {
            emit(.signedOut)
        }
    }

    // MARK: - DPoP enablement

    /// Enable RFC 9449 DPoP-bound refresh for this controller. Creates the ONE
    /// session keypair (generated eagerly inside the prover) and the `DpopSession`
    /// handle that the issuance + every refresh share. Call once before sign-in.
    /// `prover` defaults to a fresh `CryptoKitDpopProver` (Secure-Enclave-backed
    /// where available, in-heap residual otherwise). The session is NOT bound until
    /// the server confirms `token_type == "DPoP"` on a token response.
    @discardableResult
    public func enableDpop(
        prover: (any DpopProver)? = nil,
        onDowngrade: (@Sendable (DpopDowngradeReason) -> Void)? = nil
    ) throws -> DpopSession {
        let resolvedProver: any DpopProver = try prover ?? CryptoKitDpopProver()
        let session = DpopSession(
            prover: resolvedProver,
            baseURL: configuration.apiBaseURL.absoluteString,
            onDowngrade: onDowngrade
        )
        self.dpopSession = session
        return session
    }

    /// Test/advanced seam — inject a custom refresh transport. Production uses the
    /// `HTTPClient`-backed default.
    public func setDpopTransport(_ transport: any DpopRefreshTransport) {
        self.dpopTransport = transport
    }

    /// Read-only access to the current DPoP session (for tests / bound-state probes).
    public func currentDpopSession() -> DpopSession? { dpopSession }

    /// Attach a DPoP proof at issuance: mint a proof bound to the
    /// session key against the token endpoint and observe the resulting `token_type`
    /// so the server records `dpop_jkt` for this key. Returns the proof to attach as
    /// the `DPoP` header on the issuance request, or `nil` if DPoP is not enabled.
    /// The proof STRING is never logged.
    public func issuanceProof(htm: String = "POST", target: String = "/v1/auth/token") async -> String? {
        guard let dpopSession else { return nil }
        return try? await dpopSession.resolveProof(htm: htm, target: target)
    }

    /// Observe a token-response `token_type` to update DPoP bound-truth.
    /// Call after EVERY issuance/refresh that may have presented a proof.
    public func observeDpopTokenType(_ tokenType: String?, attachedProof: Bool) async {
        await dpopSession?.observeTokenType(tokenType, attachedProof: attachedProof)
    }

    // MARK: - State management

    public func currentState() -> AuthState { current }

    public func invalidateJWKS() async {
        await jwksCache.invalidate()
    }

    public func emit(_ state: AuthState) {
        current = state
        stateContinuation.yield(state)
    }

    public func emitEvent(_ event: AuthEvent) {
        eventContinuation.yield(event)
    }

    // MARK: - Sign-in primitives

    public func signInPassword(email: String, password: String) async {
        emit(.loading)
        struct Resp: Decodable {
            let accessToken: String
            let refreshToken: String?
            let expiresIn: Int
            let nextAction: String?
            let challengeId: String?
        }
        do {
            let body: [String: Any] = ["email": email, "password": password]
            let resp = try await httpClient.post(path: "/v1/auth/login", body: body, as: Resp.self)
            if resp.nextAction == "verify_mfa" {
                if let cid = resp.challengeId {
                    eventContinuation.yield(.mfaChallengeRequired(challengeId: cid))
                }
                emit(
                    .error(
                        SdkError(
                            code: .mfaStepUpRequired,
                            reason: .mfaStepUpRequired,
                            errorMessage: "verify_mfa"
                        )
                    )
                )
                return
            }
            try await completeSignIn(
                accessToken: resp.accessToken,
                refreshToken: resp.refreshToken,
                expiresIn: TimeInterval(resp.expiresIn)
            )
        } catch let err as SdkError {
            emit(.error(err))
        } catch {
            emit(
                .error(
                    SdkError(
                        code: .signInFailed,
                        reason: .unknown,
                        errorMessage: "sign_in_unknown"
                    )
                )
            )
        }
    }

    public func signUp(email: String, password: String) async {
        emit(.loading)
        struct Resp: Decodable {
            let accessToken: String
            let refreshToken: String?
            let expiresIn: Int
        }
        do {
            let body: [String: Any] = ["email": email, "password": password]
            let resp = try await httpClient.post(path: "/v1/auth/register", body: body, as: Resp.self)
            try await completeSignIn(
                accessToken: resp.accessToken,
                refreshToken: resp.refreshToken,
                expiresIn: TimeInterval(resp.expiresIn)
            )
        } catch let err as SdkError {
            emit(.error(err))
        } catch {
            emit(
                .error(
                    SdkError(
                        code: .signInFailed,
                        reason: .unknown,
                        errorMessage: "sign_up_unknown"
                    )
                )
            )
        }
    }

    /// Complete sign-in after acquiring tokens from any flow (password, OAuth,
    /// MFA, magic link, OTP, device-code). Verifies the access token, persists
    /// the refresh token, emits `.authenticated`.
    public func completeSignIn(
        accessToken: String,
        refreshToken: String?,
        expiresIn: TimeInterval
    ) async throws {
        let now = adapter.now()
        let session = Session(
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresAt: now.addingTimeInterval(expiresIn),
            tenantId: configuration.tenantId
        )

        let user = try await verifyAndDecodeUser(token: accessToken)
        if let refresh = refreshToken {
            let res = await adapter.storageWrite(
                key: StorageKeys.refreshToken(tenantId: configuration.tenantId),
                value: refresh
            )
            if case .failed(let err) = res {
                // Surface the failure without blocking the sign-in; a storage
                // write failure is never swallowed silently.
                emit(.error(err))
            }
        }
        emit(.authenticated(user, session))
        eventContinuation.yield(.signedIn(user))
        eventContinuation.yield(.tokenRefreshed)
    }

    // MARK: - Refresh

    @discardableResult
    public func refresh(force: Bool) async throws -> Session {
        if let inflight = inFlightRefresh {
            return try await inflight.value
        }
        let task = Task { try await self.performRefresh() }
        inFlightRefresh = task
        defer { inFlightRefresh = nil }
        return try await task.value
    }

    private func performRefresh() async throws -> Session {
        let refreshKey = StorageKeys.refreshToken(tenantId: configuration.tenantId)
        guard let token = await adapter.storageRead(key: refreshKey) else {
            await clearSession(reason: .refreshExpired)
            throw SdkError(
                code: .refreshFailed,
                reason: .refreshExpired,
                errorMessage: "no_refresh_token"
            )
        }

        // ── DPoP-bound refresh path. A proof is attached IFF the session is
        //    bound (server last said `token_type == "DPoP"`). The single-flight guard
        //    in `refresh(force:)` is already set BEFORE this async signing begins
        //    (TOCTOU pin) so two concurrent refreshes never mint two jti / two
        //    rotations. A capable SDK facing a Bearer session falls through to the
        //    plain Bearer path below (no proof). ──
        if let dpopSession, await dpopSession.isBound {
            return try await performDpopRefresh(token: token, refreshKey: refreshKey, session: dpopSession)
        }

        struct Resp: Decodable {
            let accessToken: String
            let refreshToken: String?
            let expiresIn: Int
        }

        for attempt in 0...refreshBackoffSeconds.count {
            do {
                let (data, http) = try await httpClient.send(
                    method: "POST",
                    path: "/v1/auth/refresh",
                    body: ["refresh_token": token]
                )
                if (200..<300).contains(http.statusCode) {
                    captureClockSkew(from: http)
                    let resp = try JSONDecoder().decode(Resp.self, from: data)
                    let session = Session(
                        accessToken: resp.accessToken,
                        refreshToken: resp.refreshToken ?? token,
                        expiresAt: adapter.now().addingTimeInterval(TimeInterval(resp.expiresIn)),
                        tenantId: configuration.tenantId
                    )
                    if let newRefresh = resp.refreshToken {
                        _ = await adapter.storageWrite(key: refreshKey, value: newRefresh)
                    }
                    let user = try await verifyAndDecodeUser(token: resp.accessToken)
                    emit(.authenticated(user, session))
                    eventContinuation.yield(.tokenRefreshed)
                    return session
                }
                if http.statusCode == 401 || http.statusCode == 403 {
                    await clearSession(reason: .refreshRevoked)
                    throw SdkError(
                        code: .refreshFailed,
                        reason: .refreshRevoked,
                        errorMessage: "refresh_rejected"
                    )
                }
                // 5xx / network — fall through to backoff.
                if attempt < refreshBackoffSeconds.count {
                    try await Task.sleep(nanoseconds: UInt64(refreshBackoffSeconds[attempt] * 1_000_000_000))
                    continue
                }
                throw SdkError(
                    code: .refreshFailed,
                    reason: .refreshNetwork,
                    errorMessage: "refresh_5xx_\(http.statusCode)"
                )
            } catch let err as SdkError where err.reason == .refreshRevoked {
                throw err
            } catch {
                if attempt < refreshBackoffSeconds.count {
                    try await Task.sleep(nanoseconds: UInt64(refreshBackoffSeconds[attempt] * 1_000_000_000))
                    continue
                }
                throw SdkError(
                    code: .refreshFailed,
                    reason: .refreshNetwork,
                    errorMessage: "refresh_network"
                )
            }
        }
        throw SdkError(code: .refreshFailed, reason: .refreshNetwork, errorMessage: "refresh_exhausted")
    }

    /// DPoP-bound refresh: delegates the attach / nonce-retry / three-class taxonomy
    /// decision to `DpopRefresh`, then persists + verifies on success. Maps the
    /// distinct DPoP failure classes onto the controller's session lifecycle:
    /// `invalid_dpop_proof` and `invalid_refresh_token` both clear the session (the
    /// app must re-login to re-bind a fresh key); `dpop_prover_unavailable` and
    /// `network` are surfaced without clearing (transient — no silent Bearer call was
    /// ever made).
    private func performDpopRefresh(
        token: String,
        refreshKey: String,
        session: DpopSession
    ) async throws -> Session {
        let outcome = await DpopRefresh.refresh(
            transport: dpopTransport,
            refreshToken: token,
            tokenEndpoint: "/v1/auth/refresh",
            session: session
        )
        switch outcome {
        case .success(let tokens, _):
            let newSession = Session(
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken ?? token,
                expiresAt: adapter.now().addingTimeInterval(TimeInterval(tokens.expiresIn)),
                tenantId: configuration.tenantId
            )
            if let newRefresh = tokens.refreshToken {
                _ = await adapter.storageWrite(key: refreshKey, value: newRefresh)
            }
            let user = try await verifyAndDecodeUser(token: tokens.accessToken)
            emit(.authenticated(user, newSession))
            eventContinuation.yield(.tokenRefreshed)
            return newSession
        case .failure(let err):
            switch err.reason {
            case .invalidDpopProof, .invalidRefreshToken:
                await clearSession(reason: .refreshRevoked)
            default:
                // dpop_prover_unavailable / network — transient, keep the session.
                break
            }
            throw err
        }
    }

    private func captureClockSkew(from http: HTTPURLResponse) {
        guard let dateStr = http.value(forHTTPHeaderField: "Date"),
            let serverDate = httpDateFormatter.date(from: dateStr)
        else { return }
        let skew = Int(serverDate.timeIntervalSince(adapter.now()) * 1000)
        if abs(skew) <= Int(maxAcceptableClockSkew * 1000) {
            clockSkewMs = skew
        }
    }

    // MARK: - getToken

    public func getToken() async throws -> String {
        switch current {
        case .authenticated(_, let session):
            if session.isStale(now: adapter.now(), leadtime: defaultRefreshLeadtime) {
                let fresh = try await refresh(force: true)
                return fresh.accessToken
            }
            return session.accessToken
        case .loading:
            // Defer to hydration.
            await hydrate()
            return try await getToken()
        case .signedOut, .error:
            throw SdkError(code: .signInFailed, reason: .sessionExpired, errorMessage: "no_session")
        }
    }

    // MARK: - hasValidSession (offline-tolerant)

    public func hasValidSession() async -> Bool {
        switch current {
        case .authenticated(_, let session):
            if session.isStale(now: adapter.now(), leadtime: 0) { return false }
            // Verify against cached JWKS — offline-tolerant.
            do {
                _ = try await verifyAndDecodeUser(token: session.accessToken)
                return true
            } catch {
                return false
            }
        default:
            return false
        }
    }

    // MARK: - Sign-out

    public func signOut() async {
        // Best-effort revoke; never block local sign-out.
        if case .authenticated(_, let session) = current, let refresh = session.refreshToken {
            _ = try? await httpClient.post(
                path: "/v1/auth/logout",
                body: ["refresh_token": refresh],
                as: EmptyResponse.self
            )
        }
        await clearSession(reason: nil)
    }

    /// Clear ONLY this configuration's local state. Sibling configurations
    /// (different tenants) are unaffected.
    private func clearSession(reason: SdkErrorReason?) async {
        let refreshKey = StorageKeys.refreshToken(tenantId: configuration.tenantId)
        await adapter.storageDelete(key: refreshKey)
        await jwksCache.invalidate()
        emit(.signedOut)
        eventContinuation.yield(.signedOut(reason: reason))
    }

    // MARK: - JWT verify + user decode

    private func verifyAndDecodeUser(token: String) async throws -> User {
        let jwks = try await jwksCache.fetch(force: false)
        let now = adapter.now().addingTimeInterval(TimeInterval(clockSkewMs) / 1000)
        do {
            let verified = try JWTVerifier.verify(
                token: token,
                jwks: jwks,
                expectedIssuer: configuration.issuer,
                expectedAudience: configuration.audience,
                now: now
            )
            return verified.user
        } catch let err as SdkError where err.errorMessage == "jwks_kid_miss" {
            // ONE retry with forced JWKS refetch.
            let fresh = try await jwksCache.fetch(force: true)
            let verified = try JWTVerifier.verify(
                token: token,
                jwks: fresh,
                expectedIssuer: configuration.issuer,
                expectedAudience: configuration.audience,
                now: now
            )
            return verified.user
        }
    }

    private func fetchUserFromToken(_ token: String) async throws -> User {
        return try await verifyAndDecodeUser(token: token)
    }
}

private struct EmptyResponse: Decodable {}

private let httpDateFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "GMT")
    f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    return f
}()
