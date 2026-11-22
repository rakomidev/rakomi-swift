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
    nonisolated let metadataCache: AuthorizationServerMetadataCache

    private var current: AuthState = .loading
    private var inFlightRefresh: Task<Session, Error>?
    private var clockSkewMs: Int = 0
    private var hydrated: Bool = false
    private var hydrationTask: Task<Void, Never>?
    /// Set when a hydration pass stopped at a denied biometric prompt, so the
    /// next `hydrate()` (typically from `unlockWithBiometric`) runs again.
    private var hydrationBlockedByBiometric: Bool = false
    /// When the biometric lock last succeeded. Only read while
    /// `configuration.requireBiometricUnlock` is on.
    private var lastBiometricUnlockAt: Date?
    /// Set only for the duration of `hydrateAfterBiometricUnlock()`, so the
    /// unlock prompt carries that hydration through even with a zero
    /// `freshAuthWindow`.
    private var pendingBiometricUnlock: Bool = false

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
    /// Delays between Bearer refresh attempts after a transient failure.
    private var refreshBackoff: [TimeInterval] = refreshBackoffSeconds
    /// While set and in the future, a refresh does not reach the network: the
    /// server asked for a pause with `Retry-After`, and the held transient error
    /// is returned instead.
    private var refreshNotBefore: Date?
    private var refreshHeldError: SdkError?
    /// Set when a hydration pass stopped at a transient refresh failure (the
    /// stored credential is kept), so the next `hydrate()` runs again.
    private var hydrationBlockedByTransientRefresh: Bool = false

    // One fan-out per surface. Reading `stateStream`/`eventStream` returns a
    // FRESH stream each time, so two consumers never split one sequence between
    // them — see Internal/Broadcaster.swift for what that used to cost.
    private nonisolated let stateBroadcaster = Broadcaster<AuthState>(
        replaysLatest: true,
        bufferSize: 8,
        initial: .loading
    )
    private nonisolated let eventBroadcaster = Broadcaster<AuthEvent>(
        replaysLatest: false,
        bufferSize: 64
    )

    /// A new subscription to the auth-state sequence, starting with the state
    /// that is current at the moment of subscription.
    public nonisolated var stateStream: AsyncStream<AuthState> { stateBroadcaster.subscribe() }

    /// A new subscription to the event sequence. Events are not replayed; a
    /// subscriber sees what happens from here on.
    public nonisolated var eventStream: AsyncStream<AuthEvent> { eventBroadcaster.subscribe() }

    public init(
        configuration: RakomiAuthConfiguration,
        adapter: any RakomiNativeAdapter
    ) {
        self.init(configuration: configuration, adapter: adapter, jwksSession: nil)
    }

    /// `jwksSession` replaces the pinned key-set session, `apiSession` the pinned
    /// API session (tests only).
    init(
        configuration: RakomiAuthConfiguration,
        adapter: any RakomiNativeAdapter,
        jwksSession: URLSession?,
        apiSession: URLSession? = nil
    ) {
        self.configuration = configuration
        self.adapter = adapter
        self.httpClient = HTTPClient(
            baseURL: configuration.apiBaseURL,
            publishableKey: configuration.publishableKey,
            certificateFingerprints: configuration.certificateFingerprints,
            session: apiSession
        )

        // KeychainStorage created here for OAuth state + JWKS cache.
        let storage = KeychainStorage(accessGroup: configuration.keychainAccessGroup)
        self.oauthStore = OAuthStateStore(storage: storage)
        self.metadataCache = AuthorizationServerMetadataCache(
            httpClient: self.httpClient,
            apiBaseURL: configuration.apiBaseURL
        )
        // The JWKS fetch MUST be pinned on the same fingerprints as the API
        // calls, so the session is passed in explicitly and never left to a
        // pinning-free default: a key set fetched over an unpinned connection
        // would make a forged token verify, defeating the point of pinning.
        self.jwksCache = JWKSCache(
            storage: storage,
            tenantId: configuration.tenantId,
            source: configuration.jwksURL.map { JWKSSource.url($0) }
                ?? .issuer(
                    configuration.issuer,
                    discoveryOrigin: IssuerDiscovery.discoveryOrigin(
                        for: configuration.issuer,
                        apiBaseURL: configuration.apiBaseURL
                    )
                ),
            session: jwksSession
                ?? makeRakomiURLSession(
                    certificateFingerprints: configuration.certificateFingerprints
                )
        )

    }

    // MARK: - Hydration

    /// Single hydration pass on cold start. Performs (1) fresh-install
    /// detection → (2) purge if needed → (3) hydration. Hydration MUST NOT
    /// run before purge.
    /// Restore a session from storage, once.
    ///
    /// A second caller AWAITS the first pass rather than returning early. It
    /// used to return the moment `hydrated` was set — before the first pass had
    /// produced a state — so `getToken()`, whose `loading` branch is
    /// "hydrate, then ask again", hydrated to a no-op, saw `loading` again and
    /// recursed. The call never returned, and an app that asked for a token
    /// while the provider was still mounting simply hung.
    public func hydrate() async {
        if let hydrationTask {
            await hydrationTask.value
            return
        }
        guard !hydrated else { return }
        hydrated = true
        let task = Task { await self.performHydration() }
        hydrationTask = task
        await task.value
        if hydrationBlockedByBiometric || hydrationBlockedByTransientRefresh {
            // A denied prompt or a transient refresh failure is not a settled
            // answer: let a later call retry.
            hydrationBlockedByBiometric = false
            hydrationBlockedByTransientRefresh = false
            hydrated = false
            hydrationTask = nil
        }
    }

    // MARK: - Biometric lock

    /// Hydrate after a successful biometric prompt obtained outside the
    /// controller (`RakomiAuth.unlockWithBiometric`). That prompt opens the
    /// fresh-auth window and satisfies the lock for this hydration, so the
    /// user is not prompted twice.
    func hydrateAfterBiometricUnlock() async {
        lastBiometricUnlockAt = adapter.now()
        pendingBiometricUnlock = true
        await hydrate()
        pendingBiometricUnlock = false
    }

    /// When `requireBiometricUnlock` is on, require a biometric success within
    /// `freshAuthWindow` before the stored credential is read or used. Throws a
    /// `biometricError` on any other outcome; the stored credential is kept.
    private func requireBiometricUnlockIfConfigured() async throws {
        guard configuration.requireBiometricUnlock else { return }
        if pendingBiometricUnlock {
            pendingBiometricUnlock = false
            return
        }
        let now = adapter.now()
        if let last = lastBiometricUnlockAt, now.timeIntervalSince(last) < configuration.freshAuthWindow {
            return
        }
        let result = await adapter.requestBiometric(reason: configuration.biometricPromptReason)
        switch result {
        case .success:
            lastBiometricUnlockAt = adapter.now()
        case .cancelled:
            throw SdkError(code: .biometricError, reason: .biometricCancelled, errorMessage: "biometric_cancelled")
        case .lockout:
            throw SdkError(code: .biometricError, reason: .biometricLockout, errorMessage: "biometric_lockout")
        case .notEnrolled:
            throw SdkError(code: .biometricError, reason: .biometricNotEnrolled, errorMessage: "biometric_not_enrolled")
        case .unavailable(let reason):
            throw SdkError(
                code: .biometricError,
                reason: .biometricUnavailable,
                errorMessage: reason ?? "biometric_unavailable"
            )
        }
    }

    private func performHydration() async {

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
        if await adapter.storageHas(key: refreshKey) {
            // Biometric lock: prompt before the credential is read. A denied
            // prompt leaves the credential in place and surfaces a typed error.
            do {
                try await requireBiometricUnlockIfConfigured()
            } catch {
                hydrationBlockedByBiometric = true
                emit(.error(error as? SdkError ?? SdkError(code: .biometricError, reason: .unknown)))
                return
            }
            // Try a refresh. A transient failure (the server is unavailable, or
            // asked for a pause) keeps the stored credential and surfaces the
            // typed error; the next `getToken()` hydrates again. Any other
            // failure surfaces signedOut.
            do {
                let session = try await refresh(force: false, biometricAlreadyChecked: true)
                let user = try await fetchUserFromToken(session.accessToken)
                emit(.authenticated(user, session))
                eventBroadcaster.yield(.signedIn(user))
            } catch let err as SdkError where RefreshFailure.keepsSession(err) {
                hydrationBlockedByTransientRefresh = true
                emit(.error(err))
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

    /// Replace the Bearer refresh backoff (tests only).
    func setRefreshBackoff(_ delays: [TimeInterval]) {
        refreshBackoff = delays
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

    /// The authorization server's published endpoints, fetched once per launch.
    public func authorizationServerMetadata() async throws -> AuthorizationServerMetadata {
        return try await metadataCache.metadata()
    }

    public func invalidateJWKS() async {
        await jwksCache.invalidate()
    }

    public func emit(_ state: AuthState) {
        current = state
        stateBroadcaster.yield(state)
    }

    public func emitEvent(_ event: AuthEvent) {
        eventBroadcaster.yield(event)
    }

    // MARK: - Sign-in primitives

    public func signInPassword(email: String, password: String) async {
        emit(.loading)
        do {
            let body: [String: Any] = ["email": email, "password": password]
            let resp = try await httpClient.post(
                path: "/v1/auth/login",
                body: body,
                as: APITokenResponse.self
            )
            // The tenant wants a second factor: no tokens in this branch, only
            // the challenge token to hand back to `verifyMfa`.
            if resp.nextStep == APINextStep.mfaVerify {
                if let challengeToken = resp.mfaChallengeToken {
                    eventBroadcaster.yield(.mfaChallengeRequired(challengeId: challengeToken))
                }
                emit(
                    .error(
                        SdkError(
                            code: .mfaStepUpRequired,
                            reason: .mfaStepUpRequired,
                            errorMessage: APINextStep.mfaVerify
                        )
                    )
                )
                return
            }
            // `authenticated` and `mfa_setup_required` both carry a session —
            // the second one additionally asks the app to enrol a factor before
            // a deadline, which is the app's business, not the SDK's.
            try await completeSignIn(from: resp, fallbackReason: .signInFailed, oauthClientId: nil)
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

    /// Register an account.
    ///
    /// Registration does not sign anyone in: the API answers with a message and
    /// the account has to verify its email address first, so the state after a
    /// successful call is `signedOut`, not `authenticated`. Call `signIn` once
    /// the address is verified.
    ///
    /// `consent` is required by the API and has no default here on purpose. It
    /// records that this person agreed to the tenant's terms, which is an act
    /// the application witnesses and the SDK cannot perform on their behalf.
    public func signUp(email: String, password: String, consent: Bool) async {
        emit(.loading)
        do {
            let body: [String: Any] = ["email": email, "password": password, "consent": consent]
            _ = try await httpClient.post(
                path: "/v1/auth/register",
                body: body,
                as: APIRegisterResponse.self
            )
            emit(.signedOut)
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
    ///
    /// `oauthClientId` names the OAuth client the tokens were issued to: the
    /// `client_id` of an authorization-code (browser) exchange at the token
    /// endpoint. Pass `nil` for tokens from a first-party `/v1/auth/*` endpoint
    /// (password, MFA, magic link, OTP, native Apple, device code). The server
    /// refreshes a client's session only at the token endpoint with that
    /// `client_id`, so a wrong value here ends the session at its first refresh.
    public func completeSignIn(
        accessToken: String,
        refreshToken: String?,
        expiresIn: TimeInterval,
        oauthClientId: String?
    ) async throws {
        let now = adapter.now()
        let session = Session(
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresAt: now.addingTimeInterval(expiresIn),
            tenantId: configuration.tenantId
        )

        let user = try await verifyAndDecodeUser(token: accessToken)
        await persistCredential(refreshToken: refreshToken, oauthClientId: oauthClientId)
        emit(.authenticated(user, session))
        eventBroadcaster.yield(.signedIn(user))
        eventBroadcaster.yield(.tokenRefreshed)
    }

    /// Store the refresh token and the client marker of a new session. The marker
    /// is written (or cleared) BEFORE the refresh token, so a stored refresh token
    /// is never paired with another session's marker; when the marker cannot be
    /// written the refresh token is not stored either (a client session refreshed
    /// at `/v1/auth/refresh` is refused), and the failure is surfaced.
    private func persistCredential(refreshToken: String?, oauthClientId: String?) async {
        let refreshKey = StorageKeys.refreshToken(tenantId: configuration.tenantId)
        let clientKey = StorageKeys.oauthClientId(tenantId: configuration.tenantId)
        await adapter.storageDelete(key: clientKey)
        guard let refresh = refreshToken else {
            await adapter.storageDelete(key: refreshKey)
            return
        }
        if let oauthClientId {
            if case .failed(let err) = await adapter.storageWrite(key: clientKey, value: oauthClientId) {
                await adapter.storageDelete(key: refreshKey)
                emit(.error(err))
                return
            }
        }
        let res = await adapter.storageWrite(key: refreshKey, value: refresh)
        if case .failed(let err) = res {
            // Surface the failure without blocking the sign-in; a storage
            // write failure is never swallowed silently.
            emit(.error(err))
        }
    }

    /// Complete sign-in from a token envelope, requiring the fields the
    /// envelope's own branch promises. A response that reached here without an
    /// access token is a contract violation, not a silent no-op.
    func completeSignIn(
        from response: APITokenResponse,
        fallbackReason: SdkErrorCode,
        oauthClientId: String?
    ) async throws {
        guard let accessToken = response.accessToken, let expiresIn = response.expiresIn else {
            throw SdkError(
                code: fallbackReason,
                reason: .invalidCredentials,
                errorMessage: "token_response_incomplete"
            )
        }
        try await completeSignIn(
            accessToken: accessToken,
            refreshToken: response.refreshToken,
            expiresIn: TimeInterval(expiresIn),
            oauthClientId: oauthClientId
        )
    }

    // MARK: - Refresh

    @discardableResult
    public func refresh(force: Bool) async throws -> Session {
        return try await refresh(force: force, biometricAlreadyChecked: false)
    }

    /// `biometricAlreadyChecked` is true only when the caller has just passed
    /// the biometric lock itself (hydration), so one cold start prompts once.
    private func refresh(force: Bool, biometricAlreadyChecked: Bool) async throws -> Session {
        if let inflight = inFlightRefresh {
            return try await inflight.value
        }
        let task = Task { try await self.performRefresh(biometricAlreadyChecked: biometricAlreadyChecked) }
        inFlightRefresh = task
        defer { inFlightRefresh = nil }
        return try await task.value
    }

    private func performRefresh(biometricAlreadyChecked: Bool) async throws -> Session {
        // Retry-After: inside the server's requested pause, nothing reaches the
        // network — not even a biometric prompt.
        if let notBefore = refreshNotBefore, let held = refreshHeldError {
            if adapter.now() < notBefore { throw held }
            refreshNotBefore = nil
            refreshHeldError = nil
        }
        do {
            let session = try await performRefreshAttempt(biometricAlreadyChecked: biometricAlreadyChecked)
            refreshNotBefore = nil
            refreshHeldError = nil
            return session
        } catch let err as SdkError {
            if RefreshFailure.keepsSession(err), let retryAfter = err.retryAfter, retryAfter > 0 {
                refreshNotBefore = adapter.now().addingTimeInterval(min(retryAfter, RefreshFailure.maxRetryAfter))
                refreshHeldError = err
            }
            throw err
        }
    }

    private func performRefreshAttempt(biometricAlreadyChecked: Bool) async throws -> Session {
        // Biometric lock: prompt BEFORE the stored credential is read.
        if !biometricAlreadyChecked {
            try await requireBiometricUnlockIfConfigured()
        }
        let refreshKey = StorageKeys.refreshToken(tenantId: configuration.tenantId)
        guard let token = await adapter.storageRead(key: refreshKey) else {
            await clearSession(reason: .refreshExpired)
            throw SdkError(
                code: .refreshFailed,
                reason: .refreshExpired,
                errorMessage: "no_refresh_token"
            )
        }

        // A session issued to an OAuth client refreshes at the token endpoint with
        // its client_id; every other session at /v1/auth/refresh.
        let endpoint = try await refreshEndpoint()

        // ── DPoP-bound refresh path. A proof is attached IFF the session is
        //    bound (server last said `token_type == "DPoP"`). The single-flight guard
        //    in `refresh(force:)` is already set BEFORE this async signing begins
        //    (TOCTOU pin) so two concurrent refreshes never mint two jti / two
        //    rotations. A capable SDK facing a Bearer session falls through to the
        //    plain Bearer path below (no proof). ──
        if let dpopSession, await dpopSession.isBound {
            return try await performDpopRefresh(
                token: token,
                refreshKey: refreshKey,
                endpoint: endpoint,
                session: dpopSession
            )
        }

        // Bearer path. Only a definitive rejection ends the session; a transient
        // failure keeps it (and the stored credential) and is retried with
        // backoff — unless the server sent `Retry-After`, which ends this round
        // at once and holds further attempts back until it elapses.
        for attempt in 0...refreshBackoff.count {
            let http: DpopRefreshHTTPResult
            do {
                http = try await dpopTransport.sendRefresh(refreshToken: token, endpoint: endpoint, dpopProof: nil)
            } catch {
                if attempt < refreshBackoff.count {
                    try await Task.sleep(nanoseconds: UInt64(refreshBackoff[attempt] * 1_000_000_000))
                    continue
                }
                throw RefreshFailure.transientError(
                    reason: .refreshNetwork,
                    message: "refresh_network",
                    httpStatus: nil,
                    retryAfter: nil
                )
            }
            if (200..<300).contains(http.statusCode) {
                captureClockSkew(dateHeader: http.serverDate)
                guard let resp = try? JSONDecoder().decode(APITokenResponse.self, from: http.body),
                    let accessToken = resp.accessToken, let expiresIn = resp.expiresIn
                else {
                    // A success the SDK cannot read: the server has consumed the
                    // presented refresh token. Presenting it again would be a
                    // reuse, which revokes every session of the user, so the
                    // session ends locally and the token is never re-sent.
                    await clearSession(reason: .refreshRevoked)
                    throw SdkError(
                        code: .refreshFailed,
                        reason: .refreshRevoked,
                        errorMessage: "refresh_response_unreadable",
                        httpStatus: http.statusCode
                    )
                }
                let session = Session(
                    accessToken: accessToken,
                    refreshToken: resp.refreshToken ?? token,
                    expiresAt: adapter.now().addingTimeInterval(TimeInterval(expiresIn)),
                    tenantId: configuration.tenantId
                )
                if let newRefresh = resp.refreshToken {
                    _ = await adapter.storageWrite(key: refreshKey, value: newRefresh)
                }
                // Not retried on failure: the server has already rotated the
                // token, so re-presenting the old one would be a reuse.
                let user = try await verifyAndDecodeUser(token: accessToken)
                emit(.authenticated(user, session))
                eventBroadcaster.yield(.tokenRefreshed)
                return session
            }
            if RefreshFailure.isDefinitiveRejection(
                status: http.statusCode,
                oauthError: RefreshFailure.oauthError(from: http.body)
            ) {
                await clearSession(reason: .refreshRevoked)
                throw SdkError(
                    code: .refreshFailed,
                    reason: .refreshRevoked,
                    errorMessage: "refresh_rejected",
                    httpStatus: http.statusCode
                )
            }
            if RefreshFailure.isTransientStatus(http.statusCode) {
                let retryAfter = RefreshFailure.parseRetryAfter(http.retryAfter, now: adapter.now())
                if retryAfter == nil, attempt < refreshBackoff.count {
                    try await Task.sleep(nanoseconds: UInt64(refreshBackoff[attempt] * 1_000_000_000))
                    continue
                }
                throw RefreshFailure.transientError(
                    reason: .refreshNetwork,
                    message: "refresh_transient_\(http.statusCode)",
                    httpStatus: http.statusCode,
                    retryAfter: retryAfter
                )
            }
            // Any other rejection (for example a 403 with no session-ending code,
            // which a proxy in front of the API can produce) does not prove the
            // session is over: it is kept, and not retried automatically.
            throw SdkError(
                code: .refreshFailed,
                reason: .unknown,
                errorMessage: "refresh_rejected_\(http.statusCode)",
                httpStatus: http.statusCode
            )
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
        endpoint: RefreshEndpoint,
        session: DpopSession
    ) async throws -> Session {
        let outcome = await DpopRefresh.refresh(
            transport: dpopTransport,
            refreshToken: token,
            endpoint: endpoint,
            session: session,
            now: adapter.now()
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
            eventBroadcaster.yield(.tokenRefreshed)
            return newSession
        case .failure(let err):
            switch err.reason {
            case .invalidDpopProof, .invalidRefreshToken:
                await clearSession(reason: .refreshRevoked)
            default:
                // dpop_prover_unavailable / network / a non-definitive rejection —
                // keep the session, the stored credential and the key binding.
                break
            }
            throw err
        }
    }

    /// Where the stored session refreshes: the token endpoint the server
    /// publishes, with the stored `client_id`, for a session issued to an OAuth
    /// client; `/v1/auth/refresh` otherwise. A metadata fetch that fails is
    /// transient: the session and the stored credential are kept.
    private func refreshEndpoint() async throws -> RefreshEndpoint {
        let clientKey = StorageKeys.oauthClientId(tenantId: configuration.tenantId)
        guard let clientId = await adapter.storageRead(key: clientKey), !clientId.isEmpty else {
            return .firstParty
        }
        do {
            let metadata = try await metadataCache.metadata()
            return .tokenEndpoint(metadata.tokenEndpoint, clientId: clientId)
        } catch {
            throw RefreshFailure.transientError(
                reason: .refreshNetwork,
                message: "authorization_server_metadata_unavailable",
                httpStatus: nil,
                retryAfter: nil
            )
        }
    }

    /// Seed the authorization-server metadata cache (tests only).
    func seedAuthorizationServerMetadata(_ metadata: AuthorizationServerMetadata) async {
        await metadataCache.seed(metadata)
    }

    private func captureClockSkew(dateHeader: String?) {
        guard let dateStr = dateHeader,
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
            // Hydration decides whether there is a session to hand back. It is
            // awaited, not re-entered: asking again from here is how this used
            // to loop forever.
            return try await tokenAfterHydration()
        case .error(let err) where err.code == .biometricError || RefreshFailure.keepsSession(err):
            // A hydration stopped at the biometric lock or at a transient refresh
            // failure: asking for a token runs hydration again (prompting, or
            // retrying the refresh once any Retry-After has elapsed).
            return try await tokenAfterHydration()
        case .signedOut, .error:
            throw SdkError(code: .signInFailed, reason: .sessionExpired, errorMessage: "no_session")
        }
    }

    private func tokenAfterHydration() async throws -> String {
        await hydrate()
        switch current {
        case .authenticated(_, let session):
            if session.isStale(now: adapter.now(), leadtime: defaultRefreshLeadtime) {
                return try await refresh(force: true).accessToken
            }
            return session.accessToken
        case .error(let err) where err.code == .biometricError || RefreshFailure.keepsSession(err):
            throw err
        default:
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

    /// End the session on the server (best effort, never blocking the local
    /// sign-out), then clear it locally.
    ///
    /// A session issued to an OAuth client revokes its refresh token at the
    /// published RFC 7009 revocation endpoint with its `client_id`, which ends
    /// the server session even after the access token has expired. A first-party
    /// session calls `POST /v1/auth/logout` with its access token (`DPoP` with
    /// a proof when the session is bound), the credential that route reads.
    public func signOut() async {
        if case .authenticated(_, let session) = current {
            let clientKey = StorageKeys.oauthClientId(tenantId: configuration.tenantId)
            if let clientId = await adapter.storageRead(key: clientKey), !clientId.isEmpty {
                if let refresh = session.refreshToken,
                    let metadata = try? await metadataCache.metadata(),
                    let revocationEndpoint = metadata.revocationEndpoint
                {
                    _ = try? await httpClient.sendForm(
                        url: revocationEndpoint,
                        fields: [
                            "token": refresh,
                            "token_type_hint": "refresh_token",
                            "client_id": clientId,
                        ]
                    )
                }
            } else {
                await logoutFirstParty(accessToken: session.accessToken)
            }
        }
        await clearSession(reason: nil)
    }

    private func logoutFirstParty(accessToken: String) async {
        var headers: [String: String] = ["Authorization": "Bearer \(accessToken)"]
        if let dpopSession, await dpopSession.isBound {
            guard let proof = try? await dpopSession.resolveProof(htm: "POST", target: "/v1/auth/logout") else {
                return
            }
            headers = ["Authorization": "DPoP \(accessToken)", "DPoP": proof]
        }
        _ = try? await httpClient.send(method: "POST", path: "/v1/auth/logout", extraHeaders: headers)
    }

    /// Clear ONLY this configuration's local state. Sibling configurations
    /// (different tenants) are unaffected.
    private func clearSession(reason: SdkErrorReason?) async {
        let refreshKey = StorageKeys.refreshToken(tenantId: configuration.tenantId)
        await adapter.storageDelete(key: refreshKey)
        await adapter.storageDelete(key: StorageKeys.oauthClientId(tenantId: configuration.tenantId))
        await jwksCache.invalidate()
        emit(.signedOut)
        eventBroadcaster.yield(.signedOut(reason: reason))
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

private let httpDateFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "GMT")
    f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    return f
}()
