// ASWebAuthenticationSession orchestration
// for social sign-in.

import Foundation

public struct SocialAuth: Sendable {
    public let controller: RakomiAuthController

    public init(controller: RakomiAuthController) {
        self.controller = controller
    }

    public func signIn(provider: SocialProvider) async {
        await controller.emit(.loading)
        do {
            try await performFlow(provider: provider)
        } catch let err as SdkError {
            await controller.emit(.error(err))
        } catch {
            await controller.emit(
                .error(
                    SdkError(
                        code: .oauthCallbackError,
                        reason: .oauthProviderError,
                        errorMessage: "social_unknown_error"
                    )
                )
            )
        }
    }

    private func performFlow(provider: SocialProvider) async throws {
        let configuration = controller.configuration
        let oauthStore = controller.oauthStore

        // Mint state + PKCE.
        let flow = try await oauthStore.mint()

        // Build authorize URL.
        var components = URLComponents(
            url: configuration.apiBaseURL.appendingPathComponent("/v1/auth/oauth/start"),
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [
            URLQueryItem(name: "provider", value: provider.wire),
            URLQueryItem(name: "publishable_key", value: configuration.publishableKey),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "state", value: flow.state),
            URLQueryItem(name: "code_challenge", value: flow.challenge),
            URLQueryItem(name: "code_challenge_method", value: PKCE.challengeMethod),
            URLQueryItem(name: "ott", value: flow.oneTimeId),
        ]
        guard let authURL = components?.url else {
            throw SdkError(
                code: .invalidConfig,
                reason: .invalidCredentials,
                errorMessage: "authorize_url_build_failed"
            )
        }

        // Launch system browser; await callback URL.
        let scheme = configuration.redirectURI.scheme ?? "rakomi"
        let adapter = controller.adapter
        let result = await adapter.launchSystemBrowser(url: authURL, callbackScheme: scheme)
        switch result {
        case .cancelled:
            throw SdkError(
                code: .oauthCallbackError,
                reason: .oauthUserCancelled,
                errorMessage: "user_cancelled"
            )
        case .failed(let err):
            throw err
        case .success(let callbackURL):
            try await processCallback(callbackURL: callbackURL, oneTimeId: flow.oneTimeId, expectedState: flow.state)
        }
    }

    public func processCallback(callbackURL: URL, oneTimeId: String, expectedState: String) async throws {
        guard let comps = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false) else {
            throw SdkError(
                code: .oauthCallbackError,
                reason: .oauthMissingParams,
                errorMessage: "callback_url_unparseable"
            )
        }
        let items = comps.queryItems ?? []
        let getter: (String) -> String? = { name in items.first { $0.name == name }?.value }

        if let err = getter("error") {
            let reason: SdkErrorReason
            switch err {
            case "access_denied": reason = .oauthUserCancelled
            case "server_error", "temporarily_unavailable": reason = .oauthProviderError
            default: reason = .oauthProviderError
            }
            throw SdkError(
                code: .oauthCallbackError,
                reason: reason,
                errorMessage: getter("error_description") ?? err
            )
        }

        guard let code = getter("code"), let state = getter("state") else {
            throw SdkError(
                code: .oauthCallbackError,
                reason: .oauthMissingParams,
                errorMessage: "callback_missing_code_or_state"
            )
        }

        // RFC 9700 §4.4 — iss mix-up defense.
        let configuration = controller.configuration
        if let iss = getter("iss"), iss != configuration.issuer.absoluteString {
            // Allow trailing slash divergence.
            if iss.trimmingCharacters(in: ["/"]) != configuration.issuer.absoluteString.trimmingCharacters(in: ["/"]) {
                throw SdkError(
                    code: .oauthCallbackError,
                    reason: .oauthStateMismatch,
                    errorMessage: "iss_mismatch"
                )
            }
        }

        // Constant-time state validation.
        let oauthStore = controller.oauthStore
        guard let stored = await oauthStore.consume(oneTimeId: oneTimeId) else {
            throw SdkError(
                code: .oauthCallbackError,
                reason: .oauthStateMismatch,
                errorMessage: "state_not_found"
            )
        }
        if !constantTimeEquals(state, stored.state) || !constantTimeEquals(stored.state, expectedState) {
            throw SdkError(
                code: .oauthCallbackError,
                reason: .oauthStateMismatch,
                errorMessage: "state_mismatch"
            )
        }

        // Exchange code for tokens.
        struct TokenResp: Decodable {
            let accessToken: String
            let refreshToken: String?
            let expiresIn: Int
            let nextAction: String?
            let challengeId: String?
        }
        let body: [String: Any] = [
            "code": code,
            "code_verifier": stored.verifier,
            "redirect_uri": configuration.redirectURI.absoluteString,
            "state": state,
        ]
        let httpClient = controller.httpClient
        let resp = try await httpClient.post(
            path: "/v1/auth/oauth/callback",
            body: body,
            as: TokenResp.self
        )
        if resp.nextAction == "verify_mfa" {
            if let cid = resp.challengeId {
                await controller.emitEvent(.mfaChallengeRequired(challengeId: cid))
            }
            await controller.emit(
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
        try await controller.completeSignIn(
            accessToken: resp.accessToken,
            refreshToken: resp.refreshToken,
            expiresIn: TimeInterval(resp.expiresIn)
        )
    }
}
