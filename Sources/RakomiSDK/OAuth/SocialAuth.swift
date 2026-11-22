// Browser sign-in: RFC 8252 authorization-code with PKCE.
//
// The system browser goes to the authorization endpoint the server PUBLISHES
// (RFC 8414 discovery — the API host is not the host that renders the login
// page), comes back to this app's private-use redirect scheme, and the code is
// exchanged at the published token endpoint. `ASWebAuthenticationSession`
// intercepts the redirect; no in-app web view is involved, ever.

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

    private func performFlow(provider: SocialProvider?) async throws {
        let configuration = controller.configuration
        guard let clientId = configuration.clientId, !clientId.isEmpty else {
            // Fail closed and say which value is missing. Starting a browser on
            // a request the server must reject is worse than not starting one.
            throw SdkError(
                code: .invalidConfig,
                reason: .notConfigured,
                errorMessage: "oauth_client_id_missing"
            )
        }

        let metadata = try await controller.authorizationServerMetadata()
        let flow = try await controller.oauthStore.mint()

        guard
            var components = URLComponents(
                url: metadata.authorizationEndpoint,
                resolvingAgainstBaseURL: false
            )
        else {
            throw SdkError(
                code: .invalidConfig,
                reason: .notConfigured,
                errorMessage: "authorization_endpoint_unparseable"
            )
        }
        var items = components.queryItems ?? []
        items.append(contentsOf: [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "state", value: flow.state),
            URLQueryItem(name: "code_challenge", value: flow.challenge),
            URLQueryItem(name: "code_challenge_method", value: PKCE.challengeMethod),
            URLQueryItem(name: "scope", value: configuration.scope),
        ])
        if let provider {
            // A hint, not a requirement: the hosted page decides what it offers.
            items.append(URLQueryItem(name: "provider", value: provider.wire))
        }
        components.queryItems = items

        guard let authURL = components.url else {
            throw SdkError(
                code: .invalidConfig,
                reason: .invalidCredentials,
                errorMessage: "authorize_url_build_failed"
            )
        }

        let scheme = configuration.redirectURI.scheme ?? "rakomi"
        let result = await controller.adapter.launchSystemBrowser(url: authURL, callbackScheme: scheme)
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
            try await processCallback(
                callbackURL: callbackURL,
                oneTimeId: flow.oneTimeId,
                expectedState: flow.state
            )
        }
    }

    /// Start a browser sign-in with no provider hint — the hosted page offers
    /// whatever the tenant has configured.
    public func signIn() async {
        await controller.emit(.loading)
        do {
            try await performFlow(provider: nil)
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

        // RFC 9700 §4.4 — issuer mix-up defence.
        let configuration = controller.configuration
        if let iss = getter("iss"), iss != configuration.issuer.absoluteString {
            if iss.trimmingCharacters(in: ["/"]) != configuration.issuer.absoluteString.trimmingCharacters(in: ["/"]) {
                throw SdkError(
                    code: .oauthCallbackError,
                    reason: .oauthStateMismatch,
                    errorMessage: "iss_mismatch"
                )
            }
        }

        // Constant-time, single-use state validation.
        guard let stored = await controller.oauthStore.consume(oneTimeId: oneTimeId) else {
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

        guard let clientId = configuration.clientId, !clientId.isEmpty else {
            throw SdkError(
                code: .invalidConfig,
                reason: .notConfigured,
                errorMessage: "oauth_client_id_missing"
            )
        }

        // RFC 6749 §4.1.3 — form-encoded, at the published token endpoint.
        let metadata = try await controller.authorizationServerMetadata()
        let resp = try await controller.httpClient.postForm(
            url: metadata.tokenEndpoint,
            fields: [
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": stored.verifier,
                "redirect_uri": configuration.redirectURI.absoluteString,
                "client_id": clientId,
            ],
            as: APITokenResponse.self
        )
        // The session is this client's: it refreshes at the token endpoint with this client_id.
        try await controller.completeSignIn(from: resp, fallbackReason: .codeExchangeFailed, oauthClientId: clientId)
    }
}
