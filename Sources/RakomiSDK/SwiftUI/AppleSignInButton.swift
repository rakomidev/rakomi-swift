// Sign in with Apple button wrapping
// `SignInWithAppleButton` (SwiftUI built-in).

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

#if canImport(SwiftUI) && canImport(AuthenticationServices) && (os(iOS) || os(macOS) || os(visionOS) || os(tvOS) || os(watchOS))
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
public struct RakomiAppleSignInButton: View {
    @Environment(RakomiAuthEnvironment.self) private var env

    public init() {}

    public var body: some View {
        SignInWithAppleButton(.signIn) { request in
            request.requestedScopes = [.fullName, .email]
        } onCompletion: { result in
            Task { await handle(result) }
        }
        .signInWithAppleButtonStyle(.black)
        .frame(height: 44)
        .accessibilityIdentifier("rakomi.signInButton.apple.native")
    }

    private func handle(_ result: Result<ASAuthorization, Error>) async {
        guard let auth = env.auth else { return }
        switch result {
        case .failure(let error):
            // Every branch here used to `return` without emitting anything, so a
            // cancelled or failed Apple sheet left the app on the signed-out
            // screen with nothing to show and no way to tell the two apart.
            await auth.controller.emit(.error(Self.mapAuthorizationError(error)))
        case .success(let authorization):
            guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential else {
                await auth.controller.emit(
                    .error(
                        SdkError(
                            code: .providerError,
                            reason: .oauthProviderError,
                            errorMessage: "apple_credential_unexpected_type"
                        )
                    )
                )
                return
            }
            guard let identityToken = credential.identityToken,
                let idTokenString = String(data: identityToken, encoding: .utf8)
            else {
                await auth.controller.emit(
                    .error(
                        SdkError(
                            code: .providerError,
                            reason: .oauthProviderError,
                            errorMessage: "apple_identity_token_missing"
                        )
                    )
                )
                return
            }

            do {
                let httpClient = auth.controller.httpClient
                let resp = try await httpClient.post(
                    path: "/v1/auth/oauth/callback",
                    body: ["provider": "apple", "id_token": idTokenString],
                    as: APITokenResponse.self
                )
                try await auth.controller.completeSignIn(
                    from: resp,
                    fallbackReason: .signInFailed,
                    oauthClientId: nil
                )
            } catch let err as SdkError {
                await auth.controller.emit(.error(err))
            } catch {
                await auth.controller.emit(
                    .error(
                        SdkError(
                            code: .signInFailed,
                            reason: .unknown,
                            errorMessage: "apple_signin_unknown"
                        )
                    )
                )
            }
        }
    }

    /// Apple reports a dismissed sheet and a real failure through the same
    /// `Error`; the caller needs to tell them apart, so the two get distinct
    /// reasons rather than one opaque provider error.
    static func mapAuthorizationError(_ error: Error) -> SdkError {
        guard let authError = error as? ASAuthorizationError else {
            return SdkError(
                code: .providerError,
                reason: .oauthProviderError,
                errorMessage: "apple_signin_failed"
            )
        }
        // Not a `switch`: `ASAuthorizationError.Code` gains cases between SDK
        // releases and an exhaustive switch here stops compiling on the next
        // one. Cancellation is the branch a caller must be able to tell apart;
        // everything else is a provider error carrying its own code.
        if authError.code == .canceled {
            return SdkError(
                code: .oauthCallbackError,
                reason: .oauthUserCancelled,
                errorMessage: "apple_signin_cancelled"
            )
        }
        return SdkError(
            code: .providerError,
            reason: .oauthProviderError,
            errorMessage: "apple_signin_error_\(authError.code.rawValue)"
        )
    }
}
#endif
