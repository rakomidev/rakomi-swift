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
        case .failure:
            // ASAuthorizationError values flow through the controller as a
            // generic provider error — Apple's SDK surfaces user-cancellation
            // as `.canceled`.
            return
        case .success(let authorization):
            guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
                let identityToken = credential.identityToken,
                let idTokenString = String(data: identityToken, encoding: .utf8)
            else { return }

            // Exchange Apple ID token via the existing OAuth callback endpoint.
            // Server-side accepts `provider=apple`.
            struct Resp: Decodable {
                let accessToken: String
                let refreshToken: String?
                let expiresIn: Int
            }
            do {
                let httpClient = auth.controller.httpClient
                let resp = try await httpClient.post(
                    path: "/v1/auth/oauth/callback",
                    body: ["provider": "apple", "id_token": idTokenString],
                    as: Resp.self
                )
                try await auth.controller.completeSignIn(
                    accessToken: resp.accessToken,
                    refreshToken: resp.refreshToken,
                    expiresIn: TimeInterval(resp.expiresIn)
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
}
#endif
