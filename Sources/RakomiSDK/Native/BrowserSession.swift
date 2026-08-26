// ASWebAuthenticationSession orchestration.
//
// System browser ONLY (RFC 8252). This SDK never uses WKWebView for the
// auth flow.

import Foundation

#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

public final class BrowserSessionLauncher: NSObject, @unchecked Sendable {
    public override init() { super.init() }

    public func launch(url: URL, callbackScheme: String) async -> BrowserAuthSessionResult {
        #if canImport(AuthenticationServices) && (os(iOS) || os(macOS) || os(visionOS))
        return await withCheckedContinuation { (continuation: CheckedContinuation<BrowserAuthSessionResult, Never>) in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let callbackURL {
                    continuation.resume(returning: .success(callbackURL: callbackURL))
                    return
                }
                if let asError = error as? ASWebAuthenticationSessionError {
                    continuation.resume(returning: Self.mapASError(asError))
                    return
                }
                continuation.resume(
                    returning: .failed(
                        SdkError(
                            code: .oauthCallbackError,
                            reason: .oauthProviderError,
                            errorMessage: "browser_session_unknown_error"
                        )
                    )
                )
            }
            session.presentationContextProvider = self.presentationContext
            session.prefersEphemeralWebBrowserSession = false
            if !session.start() {
                continuation.resume(
                    returning: .failed(
                        SdkError(
                            code: .oauthCallbackError,
                            reason: .oauthProviderError,
                            errorMessage: "browser_session_start_failed"
                        )
                    )
                )
            }
        }
        #else
        _ = (url, callbackScheme)
        return .failed(
            SdkError(
                code: .oauthCallbackError,
                reason: .oauthProviderError,
                errorMessage: "browser_session_unavailable_platform"
            )
        )
        #endif
    }

    #if canImport(AuthenticationServices)
    static func mapASError(_ error: ASWebAuthenticationSessionError) -> BrowserAuthSessionResult {
        switch error.code {
        case .canceledLogin:
            return .cancelled
        case .presentationContextNotProvided, .presentationContextInvalid:
            return .failed(
                SdkError(
                    code: .oauthCallbackError,
                    reason: .oauthProviderError,
                    errorMessage: "presentation_context_missing"
                )
            )
        @unknown default:
            return .failed(
                SdkError(
                    code: .oauthCallbackError,
                    reason: .oauthProviderError,
                    errorMessage: "as_error_\(error.code.rawValue)"
                )
            )
        }
    }
    #endif

    // MARK: - Presentation context

    let presentationContext = PresentationContext()

    final class PresentationContext: NSObject, @unchecked Sendable {
        #if canImport(AuthenticationServices)
        // Conformance below in dedicated extension to avoid forcing
        // `import UIKit` on macOS.
        #endif
    }
}

#if canImport(AuthenticationServices) && os(iOS)
import UIKit

extension BrowserSessionLauncher.PresentationContext: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
            ?? ASPresentationAnchor()
    }
}
#elseif canImport(AuthenticationServices) && os(macOS)
import AppKit

extension BrowserSessionLauncher.PresentationContext: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return NSApplication.shared.windows.first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }
}
#elseif canImport(AuthenticationServices) && os(visionOS)
import UIKit

extension BrowserSessionLauncher.PresentationContext: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
            ?? ASPresentationAnchor()
    }
}
#endif
