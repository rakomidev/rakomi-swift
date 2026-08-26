// MFA TOTP step-up.
//
// TOTP code contract: exactly 6 numeric chars (regex `^\d{6}$`); leading
// zeros preserved; no whitespace trim.

import Foundation

public struct MFA: Sendable {
    public let controller: RakomiAuthController

    public init(controller: RakomiAuthController) {
        self.controller = controller
    }

    /// Validate TOTP code format BEFORE any API call. Mirrors RN/Flutter.
    public static func isValidTotpFormat(_ code: String) -> Bool {
        guard code.count == 6 else { return false }
        return code.allSatisfy { $0.isNumber && $0.isASCII }
    }

    public func verifyTotp(challengeId: String, code: String) async {
        await controller.emit(.loading)
        guard Self.isValidTotpFormat(code) else {
            await controller.emit(
                .error(
                    SdkError(
                        code: .invalidCredentials,
                        reason: .invalidCredentials,
                        errorMessage: "totp_format"
                    )
                )
            )
            return
        }
        struct Resp: Decodable {
            let accessToken: String
            let refreshToken: String?
            let expiresIn: Int
        }
        do {
            let body: [String: Any] = ["challenge_id": challengeId, "code": code]
            let httpClient = controller.httpClient
            let resp = try await httpClient.post(
                path: "/v1/auth/mfa/totp/verify",
                body: body,
                as: Resp.self
            )
            try await controller.completeSignIn(
                accessToken: resp.accessToken,
                refreshToken: resp.refreshToken,
                expiresIn: TimeInterval(resp.expiresIn)
            )
            await controller.emitEvent(.mfaChallengeVerified)
        } catch let err as SdkError {
            await controller.emit(.error(err))
        } catch {
            await controller.emit(
                .error(
                    SdkError(
                        code: .invalidCredentials,
                        reason: .invalidCredentials,
                        errorMessage: "totp_unknown"
                    )
                )
            )
        }
    }
}

public struct MfaStepUpRequiredError: Error, Sendable {
    public let challengeId: String
    public let availableMethods: [String]
}

public struct MfaStepUpUnavailableError: Error, Sendable {
    public let reason: String
}
