// RFC 8628 device authorization grant
// (tvOS-only flow).

import Foundation

public struct DeviceAuthorizationStart: Sendable, Decodable, Equatable {
    public let deviceCode: String
    public let userCode: String
    public let verificationURI: String
    public let verificationURIComplete: String?
    public let expiresIn: Int
    public let interval: Int

    enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationURI = "verification_uri"
        case verificationURIComplete = "verification_uri_complete"
        case expiresIn = "expires_in"
        case interval
    }
}

/// What a non-2xx answer of `/v1/auth/oauth/device/token` means for the
/// polling loop. The route is a `/v1/*` route, so its RFC 8628 §3.5 polling
/// states arrive as RFC 9457 problem+json with HTTP 400 and the state in the
/// `code` member (`oauth/authorization_pending`, `oauth/slow_down`,
/// `oauth/access_denied`, `oauth/expired_token`); there is no `error` member.
enum DevicePollAnswer: Equatable {
    case pending
    case slowDown
    case denied
    case expired
    case unexpected
}

private struct DevicePollProblem: Decodable {
    let code: String?
}

public struct DeviceCode: Sendable {
    /// RFC 8628 §3.5: every `slow_down` answer raises the polling interval
    /// by 5 seconds for this and all later polls.
    static let slowDownIncrement: TimeInterval = 5

    public let controller: RakomiAuthController

    public init(controller: RakomiAuthController) {
        self.controller = controller
    }

    /// Begin device authorization flow. Returns the user-facing data
    /// (code + verification URI) and starts the polling loop. The polling
    /// task transitions `authStateChanges` to `.authenticated(...)` on
    /// approval.
    public func start() async throws -> DeviceAuthorizationStart {
        let configuration = controller.configuration
        let httpClient = controller.httpClient
        let body: [String: Any] = ["publishable_key": configuration.publishableKey]
        let started = try await httpClient.post(
            path: "/v1/auth/oauth/device/authorize",
            body: body,
            as: DeviceAuthorizationStart.self
        )
        Task { await self.poll(start: started) }
        return started
    }

    /// Reads a non-2xx polling answer by the route's RFC 9457 `code` member.
    static func pollAnswer(statusCode: Int, body: Data) -> DevicePollAnswer {
        guard statusCode == 400,
            let problem = try? JSONDecoder().decode(DevicePollProblem.self, from: body)
        else { return .unexpected }
        switch problem.code {
        case "oauth/authorization_pending": return .pending
        case "oauth/slow_down": return .slowDown
        case "oauth/access_denied": return .denied
        case "oauth/expired_token": return .expired
        default: return .unexpected
        }
    }

    func poll(start: DeviceAuthorizationStart) async {
        var interval = TimeInterval(start.interval)
        let deadline = Date().addingTimeInterval(TimeInterval(start.expiresIn))
        let httpClient = controller.httpClient
        let configuration = controller.configuration

        while Date() < deadline {
            do {
                try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                let body: [String: Any] = [
                    "device_code": start.deviceCode,
                    "publishable_key": configuration.publishableKey,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                ]
                let (data, http) = try await httpClient.send(
                    method: "POST",
                    path: "/v1/auth/oauth/device/token",
                    body: body
                )
                if (200..<300).contains(http.statusCode) {
                    let resp = try JSONDecoder().decode(APITokenResponse.self, from: data)
                    guard let access = resp.accessToken,
                        let expiresIn = resp.expiresIn
                    else {
                        await controller.emit(
                            .error(
                                SdkError(
                                    code: .codeExchangeFailed,
                                    reason: .deviceCodeAccessDenied,
                                    errorMessage: "device_token_response_incomplete"
                                )
                            )
                        )
                        return
                    }
                    try await controller.completeSignIn(
                        accessToken: access,
                        refreshToken: resp.refreshToken,
                        expiresIn: TimeInterval(expiresIn),
                        // The publishable-key device flow issues a first-party
                        // session (no OAuth client): it refreshes at /v1/auth/refresh.
                        oauthClientId: nil
                    )
                    return
                }
                switch Self.pollAnswer(statusCode: http.statusCode, body: data) {
                case .pending:
                    continue
                case .slowDown:
                    interval += Self.slowDownIncrement
                    continue
                case .denied:
                    await controller.emit(
                        .error(
                            SdkError(
                                code: .signInFailed,
                                reason: .deviceCodeAccessDenied,
                                errorMessage: "device_code_denied"
                            )
                        )
                    )
                    return
                case .expired:
                    await controller.emit(
                        .error(
                            SdkError(
                                code: .signInFailed,
                                reason: .deviceCodeExpired,
                                errorMessage: "device_code_expired"
                            )
                        )
                    )
                    return
                case .unexpected:
                    await controller.emit(
                        .error(
                            SdkError(
                                code: .signInFailed,
                                reason: .unknown,
                                errorMessage: "device_token_status_\(http.statusCode)"
                            )
                        )
                    )
                    return
                }
            } catch {
                // Network blip — keep polling within the deadline.
                continue
            }
        }
        await controller.emit(
            .error(
                SdkError(
                    code: .signInFailed,
                    reason: .deviceCodeExpired,
                    errorMessage: "device_code_deadline"
                )
            )
        )
    }
}
