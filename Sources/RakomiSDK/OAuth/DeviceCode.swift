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

public struct DeviceCode: Sendable {
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

    func poll(start: DeviceAuthorizationStart) async {
        var interval = TimeInterval(start.interval)
        let deadline = Date().addingTimeInterval(TimeInterval(start.expiresIn))
        struct PollResp: Decodable {
            let accessToken: String?
            let refreshToken: String?
            let expiresIn: Int?
            let error: String?
        }
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
                    let resp = try JSONDecoder().decode(PollResp.self, from: data)
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
                        expiresIn: TimeInterval(expiresIn)
                    )
                    return
                }
                let payload = try? JSONDecoder().decode(PollResp.self, from: data)
                switch payload?.error {
                case "authorization_pending":
                    continue
                case "slow_down":
                    interval *= 2
                    continue
                case "access_denied":
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
                case "expired_token":
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
                default:
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
