// The wire contract of the first-party auth endpoints.
//
// Before these existed, every token-carrying response struct in the SDK declared
// camelCase properties with no CodingKeys and was decoded by a plain
// JSONDecoder, so a real snake_case body from the API decoded to nothing and
// every sign-in ended as `response_decode_failed`. Both polarities are asserted
// here: the shape the API actually sends MUST decode, and the camelCase shape
// the old structs assumed MUST NOT be mistaken for it.
//
// Fixture provenance: the bodies below are the response shapes the API's own
// published schema declares for POST /v1/auth/login, /v1/auth/refresh,
// /v1/auth/mfa/verify-login and the device-code token endpoint.

import XCTest

@testable import RakomiSDK

final class APIResponsesTests: XCTestCase {

    private func decode(_ json: String) throws -> APITokenResponse {
        return try JSONDecoder().decode(APITokenResponse.self, from: Data(json.utf8))
    }

    // MARK: - Should decode: the shape the API sends

    func testAuthenticatedLoginResponseDecodes() throws {
        let resp = try decode(
            """
            {"next_step":"authenticated","access_token":"header.payload.signature",
             "refresh_token":"v1.abc","expires_in":900,"token_type":"Bearer"}
            """
        )
        XCTAssertEqual(resp.nextStep, APINextStep.authenticated)
        XCTAssertEqual(resp.accessToken, "header.payload.signature")
        XCTAssertEqual(resp.refreshToken, "v1.abc")
        XCTAssertEqual(resp.expiresIn, 900)
        XCTAssertEqual(resp.tokenType, "Bearer")
        XCTAssertNil(resp.mfaChallengeToken)
    }

    func testMfaChallengeResponseDecodes() throws {
        let resp = try decode(
            """
            {"next_step":"mfa_verify","mfa_challenge_token":"chal_abc","expires_in":300,
             "available_methods":["totp"]}
            """
        )
        XCTAssertEqual(resp.nextStep, APINextStep.mfaVerify)
        XCTAssertEqual(resp.mfaChallengeToken, "chal_abc")
        XCTAssertNil(resp.accessToken, "the MFA branch carries no tokens")
    }

    func testMfaSetupRequiredResponseStillCarriesASession() throws {
        let resp = try decode(
            """
            {"next_step":"mfa_setup_required","grace_deadline_at":"2026-04-01T00:00:00.000Z",
             "access_token":"header.payload.signature","refresh_token":"v1.abc",
             "expires_in":900,"token_type":"Bearer"}
            """
        )
        XCTAssertEqual(resp.nextStep, APINextStep.mfaSetupRequired)
        XCTAssertEqual(resp.accessToken, "header.payload.signature")
    }

    func testDpopRefreshResponseDecodes() throws {
        let resp = try decode(
            """
            {"next_step":"authenticated","access_token":"a.b.c","refresh_token":"v1.def",
             "expires_in":900,"token_type":"DPoP"}
            """
        )
        XCTAssertEqual(resp.tokenType, "DPoP")
    }

    func testDeviceCodePendingResponseDecodes() throws {
        let resp = try decode(#"{"error":"authorization_pending"}"#)
        XCTAssertEqual(resp.error, "authorization_pending")
        XCTAssertNil(resp.accessToken)
    }

    func testRegisterResponseCarriesNoTokens() throws {
        let resp = try JSONDecoder().decode(
            APIRegisterResponse.self,
            from: Data(#"{"message":"Registration initiated — check email for verification"}"#.utf8)
        )
        XCTAssertFalse(resp.message.isEmpty)
        XCTAssertNil(resp.nextStep)
    }

    // MARK: - Should NOT decode: the shape the old structs assumed

    func testCamelCaseBodyYieldsNoTokens() throws {
        // A camelCase body is still valid JSON, so it does not throw — it decodes
        // to an envelope with nothing in it. That is the failure the SDK used to
        // hit from the other direction, and the reason the callers now require
        // the fields their branch promises instead of trusting the decode.
        let resp = try decode(
            """
            {"nextStep":"authenticated","accessToken":"a.b.c","refreshToken":"v1.abc",
             "expiresIn":900,"tokenType":"Bearer"}
            """
        )
        XCTAssertNil(resp.accessToken)
        XCTAssertNil(resp.refreshToken)
        XCTAssertNil(resp.expiresIn)
        XCTAssertNil(resp.nextStep)
    }

    func testDeviceAuthorizationStartRejectsCamelCase() throws {
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                DeviceAuthorizationStart.self,
                from: Data(
                    #"{"deviceCode":"d","userCode":"u","verificationURI":"https://x","expiresIn":600,"interval":5}"#
                        .utf8
                )
            ),
            "the device-authorization start is snake_case on the wire"
        )
    }

    func testDeviceAuthorizationStartDecodesSnakeCase() throws {
        let start = try JSONDecoder().decode(
            DeviceAuthorizationStart.self,
            from: Data(
                #"{"device_code":"d","user_code":"WDJB-MJHT","verification_uri":"https://example.test/device","expires_in":600,"interval":5}"#
                    .utf8
            )
        )
        XCTAssertEqual(start.userCode, "WDJB-MJHT")
        XCTAssertEqual(start.verificationURI, "https://example.test/device")
    }
}
