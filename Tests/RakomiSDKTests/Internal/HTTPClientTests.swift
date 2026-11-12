import XCTest

@testable import RakomiSDK

final class HTTPClientTests: XCTestCase {

    func testMapErrorStatus401() {
        let err = HTTPClient.mapErrorStatus(status: 401, data: Data())
        XCTAssertEqual(err.code, .signInFailed)
    }

    func testMapErrorStatus429() {
        let err = HTTPClient.mapErrorStatus(status: 429, data: Data())
        XCTAssertEqual(err.code, .rateLimited)
        XCTAssertEqual(err.reason, .rateLimited)
    }

    func testMapErrorStatus500MapsToNetwork() {
        let err = HTTPClient.mapErrorStatus(status: 503, data: Data())
        XCTAssertEqual(err.code, .networkError)
    }

    func testMapErrorWithVerifyMfaPayload() throws {
        // RFC 9457 shape: `code`/`detail` at the top level, `next_action` nested under `details`
        // (see HTTPClient.mapErrorStatus's own doc comment: the API sends `next_action` inside
        // `details`).
        // This fixture used to place `next_action` at the TOP level — mapErrorStatus reads
        // `details?["next_action"]`, so the old shape never matched and this test silently asserted
        // the WRONG branch's fallback (401 → .signInFailed) passed for the wrong reason until this
        // was caught by a local `mise run swift:ci` run (compensating control for
        // story swift-sdk-ci-coverage-exit-condition — swift-sdk-pr-light is currently skipped on
        // every PR under MACOS_CI_ENABLED='release-only', so this regression would not have surfaced
        // in CI at all).
        let payload =
            #"{"code":"account_linking/mfa_required","detail":"MFA verification required before linking a new identity","details":{"next_action":"verify_mfa","challenge_id":"ch_x"}}"#
        let data = payload.data(using: .utf8)!
        let err = HTTPClient.mapErrorStatus(status: 401, data: data)
        XCTAssertEqual(err.code, .mfaStepUpRequired)
    }

    /// The publishable key has to arrive in the header the API actually reads.
    /// It used to be sent as `X-Rakomi-Publishable-Key`, a name nothing on the
    /// server side has ever looked at, so every first-party auth call came back
    /// 401 with `auth/missing_api_key` before the body was even considered.
    func testPublishableKeyTravelsInTheHeaderTheAPIReads() async {
        let client = HTTPClient(
            baseURL: URL(string: "https://api.example.test")!,
            publishableKey: "pk_test_header_probe"
        )
        let headers = await client.session.configuration.httpAdditionalHeaders ?? [:]

        // Substrate first: an empty header dictionary would satisfy the absence
        // assertion below for the wrong reason.
        XCTAssertEqual(headers["Content-Type"] as? String, "application/json")
        XCTAssertEqual(headers["X-API-Key"] as? String, "pk_test_header_probe")
        XCTAssertNil(headers["X-Rakomi-Publishable-Key"])
    }

    func testTraceContextTaskLocal() async {
        await TraceContext.$current.withValue("00-trace-id-01-01") {
            XCTAssertEqual(TraceContext.current, "00-trace-id-01-01")
        }
    }
}
