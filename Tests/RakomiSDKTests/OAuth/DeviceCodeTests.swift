// RFC 8628 model validation.

import XCTest

@testable import RakomiSDK

final class DeviceCodeTests: XCTestCase {

    func testDeviceAuthorizationStartDecodes() throws {
        let json = #"""
            {
              "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
              "user_code": "WDJB-MJHT",
              "verification_uri": "https://dashboard.rakomi.com/device",
              "verification_uri_complete": "https://dashboard.rakomi.com/device?user_code=WDJB-MJHT",
              "expires_in": 1800,
              "interval": 5
            }
            """#
        let data = json.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(DeviceAuthorizationStart.self, from: data)
        XCTAssertEqual(decoded.userCode, "WDJB-MJHT")
        XCTAssertEqual(decoded.expiresIn, 1800)
        XCTAssertEqual(decoded.interval, 5)
    }

    func testDeviceAuthorizationStartHandlesMissingComplete() throws {
        let json = #"""
            {"device_code":"x","user_code":"AAAA","verification_uri":"https://r.test/d","expires_in":600,"interval":5}
            """#
        let data = json.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(DeviceAuthorizationStart.self, from: data)
        XCTAssertNil(decoded.verificationURIComplete)
    }

    func testDeviceCodeReasonsHaveDistinctWireValues() {
        let reasons: [SdkErrorReason] = [
            .deviceCodeAuthorizationPending, .deviceCodeSlowDown,
            .deviceCodeAccessDenied, .deviceCodeExpired,
        ]
        let wires = Set(reasons.map { $0.wire })
        XCTAssertEqual(wires.count, reasons.count)
        XCTAssertTrue(wires.contains("device_code_slow_down"))
        XCTAssertTrue(wires.contains("device_code_expired"))
    }

    func testDeviceCodeFlowConstants() {
        // These mirror RFC 8628 §3.1: interval default 5s, expires_in
        // typical ~30min. We don't hardcode them in the SDK (server-driven),
        // but we want a smoke check that the model accepts those ranges.
        let json =
            #"{"device_code":"d","user_code":"u","verification_uri":"https://r.test/d","expires_in":1800,"interval":5}"#
        let data = json.data(using: .utf8)!
        let decoded = try? JSONDecoder().decode(DeviceAuthorizationStart.self, from: data)
        XCTAssertEqual(decoded?.interval, 5)
    }
}
