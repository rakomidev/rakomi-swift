// Surface naming + error reason parity vs
// RN AND Flutter.

import XCTest

@testable import RakomiSDK

final class ParityTests: XCTestCase {

    // MARK: - Fixture loading

    private func loadFixture(_ name: String) throws -> [String: Any] {
        let bundle = Bundle.module
        guard
            let url = bundle.url(forResource: name, withExtension: "json", subdirectory: "Fixtures")
                ?? bundle.url(forResource: "Fixtures/\(name)", withExtension: "json")
                ?? bundle.url(forResource: name, withExtension: "json")
        else {
            throw XCTSkip("Fixture \(name).json not found in test bundle")
        }
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: - Reason wire parity vs RN

    func testReasonWireParityVsRN() throws {
        let rn = try loadFixture("rn_sdk_surface")
        let rnReasons = Set((rn["errorReasons"] as? [String]) ?? [])
        let swiftReasons = Set(SdkErrorReason.allCases.map { $0.wire })

        // Every RN reason MUST exist on Swift side (hard fail — an RN-removed reason must not silently linger
        // in Swift). Note: 'rate_limited', 'invalid_credentials', 'mfa_*'
        // are present in both Swift and RN.
        for reason in rnReasons {
            XCTAssertTrue(
                swiftReasons.contains(reason),
                "RN reason '\(reason)' missing in Swift SdkErrorReason"
            )
        }
    }

    func testReasonWireParityVsFlutter() throws {
        let flutter = try loadFixture("flutter_sdk_surface")
        let flutterReasons = Set((flutter["errorReasons"] as? [String]) ?? [])
        let swiftReasons = Set(SdkErrorReason.allCases.map { $0.wire })

        for reason in flutterReasons {
            XCTAssertTrue(
                swiftReasons.contains(reason),
                "Flutter reason '\(reason)' missing in Swift SdkErrorReason"
            )
        }
    }

    func testCodeWireParityVsFlutter() throws {
        let flutter = try loadFixture("flutter_sdk_surface")
        let flutterCodes = Set((flutter["errorCodes"] as? [String]) ?? [])
        let swiftCodes = Set(SdkErrorCode.allCases.map { $0.wire })
        for code in flutterCodes {
            XCTAssertTrue(swiftCodes.contains(code), "Flutter code '\(code)' missing")
        }
    }

    // MARK: - Public surface mapping

    func testCoreTypesAreExported() {
        // Compile-time assertions — if any of these names rename or move,
        // the test target fails to compile.
        XCTAssertNotNil(SdkErrorReason.unknown.wire)
        XCTAssertNotNil(SdkErrorCode.unknown.wire)
        let _: AuthState = .loading
        let _: AuthEvent = .tokenRefreshed
        let _ = SocialProvider.google
        XCTAssertEqual(SocialProvider.allCases.count, 10)
    }

    func testAllSwiftReasonsHaveSnakeCaseWire() {
        for reason in SdkErrorReason.allCases {
            XCTAssertFalse(reason.wire.isEmpty)
            XCTAssertFalse(reason.wire.contains(" "))
            XCTAssertEqual(reason.wire, reason.wire.lowercased())
        }
    }

    func testAllSwiftCodesHaveUppercaseWire() {
        for code in SdkErrorCode.allCases {
            XCTAssertFalse(code.wire.isEmpty)
            XCTAssertEqual(code.wire, code.wire.uppercased())
        }
    }
}
