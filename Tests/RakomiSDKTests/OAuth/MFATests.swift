// MFA TOTP format guard.

import XCTest

@testable import RakomiSDK

final class MFATests: XCTestCase {

    func testValidTotpFormat() {
        XCTAssertTrue(MFA.isValidTotpFormat("012345"))
        XCTAssertTrue(MFA.isValidTotpFormat("000000"))
        XCTAssertTrue(MFA.isValidTotpFormat("999999"))
        XCTAssertTrue(MFA.isValidTotpFormat("123456"))
    }

    func testInvalidTotpFormat() {
        XCTAssertFalse(MFA.isValidTotpFormat(""))
        XCTAssertFalse(MFA.isValidTotpFormat("12345"))
        XCTAssertFalse(MFA.isValidTotpFormat("1234567"))
        XCTAssertFalse(MFA.isValidTotpFormat("12345a"))
        XCTAssertFalse(MFA.isValidTotpFormat("12 345"))
        XCTAssertFalse(MFA.isValidTotpFormat("abc123"))
        XCTAssertFalse(MFA.isValidTotpFormat("０１２３４５"))  // full-width digits rejected
    }

    func testLeadingZerosPreserved() {
        XCTAssertTrue(MFA.isValidTotpFormat("000123"))
        XCTAssertTrue(MFA.isValidTotpFormat("001234"))
    }

    func testStepUpErrorTypes() {
        let req = MfaStepUpRequiredError(challengeId: "ch_x", availableMethods: ["totp"])
        XCTAssertEqual(req.challengeId, "ch_x")
        let una = MfaStepUpUnavailableError(reason: "passwordless")
        XCTAssertEqual(una.reason, "passwordless")
    }
}
