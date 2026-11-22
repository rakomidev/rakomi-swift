import XCTest

@testable import RakomiSDK

final class SocialProviderTests: XCTestCase {

    func testTenSocialProviders() {
        XCTAssertEqual(SocialProvider.allCases.count, 10)
    }

    func testWireValuesAreLowercase() {
        for p in SocialProvider.allCases {
            XCTAssertEqual(p.wire, p.wire.lowercased())
        }
    }

    func testDisplayNamesAreNonEmpty() {
        for p in SocialProvider.allCases {
            XCTAssertFalse(p.displayName.isEmpty)
        }
    }

    func testEUDIWalletExtensionFactory() {
        let eudi = SocialProviderExtension.eudiWallet
        XCTAssertEqual(eudi.wire, "eudi_wallet")
        XCTAssertEqual(eudi.displayName, "EUDI Wallet")
    }

    func testCodableRoundtrip() throws {
        let encoded = try JSONEncoder().encode(SocialProvider.google)
        let decoded = try JSONDecoder().decode(SocialProvider.self, from: encoded)
        XCTAssertEqual(decoded, .google)
    }
}
