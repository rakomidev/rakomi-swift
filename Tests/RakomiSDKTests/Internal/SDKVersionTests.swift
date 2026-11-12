// The version the SDK reports in its User-Agent is the version the SBOM
// declares for this release; a release bump that misses one of them fails here.

import Foundation
import XCTest

@testable import RakomiSDK

final class SDKVersionTests: XCTestCase {
    func testSDKVersionMatchesTheSBOMComponentVersion() throws {
        // #filePath is Tests/RakomiSDKTests/Internal/<this file>; the package root
        // is four levels up.
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(contentsOf: packageRoot.appendingPathComponent("sbom.cdx.json"))
        let sbom = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let metadata = try XCTUnwrap(sbom["metadata"] as? [String: Any])
        let component = try XCTUnwrap(metadata["component"] as? [String: Any])
        XCTAssertEqual(component["version"] as? String, rakomiSDKVersion)
        XCTAssertEqual(rakomiUserAgent, "RakomiSwiftSDK/\(rakomiSDKVersion)")
    }
}
