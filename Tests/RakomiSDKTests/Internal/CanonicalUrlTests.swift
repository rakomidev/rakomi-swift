// Golden-`htu` conformance. Asserts the Swift `CanonicalUrl.canonicalize` reproduces the SHARED
// `dpop-canonicalization-parity-vectors.json` (the server-aligned `@rakomi/node`
// oracle's fixture, copied into the test bundle) for every PRODUCTION-REACHABLE case.
//
// CANONICALIZATION DECISION (documented residual): the two IDN/Unicode-NFC vectors
// (`exämple.com` → `xn--…`, `café.com` → `xn--…`) are EXPLICITLY skipped — the frozen
// Rakomi issuer host is ASCII (`https://api.rakomi.com`), so an IDN host is
// structurally unreachable in production, and pulling a punycode/IDNA2008 dependency
// would violate the SDK's zero-production-dependency budget. The `@rakomi/node` oracle
// (WHATWG URL parser) covers those vectors.

import XCTest

@testable import RakomiSDK

final class CanonicalUrlTests: XCTestCase {

    private struct Vector: Decodable {
        let input: String
        let expectedCanonical: String
        let rule: String
    }

    /// Rules in the shared fixture that are IDN/Unicode — documented-skip on Swift.
    private let idnResidualRules: Set<String> = [
        "IDN to Punycode",
        "Unicode NFC + IDN",
    ]

    private func loadVectors() throws -> [Vector] {
        let bundle = Bundle.module
        guard
            let url = bundle.url(
                forResource: "dpop-canonicalization-parity-vectors",
                withExtension: "json",
                subdirectory: "Fixtures"
            )
                ?? bundle.url(
                    forResource: "Fixtures/dpop-canonicalization-parity-vectors",
                    withExtension: "json"
                )
                ?? bundle.url(forResource: "dpop-canonicalization-parity-vectors", withExtension: "json")
        else {
            throw XCTSkip("shared canonicalization fixture not found in test bundle")
        }
        struct Doc: Decodable { let cases: [Vector] }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Doc.self, from: data).cases
    }

    func testReachableGoldenHtuVectorsMatchSharedFixture() throws {
        let vectors = try loadVectors()
        XCTAssertGreaterThanOrEqual(vectors.count, 13, "fixture shrank — coverage regression")

        var asserted = 0
        var skipped = 0
        for v in vectors {
            if idnResidualRules.contains(v.rule) {
                // documented residual — see the file header.
                skipped += 1
                continue
            }
            let got = try CanonicalUrl.canonicalize(v.input)
            XCTAssertEqual(
                got,
                v.expectedCanonical,
                "rule '\(v.rule)': canonicalize(\(v.input)) → \(got), expected \(v.expectedCanonical)"
            )
            asserted += 1
        }
        XCTAssertEqual(skipped, 2, "expected exactly the 2 IDN/NFC residual vectors to be skipped")
        XCTAssertEqual(asserted, vectors.count - 2, "every non-IDN vector must be asserted")
    }

    // Spot-check the individually-load-bearing rules so a fixture refactor that drops
    // a vector still leaves an explicit regression net for the riskiest cases.

    func testLowercaseScheme() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("HTTPS://api.rakomi.com/oauth/token"),
            "https://api.rakomi.com/oauth/token"
        )
    }

    func testStripDefaultHttpsPort() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("https://api.rakomi.com:443/oauth/token"),
            "https://api.rakomi.com/oauth/token"
        )
    }

    func testStripQueryDefendsNextEvilReplay() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("https://api.rakomi.com/oauth/token?next=evil"),
            "https://api.rakomi.com/oauth/token"
        )
    }

    func testLowercasePercentEncodedHexNotDecoded() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("https://api.rakomi.com/oauth/token%2Fxyz"),
            "https://api.rakomi.com/oauth/token%2fxyz"
        )
    }

    func testResolveDotSegments() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("https://api.rakomi.com/oauth/./token"),
            "https://api.rakomi.com/oauth/token"
        )
    }

    func testCollapseRepeatedSlashes() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("https://api.rakomi.com//oauth//token"),
            "https://api.rakomi.com/oauth/token"
        )
    }

    func testRootPathPreserved() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("https://api.rakomi.com/"),
            "https://api.rakomi.com/"
        )
    }

    func testIPv6LiteralWithNonDefaultPortPreserved() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("https://[::1]:8443/oauth/token"),
            "https://[::1]:8443/oauth/token"
        )
    }

    func testCombinedNormalization() throws {
        XCTAssertEqual(
            try CanonicalUrl.canonicalize("HTTPS://API.RAKOMI.COM:443/oauth/token/?next=evil#x"),
            "https://api.rakomi.com/oauth/token"
        )
    }

    func testNonAbsoluteUrlThrows() {
        XCTAssertThrowsError(try CanonicalUrl.canonicalize("/oauth/token"))
        XCTAssertThrowsError(try CanonicalUrl.canonicalize("ftp://api.rakomi.com/x"))
    }
}
