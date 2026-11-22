// Swift publisher-webhook verifier.
//
// Primary test: the SHARED cross-SDK conformance vector loop (the same fixture @rakomi/node, Flutter, and
// React-Native load). A divergence between ports is itself a finding. Plus a focused negative matrix.

import XCTest

@testable import RakomiSDK

#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Crypto)
import Crypto
#endif

final class WebhookVerifyTests: XCTestCase {

    struct Expect: Decodable {
        let ok: Bool
        let error_class: String?
    }
    struct Vector: Decodable {
        let name: String
        let secret: String
        let body: String
        let headers: [String: String]
        let now_override: Int
        let tolerance: Int
        let expect: Expect
    }
    struct Fixture: Decodable {
        let vectors: [Vector]
    }

    private func loadVectors() throws -> [Vector] {
        let bundle = Bundle.module
        guard
            let url = bundle.url(
                forResource: "publisher-webhook-verify",
                withExtension: "json",
                subdirectory: "Fixtures"
            )
                ?? bundle.url(forResource: "Fixtures/publisher-webhook-verify", withExtension: "json")
                ?? bundle.url(forResource: "publisher-webhook-verify", withExtension: "json")
        else {
            throw XCTSkip("Fixture publisher-webhook-verify.json not found in test bundle")
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Fixture.self, from: data).vectors
    }

    func testSharedConformanceVectors() throws {
        let vectors = try loadVectors()
        XCTAssertGreaterThan(vectors.count, 15, "fixture should be comprehensive")

        for v in vectors {
            let now = Date(timeIntervalSince1970: Double(v.now_override))
            let result = WebhookVerifier.verifyPublisherWebhook(
                body: Data(v.body.utf8),
                headers: v.headers,
                secret: v.secret,
                tolerance: v.tolerance,
                now: now
            )

            switch result {
            case .success(let data):
                XCTAssertTrue(v.expect.ok, "vector \(v.name): expected failure, got success")
                XCTAssertFalse(data.webhookId.isEmpty, "vector \(v.name): webhookId must be present")
                XCTAssertEqual(data.payload.isEmpty, v.body == "{}", "vector \(v.name): payload parse")
            case .failure(let error):
                XCTAssertFalse(v.expect.ok, "vector \(v.name): expected success, got \(error.rawValue)")
                if let cls = v.expect.error_class {
                    XCTAssertEqual(error.rawValue, cls, "vector \(v.name): error_class mismatch")
                }
            }
        }
    }

    // ─── Focused per-SDK invariants (beyond the shared loop) ───

    private static let secret = "rksec_" + Data(repeating: 7, count: 32).base64URLEncodedString()
    private static let body = #"{"publisher_id":"p","correlation_id":"c","actor_axis":"tenant_admin"}"#

    private func sign(_ body: String, ts: Int, id: String, secretKey: Data) -> String {
        // standard-base64 HMAC-SHA256 over `{id}.{ts}.{body}` — mirrors the producer.
        let key = SymmetricKey(data: secretKey)
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data("\(id).\(ts).\(body)".utf8),
            using: key
        )
        return "v1," + Data(mac).base64EncodedString()
    }

    func testValidDeliveryVerifiesAndSurfacesDedupKey() {
        let ts = 1_700_000_000
        let key = Data(repeating: 7, count: 32)
        let sig = sign(Self.body, ts: ts, id: "wid_1", secretKey: key)
        let headers = [
            "webhook-id": "wid_1",
            "webhook-timestamp": String(ts),
            "webhook-signature": sig,
            "x-rakomi-delivery-id": "did_1",
            "x-rakomi-event": "app.uninstalled",
        ]
        let result = WebhookVerifier.verifyPublisherWebhook(
            body: Data(Self.body.utf8),
            headers: headers,
            secret: Self.secret,
            tolerance: 300,
            now: Date(timeIntervalSince1970: Double(ts))
        )
        guard case .success(let data) = result else { return XCTFail("expected success") }
        XCTAssertEqual(data.webhookId, "wid_1")
        XCTAssertEqual(data.deliveryId, "did_1")
        XCTAssertEqual(data.eventType, "app.uninstalled")
    }

    func testRejectsNonRksecSecret() {
        let headers = [
            "webhook-id": "wid_1",
            "webhook-timestamp": "1700000000",
            "webhook-signature": "v1,AAAA",
        ]
        let result = WebhookVerifier.verifyPublisherWebhook(
            body: Data(Self.body.utf8),
            headers: headers,
            secret: "raw-not-prefixed",
            tolerance: 300,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )
        guard case .failure(let e) = result else { return XCTFail("expected failure") }
        XCTAssertEqual(e, .invalidSecret)
    }

    func testWrongLengthDecodedSigDoesNotCrash() {
        let ts = 1_700_000_000
        // a 16-byte decoded signature (valid base64) → invalid_signature, never a crash.
        let shortSig = "v1," + Data(repeating: 1, count: 16).base64EncodedString()
        let headers = [
            "webhook-id": "wid_1", "webhook-timestamp": String(ts), "webhook-signature": shortSig,
        ]
        let result = WebhookVerifier.verifyPublisherWebhook(
            body: Data(Self.body.utf8),
            headers: headers,
            secret: Self.secret,
            tolerance: 300,
            now: Date(timeIntervalSince1970: Double(ts))
        )
        guard case .failure(let e) = result else { return XCTFail("expected failure") }
        XCTAssertEqual(e, .invalidSignature)
    }
}

// Local base64url helper for the fixed test key (mirrors the package's base64URLEncode).
extension Data {
    fileprivate func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
