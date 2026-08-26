// Publisher-webhook receiver verification (Standard Webhooks).
//
// ─── Irreducible Receiver Contract (the 5-point first-principles invariant — port this verbatim) ───
//  1. Verify over the EXACT received bytes joined `{webhook-id}.{webhook-timestamp}.{body}` — never a
//     re-serialized / re-encoded body. Sign over the raw body string as received on the wire.
//  2. Constant-time signature compare on the fixed 32 raw HMAC bytes — never a base64-string `==`.
//     (CryptoKit `HMAC<SHA256>.isValidAuthenticationCode` is constant-time by contract.)
//  3. HMAC-SHA256 is HARDCODED — never read an algorithm from input. `v1,` = HMAC-SHA256; non-`v1,`
//     entries are SKIPPED (forward-compat), but ZERO `v1,` candidates FAIL CLOSED (never "no candidates ⇒ ok").
//  4. Timestamp bounded BOTH ways (too-old AND too-new) and checked BEFORE the HMAC (cheap reject +
//     caps the HMAC-DoS surface). Parse as integer seconds; non-integer → missing/invalid, NOT "expired".
//  5. Secret is `rksec_<base64url>`; after stripping the prefix and base64url-decoding it MUST be exactly
//     32 bytes. The SECRET is base64url (-/_); the SIGNATURE is standard base64 (+//) — two alphabets.
//
// Mirrors `Internal/JWTVerify.swift` structure. Returns a Swift `Result` (not throwing) per the verify
// convention. No attacker-controlled input may crash (malformed base64, wrong-length sig, NaN ts → typed
// error). Error messages NEVER embed the secret, decoded key, or computed HMAC.

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Crypto)
import Crypto
#endif

/// Portable webhook-verify error. `rawValue` IS the cross-SDK conformance `error_class` (the shared
/// test-vector fixture maps each port's native error to this enum).
public enum WebhookVerifyError: String, Error, Sendable, Equatable, CaseIterable {
    case invalidSignature = "invalid_signature"
    case invalidSecret = "invalid_secret"
    case missingHeader = "missing_header"
    case timestampTooOld = "timestamp_too_old"
    case timestampTooNew = "timestamp_too_new"
    case invalidBody = "invalid_body"
}

/// Verified publisher-webhook delivery. `webhookId` is the stable at-least-once dedup key; `deliveryId`
/// is per-delivery diagnostics; `eventType` comes from the `X-Rakomi-Event` header (the body carries no
/// `type`); `payload` is the flat, verified metadata object.
public struct PublisherWebhookVerifiedData: Sendable, Equatable {
    public let webhookId: String
    public let deliveryId: String
    public let eventType: String
    public let timestamp: Int
    public let payload: [String: AnyClaim]
}

public enum WebhookVerifier {
    static let rksecPrefix = "rksec_"
    static let expectedKeyLength = 32
    public static let defaultTolerance = 300
    public static let maxTolerance = 600

    /// Case-insensitive header lookup (RFC 9110 §5.1).
    static func header(_ headers: [String: String], _ name: String) -> String? {
        let lower = name.lowercased()
        for (key, value) in headers where key.lowercased() == lower {
            return value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return nil
    }

    /// `rksec_` strip + base64url decode + 32-byte length validation. nil → invalid secret.
    static func deriveKey(_ secret: String) -> SymmetricKey? {
        let encoded = secret.hasPrefix(rksecPrefix) ? String(secret.dropFirst(rksecPrefix.count)) : secret
        guard let data = base64URLDecode(encoded), data.count == expectedKeyLength else { return nil }
        return SymmetricKey(data: data)
    }

    /// Raw generic verify (tenant + advanced use). `now` is injectable for deterministic tests.
    public static func verifyWebhook(
        body: Data,
        headers: [String: String],
        secret: String,
        tolerance: Int = defaultTolerance,
        now: Date = Date()
    ) -> Result<PublisherWebhookVerifiedData, WebhookVerifyError> {
        // 1. Required headers (empty signature is treated as missing — fail closed).
        guard let signature = header(headers, "webhook-signature"), !signature.isEmpty,
            let timestampStr = header(headers, "webhook-timestamp"),
            let webhookId = header(headers, "webhook-id"), !webhookId.isEmpty
        else {
            return .failure(.missingHeader)
        }

        // 2. Integer-seconds timestamp (non-integer → missing/invalid, never "expired").
        guard let timestamp = Int(timestampStr) else {
            return .failure(.missingHeader)
        }

        // 3. Freshness BOTH ways, BEFORE the HMAC.
        let diff = Int(now.timeIntervalSince1970) - timestamp
        if diff > tolerance { return .failure(.timestampTooOld) }
        if diff < -tolerance { return .failure(.timestampTooNew) }

        // 4. Derive + validate key.
        guard let key = deriveKey(secret) else { return .failure(.invalidSecret) }

        // 5. Signed content over the RAW received body bytes + the RAW timestamp string.
        guard let bodyString = String(data: body, encoding: .utf8) else { return .failure(.invalidBody) }
        let signedContent = "\(webhookId).\(timestampStr).\(bodyString)"
        let signedData = Data(signedContent.utf8)

        // 6. Multi-signature: try each `v1,` entry (rotation overlap + forward-compat). Skip non-`v1,`.
        //    Fail closed if ZERO `v1,` candidates. Constant-time MAC check on the fixed 32 bytes.
        var matched = false
        for entry in signature.split(separator: " ").map(String.init) {
            guard entry.hasPrefix("v1,") else { continue }  // skip v2,/etc. (forward-compat)
            let candidateB64 = String(entry.dropFirst(3))
            // SIGNATURE is standard base64 (+//) — distinct alphabet from the base64url secret.
            guard let candidate = Data(base64Encoded: candidateB64), candidate.count == expectedKeyLength else {
                continue  // malformed / wrong-length → non-match, never a crash
            }
            if HMAC<SHA256>.isValidAuthenticationCode(candidate, authenticating: signedData, using: key) {
                matched = true
                break
            }
        }
        guard matched else { return .failure(.invalidSignature) }

        // 7. Parse the verified body (after the signature matched).
        guard let payload = try? JSONDecoder().decode([String: AnyClaim].self, from: body) else {
            return .failure(.invalidBody)
        }

        let deliveryId = header(headers, "x-rakomi-delivery-id") ?? webhookId
        let eventType = header(headers, "x-rakomi-event") ?? ""
        return .success(
            PublisherWebhookVerifiedData(
                webhookId: webhookId,
                deliveryId: deliveryId,
                eventType: eventType,
                timestamp: timestamp,
                payload: payload
            )
        )
    }

    /// Recommended publisher entry point. Pre-binds the publisher tolerance (300 s, clamped ≤600) and
    /// REJECTS a non-`rksec_` secret outright (publisher secrets are always `rksec_`-prefixed — closes the
    /// legacy raw-UTF-8 downgrade path). Mirrors `@rakomi/node`'s `verifyPublisherWebhook`.
    public static func verifyPublisherWebhook(
        body: Data,
        headers: [String: String],
        secret: String,
        tolerance: Int = defaultTolerance,
        now: Date = Date()
    ) -> Result<PublisherWebhookVerifiedData, WebhookVerifyError> {
        guard secret.hasPrefix(rksecPrefix) else { return .failure(.invalidSecret) }
        let clamped = min(max(0, tolerance), maxTolerance)
        return verifyWebhook(body: body, headers: headers, secret: secret, tolerance: clamped, now: now)
    }
}
