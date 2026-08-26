// ONE long-lived URLSession per `RakomiAuthConfiguration`, never per call.
//
// Bridges W3C Trace Context: if the calling `Task` has a `traceparent`
// task-local value, propagate it as the `traceparent` header (opt-in).

import Foundation

/// Build a `URLSession` that honours `certificateFingerprints`.
///
/// EVERY session the SDK creates comes from here — this is the only place that
/// attaches the pinning delegate, and no API in the SDK takes a session it did
/// not build. `URLSession.shared` is not usable for a pinned session: it
/// carries no delegate, so it cannot enforce a pin.
///
/// `nil` or an empty fingerprint list means the integrator did not ask for
/// pinning, and the session uses default trust evaluation.
func makeRakomiURLSession(
    certificateFingerprints: [String]?,
    additionalHeaders: [String: String]? = nil
) -> URLSession {
    let config = URLSessionConfiguration.default
    config.timeoutIntervalForRequest = 15
    config.timeoutIntervalForResource = 30
    if let additionalHeaders {
        config.httpAdditionalHeaders = additionalHeaders
    }

    guard let fingerprints = certificateFingerprints, !fingerprints.isEmpty else {
        return URLSession(configuration: config)
    }
    let delegate = CertificatePinningDelegate(allowedFingerprints: fingerprints)
    return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
}

actor HTTPClient {
    let session: URLSession
    let baseURL: URL
    let publishableKey: String
    let userAgent: String

    init(
        baseURL: URL,
        publishableKey: String,
        certificateFingerprints: [String]? = nil,
        userAgent: String = rakomiUserAgent
    ) {
        self.session = makeRakomiURLSession(
            certificateFingerprints: certificateFingerprints,
            additionalHeaders: [
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Rakomi-Publishable-Key": publishableKey,
            ]
        )
        self.baseURL = baseURL
        self.publishableKey = publishableKey
        self.userAgent = userAgent
    }

    func post<T: Decodable>(
        path: String,
        body: [String: Any],
        bearer: String? = nil,
        as: T.Type
    ) async throws -> T {
        let (data, http) = try await sendRequest(method: "POST", path: path, body: body, bearer: bearer)
        return try decode(data, status: http.statusCode, as: T.self)
    }

    func get<T: Decodable>(
        path: String,
        bearer: String? = nil,
        as: T.Type
    ) async throws -> T {
        let (data, http) = try await sendRequest(method: "GET", path: path, body: nil, bearer: bearer)
        return try decode(data, status: http.statusCode, as: T.self)
    }

    /// Lower-level send returning (data, response) for callers that need
    /// the response headers (e.g. JWKS ETag, server `Date` for clock-skew).
    ///
    /// `extraHeaders` is additive — used by the DPoP refresh path to attach the
    /// `DPoP` proof header. The header
    /// VALUE (the proof JWT) is never logged.
    func send(
        method: String,
        path: String,
        body: [String: Any]? = nil,
        bearer: String? = nil,
        extraHeaders: [String: String]? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        return try await sendRequest(
            method: method,
            path: path,
            body: body,
            bearer: bearer,
            extraHeaders: extraHeaders
        )
    }

    private func sendRequest(
        method: String,
        path: String,
        body: [String: Any]?,
        bearer: String?,
        extraHeaders: [String: String]? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        let url = baseURL.appendingPathComponent(path.trimmingCharacters(in: ["/"]))
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        if let bearer { request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        if let extraHeaders {
            for (k, v) in extraHeaders { request.setValue(v, forHTTPHeaderField: k) }
        }
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        if let traceparent = TraceContext.current {
            request.setValue(traceparent, forHTTPHeaderField: "traceparent")
        }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw SdkError(code: .networkError, reason: .network, errorMessage: "non_http_response")
        }
        return (data, http)
    }

    private func decode<T: Decodable>(_ data: Data, status: Int, as: T.Type) throws -> T {
        if (200..<300).contains(status) {
            do {
                return try JSONDecoder().decode(T.self, from: data)
            } catch {
                throw SdkError(
                    code: .codeExchangeFailed,
                    reason: .invalidCredentials,
                    errorMessage: "response_decode_failed"
                )
            }
        }
        throw Self.mapErrorStatus(status: status, data: data)
    }

    static func mapErrorStatus(status: Int, data: Data) -> SdkError {
        let payload = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        let nextAction = payload?["next_action"] as? String
        if nextAction == "verify_mfa" {
            return SdkError(
                code: .mfaStepUpRequired,
                reason: .mfaStepUpRequired,
                errorMessage: "verify_mfa"
            )
        }
        if status == 401 {
            return SdkError(
                code: .signInFailed,
                reason: .invalidCredentials,
                errorMessage: "unauthorized"
            )
        }
        if status == 403 {
            let msg = payload?["error"] as? String ?? "forbidden"
            if msg.contains("mfa") {
                return SdkError(
                    code: .mfaStepUpUnavailable,
                    reason: .mfaStepUpUnavailable,
                    errorMessage: msg
                )
            }
            return SdkError(code: .signInFailed, reason: .invalidCredentials, errorMessage: msg)
        }
        if status == 429 {
            return SdkError(code: .rateLimited, reason: .rateLimited, errorMessage: "rate_limited")
        }
        if (500...599).contains(status) {
            return SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "server_error_\(status)"
            )
        }
        return SdkError(code: .signInFailed, reason: .unknown, errorMessage: "http_\(status)")
    }
}

/// Trace Context (W3C) bridge — opt-in. Consumer apps set
/// `TraceContext.$current.withValue("00-...")` before calling SDK methods;
/// the HTTP client adds the `traceparent` header.
///
/// Internal — not part of the public API surface today. The task-local
/// cannot be set from outside the module; re-exposing it is a non-breaking
/// MINOR bump once it is documented.
enum TraceContext {
    @TaskLocal static var current: String?
}

/// SHA-256 certificate pinning delegate.
final class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    /// Canonical form: lowercase hex of SHA-256(cert.der).
    let allowedFingerprints: Set<String>

    init(allowedFingerprints: [String]) {
        self.allowedFingerprints = Set(allowedFingerprints.compactMap(Self.normalise))
    }

    /// Accepts every form the published `certificateFingerprints` contract
    /// documents — base64 (the canonical one), hex, and hex with colons — and
    /// reduces them to one. Accepting only hex meant an integrator following
    /// the documented base64 format had EVERY pinned connection rejected,
    /// indistinguishable from an active MITM. The Flutter port already
    /// normalises all three.
    static func normalise(_ raw: String) -> String? {
        let trimmed = raw.replacingOccurrences(of: ":", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()
        if lower.count == 64, lower.allSatisfy({ $0.isHexDigit }) { return lower }
        if let data = Data(base64Encoded: Self.padBase64(trimmed)), data.count == 32 {
            return data.map { String(format: "%02x", $0) }.joined()
        }
        return nil
    }

    private static func padBase64(_ s: String) -> String {
        let pad = (4 - s.count % 4) % 4
        return s + String(repeating: "=", count: pad)
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        #if canImport(Security)
        // STEP 1 — default trust evaluation FIRST, and it is not optional.
        // Answering `.useCredential` REPLACES URLSession's own evaluation, so a
        // delegate that only compares a fingerprint has silently switched off
        // hostname verification, expiry and revocation for the pinned path.
        // Pinning is meant to NARROW what is accepted, never to widen it.
        guard SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // STEP 2 — pin the LEAF only. Index 0 of the chain is the server's own
        // certificate; the rest are the CAs that signed it. Accepting a match
        // anywhere in the chain turns a pin on an intermediate or root into
        // "any certificate that CA ever issues, for any hostname" — which is
        // the property pinning exists to remove. The Flutter SDK pins the leaf
        // (`SecureSocket.peerCertificate`), so this is also the parity fix.
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
            let leaf = chain.first
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let der = SecCertificateCopyData(leaf) as Data
        if allowedFingerprints.contains(sha256Hex(der).lowercased()) {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        #endif
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    private func sha256Hex(_ data: Data) -> String {
        return PKCE.sha256(data).map { String(format: "%02x", $0) }.joined()
    }
}
