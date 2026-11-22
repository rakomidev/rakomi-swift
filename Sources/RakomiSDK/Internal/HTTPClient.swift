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
        userAgent: String = rakomiUserAgent,
        session: URLSession? = nil
    ) {
        // `session` replaces the pinned session (tests only).
        if let session {
            self.session = session
        } else {
            self.session = makeRakomiURLSession(
                certificateFingerprints: certificateFingerprints,
                additionalHeaders: [
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    // The tenant-scoped publishable key travels as `X-API-Key`, the
                    // header the API reads and the one the other Rakomi SDKs send.
                    "X-API-Key": publishableKey,
                ]
            )
        }
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

    /// Form-encoded POST to an ABSOLUTE url.
    ///
    /// RFC 6749 §4.1.3 specifies the token request as
    /// `application/x-www-form-urlencoded`, and the token endpoint is discovered
    /// rather than derived — it need not sit on `baseURL`'s host — so this takes
    /// a whole URL and sets its own content type.
    func postForm<T: Decodable>(
        url: URL,
        fields: [String: String],
        as: T.Type
    ) async throws -> T {
        let (data, http) = try await sendForm(url: url, fields: fields)
        return try decode(data, status: http.statusCode, as: T.self)
    }

    /// Form-encoded POST to an ABSOLUTE url, returning the raw response for
    /// callers that classify it themselves (the token-endpoint refresh, RFC 7009
    /// revocation). `extraHeaders` carries a DPoP proof; its value is never logged.
    func sendForm(
        url: URL,
        fields: [String: String],
        extraHeaders: [String: String]? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(publishableKey, forHTTPHeaderField: "X-API-Key")
        if let extraHeaders {
            for (k, v) in extraHeaders { request.setValue(v, forHTTPHeaderField: k) }
        }
        if let traceparent = TraceContext.current {
            request.setValue(traceparent, forHTTPHeaderField: "traceparent")
        }
        request.httpBody = Data(Self.formEncode(fields).utf8)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let urlError as URLError {
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "url_error_\(urlError.code.rawValue)"
            )
        }
        guard let http = response as? HTTPURLResponse else {
            throw SdkError(code: .networkError, reason: .network, errorMessage: "non_http_response")
        }
        return (data, http)
    }

    /// `application/x-www-form-urlencoded`. Every character outside the RFC 3986
    /// unreserved set is percent-encoded, space included, which every form
    /// parser decodes; the `+`-for-space spelling is the other legal one and is
    /// not used here. Keys are sorted so the body is byte-stable and testable.
    static func formEncode(_ fields: [String: String]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return
            fields
            .sorted { $0.key < $1.key }
            .map { key, value in
                let k = key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key
                let v = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
                return "\(k)=\(v)"
            }
            .joined(separator: "&")
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
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let urlError as URLError {
            // Transport failures used to escape as bare `URLError`s. Every caller
            // catches `SdkError` and falls through to a generic "unknown" branch,
            // so an unreachable host, a rejected certificate and a timeout all
            // reported themselves as an unexplained sign-in failure. Map them
            // once, here, where the underlying code is still available.
            throw SdkError(
                code: .networkError,
                reason: .network,
                errorMessage: "url_error_\(urlError.code.rawValue)"
            )
        }
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

    /// `/v1/*` errors are RFC 9457 `application/problem+json`: `code`/`detail` at the top level of
    /// the body, endpoint-specific extras (e.g. `next_action`) nested under `details`.
    static func mapErrorStatus(status: Int, data: Data) -> SdkError {
        let payload = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        let code = payload?["code"] as? String
        let detail = payload?["detail"] as? String
        let details = payload?["details"] as? [String: Any]
        let nextAction = details?["next_action"] as? String
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
            let msg = detail ?? "forbidden"
            if (code ?? "").contains("mfa") {
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
        // Everything below carries the server's OWN error code and detail. They
        // used to be parsed and then dropped for every status but 403, so a
        // caller looking at a rejected request saw `http_400` and had no way to
        // learn which field the API refused.
        let described = [code, detail].compactMap { $0 }.joined(separator: ": ")
        return SdkError(
            code: .signInFailed,
            reason: .unknown,
            errorMessage: described.isEmpty ? "http_\(status)" : "http_\(status) \(described)"
        )
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
