// RFC 9449 §4.3 DPoP `htu` URL canonicalization.
//
// Every Rakomi SDK canonicalizes `htu` identically, and identically to the
// server, for all PRODUCTION-REACHABLE cases; a shared golden-`htu` vector is
// the cross-runtime conformance oracle.
//
// DRIFT CONSIDERATION: a divergence between the SDK's canonicalization and the
// server's makes valid proofs fail verification, so this implementation MUST NOT
// be changed in isolation. `CanonicalUrlTests` is the regression tripwire.
//
// WHY HAND-ROLLED, NOT `URL`/`URLComponents`: Foundation's URL parser normalizes
// percent-encoding, host case, and dot-segments inconsistently across platforms
// (and would NOT preserve `%2f` as-lowercased-but-not-decoded). A small explicit
// state machine is the only way to reproduce the WHATWG-URL-parser behaviour
// byte-for-byte.
//
// CANONICALIZATION SCOPE:
//   - REACHABLE here and asserted: lowercase scheme, lowercase host, strip default
//     port (:443 https /:80 http), strip fragment, strip query, strip trailing
//     slash on non-root path, lowercase percent-encoded hex (`%2F`→`%2f`), resolve
//     `.`/`..` dot segments, collapse repeated slashes, root path preserved, IPv6
//     literal with non-default port preserved.
//   - NOT performed: IDN → Punycode (`exämple.com` → `xn--…`) and Unicode-NFC.
//     Adding an IDNA2008 dependency would break the SDK's zero-production-
//     dependency budget. INTEGRATOR REQUIREMENT: configure an ASCII (already
//     punycoded) API host — the Rakomi platform host is ASCII.
//
// Canonicalization rules (RFC chain — RFC 9449 §4.3 → RFC 9110 §3.2 / §7.1 →
// RFC 3986 §6.2.2):
//   - lowercase scheme (RFC 3986 §6.2.2.1)
//   - lowercase host (RFC 3986 §6.2.2.1)
//   - strip default port (`:443` https, `:80` http) (RFC 3986 §6.2.3)
//   - strip fragment AND query (RFC 9449 §4.3 — defends `?next=evil.com` replay)
//   - resolve `.`/`..` segments (RFC 3986 §6.2.2.3)
//   - collapse repeated slashes (`//`)
//   - strip trailing slash on non-root path (RFC 3986 §6.2.2.3)
//   - lowercase percent-encoded hex (`%2F` → `%2f`) (RFC 3986 §6.2.2.2)

import Foundation

/// Error raised when a `htu` target cannot be canonicalized. Maps to a
/// `dpop_prover_unavailable` at the call site — a non-canonicalizable URL is a
/// programmer error, never a silent Bearer downgrade.
struct CanonicalizeUrlError: Error, Equatable, Sendable {
    enum Code: String, Sendable {
        case invalidUrl
        case unsupportedVersion
    }
    let code: Code
    let message: String
}

enum CanonicalUrl {
    /// Versioned so a future canonicalization change is an explicit opt-in, never a
    /// silent behaviour drift (mirrors the shared `version` option).
    static let version = "rfc9449-2023"

    /// Canonicalize an absolute http(s) URL into its RFC 9449 §4.3 `htu` form.
    /// Behaviourally identical across every Rakomi SDK for every
    /// production-reachable case (see file header). Throws `CanonicalizeUrlError`
    /// on a non-absolute / malformed input rather than returning a best-effort
    /// string — the caller MUST NOT proceed with a guessed `htu`.
    static func canonicalize(_ input: String, version: String = version) throws -> String {
        guard version == Self.version else {
            throw CanonicalizeUrlError(
                code: .unsupportedVersion,
                message: "unsupported canonicalize-url version: \(version)"
            )
        }

        // ── 1. Split off fragment, then query (both stripped). ──
        var s = input
        if let hashIdx = s.firstIndex(of: "#") {
            s = String(s[s.startIndex..<hashIdx])
        }
        if let qIdx = s.firstIndex(of: "?") {
            s = String(s[s.startIndex..<qIdx])
        }

        // ── 2. Scheme — must be present and http(s). Lowercased. ──
        guard let schemeSep = s.range(of: "://") else {
            throw CanonicalizeUrlError(code: .invalidUrl, message: "invalid url")
        }
        let scheme = String(s[s.startIndex..<schemeSep.lowerBound]).lowercased()
        guard scheme == "http" || scheme == "https" else {
            throw CanonicalizeUrlError(code: .invalidUrl, message: "invalid url")
        }
        let afterScheme = String(s[schemeSep.upperBound...])

        // ── 3. Split authority from path. Path begins at the first `/` that is
        //       NOT inside an IPv6 `[...]` literal. ──
        var authority = afterScheme
        var path = ""
        var inBracket = false
        for (offset, ch) in afterScheme.enumerated() {
            if ch == "[" {
                inBracket = true
            } else if ch == "]" {
                inBracket = false
            } else if ch == "/" && !inBracket {
                let idx = afterScheme.index(afterScheme.startIndex, offsetBy: offset)
                authority = String(afterScheme[afterScheme.startIndex..<idx])
                path = String(afterScheme[idx...])
                break
            }
        }
        if authority.isEmpty {
            throw CanonicalizeUrlError(code: .invalidUrl, message: "invalid url")
        }

        // ── 4. Authority → host + optional port. Reject userinfo (`@`) — the
        //       refresh endpoint never carries credentials in the URL. ──
        if authority.contains("@") {
            throw CanonicalizeUrlError(code: .invalidUrl, message: "invalid url")
        }
        let (host, port) = try splitHostPort(authority)
        // Reject an empty host (e.g. `https://:443/x`) — the `authority.isEmpty`
        // guard above does not catch a port-only authority. Throw rather than emit a
        // garbage `https:///path` htu (parity with the WHATWG `new URL` oracle, which
        // throws on an empty host).
        guard !host.isEmpty else {
            throw CanonicalizeUrlError(code: .invalidUrl, message: "invalid url")
        }

        // ── 5. Strip default port; lowercase host (NOT inside brackets is fine —
        //       hex IPv6 is already case-insensitive, and our reachable IPv6 vector
        //       is all-lowercase). ──
        var authorityOut = host.lowercased()
        if let port {
            let isDefault =
                (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
            if !isDefault {
                authorityOut += ":\(port)"
            }
        }

        // ── 6. Path normalization: lowercase percent-hex, resolve dot segments,
        //       collapse repeated slashes, strip non-root trailing slash. ──
        let normalizedPath = collapseAndTrim(resolveDotSegments(lowercasePercentHex(path)))

        return "\(scheme)://\(authorityOut)\(normalizedPath)"
    }

    // MARK: - Helpers

    /// Split `host[:port]` honoring an IPv6 `[...]` literal. The port (if any) is
    /// the run of digits after the FINAL `:` that is outside any bracket.
    private static func splitHostPort(_ authority: String) throws -> (host: String, port: String?) {
        if authority.hasPrefix("[") {
            // IPv6 literal: host is `[...]`, optional `:port` follows the `]`.
            guard let close = authority.firstIndex(of: "]") else {
                throw CanonicalizeUrlError(code: .invalidUrl, message: "invalid url")
            }
            let host = String(authority[authority.startIndex...close])
            let rest = String(authority[authority.index(after: close)...])
            if rest.isEmpty { return (host, nil) }
            guard rest.hasPrefix(":") else {
                throw CanonicalizeUrlError(code: .invalidUrl, message: "invalid url")
            }
            let port = String(rest.dropFirst())
            try validatePort(port)
            return (host, port)
        }
        guard let colon = authority.lastIndex(of: ":") else {
            return (authority, nil)
        }
        let host = String(authority[authority.startIndex..<colon])
        let port = String(authority[authority.index(after: colon)...])
        if port.isEmpty { return (host, nil) }
        try validatePort(port)
        return (host, port)
    }

    private static func validatePort(_ port: String) throws {
        guard !port.isEmpty, port.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            throw CanonicalizeUrlError(code: .invalidUrl, message: "invalid url")
        }
    }

    /// `%2F` → `%2f` (RFC 3986 §6.2.2.2 — percent-encoded hex normalized to
    /// lowercase). The literal already-decoded chars are untouched.
    private static func lowercasePercentHex(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        let chars = Array(s)
        var i = 0
        while i < chars.count {
            if chars[i] == "%", i + 2 < chars.count,
                chars[i + 1].isHexDigit, chars[i + 2].isHexDigit
            {
                out.append("%")
                out.append(Character(chars[i + 1].lowercased()))
                out.append(Character(chars[i + 2].lowercased()))
                i += 3
            } else {
                out.append(chars[i])
                i += 1
            }
        }
        return out
    }

    /// Resolve `.` and `..` segments (RFC 3986 §5.2.4 simplified for an absolute
    /// path). Preserves a leading `/` and a trailing slash marker so the
    /// collapse/trim step can apply the non-root rule afterwards.
    private static func resolveDotSegments(_ path: String) -> String {
        guard path.hasPrefix("/") else { return path }
        let hadTrailingSlash = path.count > 1 && path.hasSuffix("/")
        let rawSegments = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        var out: [String] = []
        for seg in rawSegments {
            if seg.isEmpty || seg == "." { continue }
            if seg == ".." {
                if !out.isEmpty { out.removeLast() }
                continue
            }
            out.append(seg)
        }
        var result = "/" + out.joined(separator: "/")
        if hadTrailingSlash && result != "/" { result += "/" }
        return result
    }

    /// Collapse repeated slashes (`//` → `/`) and strip a trailing slash on a
    /// non-root path. Root (`/`) is preserved.
    private static func collapseAndTrim(_ path: String) -> String {
        let normalizedPath = path.isEmpty ? "/" : path
        // Collapse runs of `/`.
        var collapsed = ""
        var lastWasSlash = false
        for ch in normalizedPath {
            if ch == "/" {
                if !lastWasSlash { collapsed.append(ch) }
                lastWasSlash = true
            } else {
                collapsed.append(ch)
                lastWasSlash = false
            }
        }
        if collapsed.count > 1 && collapsed.hasSuffix("/") {
            collapsed.removeLast()
        }
        return collapsed
    }
}
