// DPoP session handle.
//
// Swift flavour of `@rakomi/node`'s + `@rakomi/react-native`'s `DpopSession`. Same
// single named contract across all four packages (hybrid (a)+(b), scored 16-vs-7 vs
// observe-only).
//
// A `DpopSession` bundles THREE things so "have a prover" ≡ "is bound" by
// construction (no separable prover + flag that can drift):
//
//   1. ONE prover (one keypair) per session. The SAME prover MUST serve issuance and
//      every refresh — the server binds `dpop_jkt` to the key it saw at issuance, so
//      a fresh keypair on refresh ⇒ `jkt` mismatch ⇒ 401 on every bound refresh (the
//      mass-lockout this design prevents). One `DpopSession` = one keypair = one bound
//      refresh lineage.
//
//   2. Bound-truth — re-confirmed from `token_type` on EVERY token
//      response. A proof is attached on refresh IFF the server's latest signal is
//      `token_type == "DPoP"` (case-sensitive), never from the SDK's own capability.
//      A capable SDK facing a Bearer session attaches NO proof.
//
//   3. A security-downgrade detector — a session that opted into DPoP but that the
//      server returned as `Bearer` is surfaced via `onDowngrade` / `isDowngraded`; it
//      never silently proceeds as Bearer.
//
// COLD-START: the keypair is session-scoped; a fresh `DpopSession`
// after an app restart has NOT observed a `DPoP` issuance, so `isBound` is `false`
// and refresh attaches NO proof. Against a server in `on` mode the proof-less refresh
// of an already-bound server session is rejected with the typed `invalid_dpop_proof`
// → the app re-logins to re-bind a fresh key. Deterministic key persistence across a
// restart is a separate, planned key-rotation change.

import Foundation

/// Reason a DPoP-requested session was downgraded to Bearer by the server.
public enum DpopDowngradeReason: String, Sendable, Equatable {
    /// The server returned `token_type: "Bearer"` for a session that presented a proof.
    case serverReturnedBearer = "server_returned_bearer"
}

/// Opaque, session-scoped DPoP binding handle. Create ONE per logged-in session,
/// pass it to the auth ceremony AND every refresh for that session. Never share an
/// instance across distinct sessions or across a refresh-token boundary.
///
/// An `actor` so bound-truth mutation is serialized without a separate lock — the
/// single-flight refresh guard in the controller plus this actor isolation keep two
/// concurrent refreshes from racing on `_bound`.
public actor DpopSession {
    private let prover: any DpopProver
    private let baseURL: String
    private let onDowngrade: (@Sendable (DpopDowngradeReason) -> Void)?

    private var _bound = false
    private var _downgraded = false
    private var _downgradeNotified = false
    private var _boundJkt: String?

    public init(
        prover: any DpopProver,
        baseURL: String,
        onDowngrade: (@Sendable (DpopDowngradeReason) -> Void)? = nil
    ) {
        self.prover = prover
        // Normalize away a trailing slash so `baseURL + path` never doubles it.
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.onDowngrade = onDowngrade
    }

    /// `true` once the server has confirmed (`token_type == "DPoP"`) that this
    /// session's key is sender-bound. The SDK attaches a refresh proof IFF this is
    /// `true`. Starts `false`.
    public var isBound: Bool { _bound }

    /// `true` if a session that presented a DPoP proof was returned as `Bearer`.
    public var isDowngraded: Bool { _downgraded }

    /// The committed RFC 7638 thumbprint (`jkt`) of the session keypair, once bound.
    public var boundJkt: String? { _boundJkt }

    /// Resolve a finished compact proof STRING for the given method + target URL using
    /// the session's single keypair. Canonicalizes the FULL target into the RFC 9449
    /// §4.3 `htu`, then delegates signing to the prover. `target` may be an absolute
    /// URL or a `baseURL`-relative path. The transport layer only ever receives the
    /// returned string, never the prover. May throw if the signer
    /// fails or the URL is non-canonicalizable; callers map that to
    /// `dpop_prover_unavailable` and MUST NOT fall back to a proof-less call.
    public func resolveProof(htm: String, target: String, nonce: String? = nil) async throws -> String {
        let absolute: String
        if let schemeRange = target.range(of: "://"),
            target[target.startIndex..<schemeRange.lowerBound].allSatisfy({
                $0.isLetter || $0.isNumber || $0 == "+" || $0 == "." || $0 == "-"
            }), !target.hasPrefix("/")
        {
            absolute = target
        } else {
            absolute = "\(baseURL)\(target)"
        }
        let htu = try CanonicalUrl.canonicalize(absolute)
        return try await prover.createProof(htm: htm, htu: htu, nonce: nonce)
    }

    /// RFC 7638 thumbprint of the session keypair.
    public func jktHint() async throws -> String {
        try await prover.jktHint()
    }

    /// Update bound-truth from a token response. Called after EVERY
    /// token response while a session is attached.
    ///
    /// - Parameters:
    ///   - tokenType: the `token_type` from the response (`"DPoP"` | `"Bearer"`).
    ///   - attachedProof: whether THIS call presented a DPoP proof (opted in).
    public func observeTokenType(_ tokenType: String?, attachedProof: Bool) async {
        if tokenType == "DPoP" {
            _bound = true
            _downgraded = false
            if _boundJkt == nil {
                _boundJkt = try? await prover.jktHint()
            }
            return
        }
        // Server signalled Bearer (or omitted token_type) — follow the server's
        // signal, never our own capability: the session is NOT bound.
        _bound = false
        if attachedProof {
            _downgraded = true
            if !_downgradeNotified {
                _downgradeNotified = true
                onDowngrade?(.serverReturnedBearer)
            }
        }
    }
}
