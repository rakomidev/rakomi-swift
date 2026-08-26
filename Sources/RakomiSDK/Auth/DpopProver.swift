// Native CryptoKit DPoP prover (RFC 9449). Proof structure is identical across
// every Rakomi SDK.
//
// SECURITY:
//   - ES256 (P-256) ONLY. `alg` is the hardcoded constant `"ES256"`, NEVER derived
//     from a key, a token header, or any input. The closed alg set is the cross-port
//     baseline (Secure-Enclave-eligible).
//   - ONE keypair per prover instance (one per session). The keypair is generated
//     EAGERLY in `init` (NOT lazily on first call) so issuance and every refresh
//     share the same key — the server binds `dpop_jkt` to the key it saw at
//     issuance; a fresh key on refresh ⇒ `jkt` mismatch ⇒ 401 for the session.
//   - Where `SecureEnclave.isAvailable`, the private key lives in the Secure
//     Enclave and NEVER enters addressable heap. Where no Secure Enclave exists
//     (simulator, or a device without one) the prover falls back to an in-memory
//     `P256.Signing.PrivateKey`: ephemeral, never persisted to disk, and destroyed
//     when the prover is deallocated (logout / session end).
//   - The prover OWNS every security-relevant field: `jti` (CSPRNG `UUID()`, fresh
//     per call), `iat` (seconds NumericDate), `typ: "dpop+jwt"`, the PUBLIC-ONLY
//     `jwk` (asserted no `d`), and the pinned `alg`. The caller supplies ONLY
//     `htm`/`htu`/optional `nonce`. NO `ath` on the refresh proof (no access token
//     at the refresh endpoint — RFC 9449 §4.3).
//   - The proof JWT, the private key, the raw jwk, and the jti are NEVER logged.

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Crypto)
import Crypto
#endif

/// Input the SDK decision layer hands to the prover. The caller supplies ONLY the
/// canonical request binding + optional server nonce; it can never influence the
/// algorithm or inject claims.
public struct DpopProofInput: Sendable, Equatable {
    /// HTTP method of the bound request — `"POST"` for the refresh call.
    public let htm: String
    /// The ALREADY-canonical `htu` (RFC 9449 §4.3). The prover signs it verbatim and
    /// MUST NOT re-derive or mutate it.
    public let htu: String
    /// Optional RFC 9449 §8 server nonce, echoed into the proof on a retry.
    public let nonce: String?

    public init(htm: String, htu: String, nonce: String? = nil) {
        self.htm = htm
        self.htu = htu
        self.nonce = nonce
    }
}

/// Failure surfaced when the native signer is unavailable / throws. The SDK maps
/// this to `dpop_prover_unavailable` and makes NO proof-less network call (never a
/// silent Bearer downgrade).
public struct DpopProverError: Error, Equatable, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
}

/// The canonical cross-port prover contract. Async to mirror the RN/Flutter
/// contract (CryptoKit is synchronous, but the seam lets a future native-keystore
/// or bridge implementation be async without an API break).
public protocol DpopProver: Sendable {
    /// Build a compact-serialized DPoP-proof JWT for the bound request. MUST reject
    /// (throw, never return an empty string) if the signer is unavailable so the SDK
    /// surfaces `dpop_prover_unavailable`.
    func createProof(htm: String, htu: String, nonce: String?) async throws -> String
    /// RFC 7638 SHA-256 thumbprint of the public JWK. Resolves the SAME value for the
    /// life of the session's keypair (`jkt`-continuity cross-check).
    func jktHint() async throws -> String
}

extension DpopProver {
    /// Convenience overload mirroring the RN `createProof(input)` shape.
    public func createProof(_ input: DpopProofInput) async throws -> String {
        try await createProof(htm: input.htm, htu: input.htu, nonce: input.nonce)
    }
}

/// CryptoKit ES256 (P-256) DPoP prover. ONE keypair per instance, generated eagerly.
///
/// `@unchecked Sendable`: no shared MUTABLE Swift state — the signing key is
/// immutable after `init` and the `Signer` enum and `Data` coordinates are value
/// types; each `createProof` mints its own jti/iat locally. (Concurrent signing on
/// one Secure Enclave key relies on CryptoKit's internal serialization, which is not
/// proven here; in practice the controller's single-flight refresh guard makes
/// concurrent signing on one prover unlikely.)
public final class CryptoKitDpopProver: DpopProver, @unchecked Sendable {
    /// Pinned algorithm. NEVER derived from a key or input.
    public static let alg = "ES256"

    /// Erases the SE-vs-heap distinction behind a uniform sign + public-key API.
    private enum Signer {
        #if canImport(CryptoKit)
        case secureEnclave(SecureEnclave.P256.Signing.PrivateKey)
        #endif
        case inHeap(P256.Signing.PrivateKey)

        /// JOSE R‖S 64-byte raw signature over `data` (NOT the DER form).
        func signature(for data: Data) throws -> Data {
            switch self {
            #if canImport(CryptoKit)
            case .secureEnclave(let key):
                return try key.signature(for: data).rawRepresentation
            #endif
            case .inHeap(let key):
                return try key.signature(for: data).rawRepresentation
            }
        }

        /// The P-256 public key (`rawRepresentation` = 64 bytes: x‖y big-endian).
        var publicKey: P256.Signing.PublicKey {
            switch self {
            #if canImport(CryptoKit)
            case .secureEnclave(let key):
                return key.publicKey
            #endif
            case .inHeap(let key):
                return key.publicKey
            }
        }
    }

    private let signer: Signer
    /// Cached public-only JWK coordinates (x, y) — base64url-no-pad, 32 bytes each.
    private let jwkX: String
    private let jwkY: String
    /// Cached RFC 7638 thumbprint (stable for the prover's life).
    private let cachedJkt: String

    /// Whether this prover is backed by the Secure Enclave (vs the in-heap residual).
    /// Surfaced for tests to gate SE-specific assertions; carries NO key material.
    public let isSecureEnclaveBacked: Bool

    /// Generate the session keypair. `preferSecureEnclave: false` forces the in-heap
    /// path (used by tests to exercise the documented residual deterministically on
    /// headless CI where the Enclave is unavailable).
    public init(preferSecureEnclave: Bool = true) throws {
        var chosen: Signer
        var seBacked = false
        #if canImport(CryptoKit)
        if preferSecureEnclave && SecureEnclave.isAvailable {
            do {
                let key = try SecureEnclave.P256.Signing.PrivateKey()
                chosen = .secureEnclave(key)
                seBacked = true
            } catch {
                // SE present but key creation failed (entitlements / locked device) —
                // fall back to the documented in-heap residual rather than failing.
                chosen = .inHeap(P256.Signing.PrivateKey())
            }
        } else {
            chosen = .inHeap(P256.Signing.PrivateKey())
        }
        #else
        chosen = .inHeap(P256.Signing.PrivateKey())
        #endif

        let raw = chosen.publicKey.rawRepresentation
        // P-256 raw public key = 64 bytes: first 32 = x, last 32 = y (big-endian).
        guard raw.count == 64 else {
            throw DpopProverError("unexpected P-256 public key length \(raw.count)")
        }
        let x = base64URLEncode(raw.prefix(32))
        let y = base64URLEncode(raw.suffix(32))

        self.signer = chosen
        self.isSecureEnclaveBacked = seBacked
        self.jwkX = x
        self.jwkY = y
        // RFC 7638 thumbprint: SHA-256 of the canonical JWK with members in
        // lexicographic order, no whitespace: {"crv":"P-256","kty":"EC","x":..,"y":..}
        let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        self.cachedJkt = base64URLEncode(PKCE.sha256(Data(canonical.utf8)))
    }

    /// The PUBLIC-ONLY JWK dictionary. Member order here is irrelevant to the wire
    /// proof (it is encoded with sorted keys) — exposed for tests to assert no `d`.
    public func publicJwk() -> [String: String] {
        return ["kty": "EC", "crv": "P-256", "x": jwkX, "y": jwkY]
    }

    public func jktHint() async throws -> String {
        return cachedJkt
    }

    public func createProof(htm: String, htu: String, nonce: String?) async throws -> String {
        // ── Protected header — PUBLIC-ONLY jwk, pinned alg, dpop+jwt typ. ──
        let header: [String: Any] = [
            "typ": "dpop+jwt",
            "alg": Self.alg,
            "jwk": ["kty": "EC", "crv": "P-256", "x": jwkX, "y": jwkY],
        ]

        // ── Payload — `iat` in SECONDS (integer NumericDate, NOT ms), `jti` from
        //    CSPRNG-backed UUID (fresh per call), optional nonce. NO `ath`. ──
        var payload: [String: Any] = [
            "htm": htm,
            "htu": htu,
            "iat": Int(Date().timeIntervalSince1970),
            "jti": UUID().uuidString,
        ]
        if let nonce { payload["nonce"] = nonce }

        // Structured JOSE encoding with sorted keys (NEVER string-concatenate claim
        // values). `.sortedKeys` gives deterministic output; `.withoutEscapingSlashes`
        // keeps `htu` slashes literal (matches the node oracle's JSON.stringify).
        let headerJSON = try canonicalJSON(header)
        let payloadJSON = try canonicalJSON(payload)
        let signingInput = "\(base64URLEncode(headerJSON)).\(base64URLEncode(payloadJSON))"

        let signature: Data
        do {
            signature = try signer.signature(for: Data(signingInput.utf8))
        } catch {
            // Signer threw (Enclave locked, etc.) — surface as prover-unavailable;
            // the decision layer makes NO proof-less call.
            throw DpopProverError("dpop signer failed")
        }
        return "\(signingInput).\(base64URLEncode(signature))"
    }

    /// Deterministic JSON for the JOSE header/payload. Sorted keys + no slash escaping
    /// to match the cross-port byte shape.
    private func canonicalJSON(_ object: [String: Any]) throws -> Data {
        var options: JSONSerialization.WritingOptions = [.sortedKeys]
        if #available(iOS 13.0, macOS 10.15, tvOS 13.0, watchOS 6.0, *) {
            options.insert(.withoutEscapingSlashes)
        }
        return try JSONSerialization.data(withJSONObject: object, options: options)
    }
}
