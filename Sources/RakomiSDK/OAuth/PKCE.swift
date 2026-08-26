// PKCE S256 (RFC 7636).
//
// `code_verifier`: 32 random bytes from `SecRandomCopyBytes` (CSPRNG),
// base64url-encoded without `=` padding.
// `code_challenge`: SHA-256 of verifier, base64url-encoded.
//
// PKCE `plain` is FORBIDDEN — S256 only.

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Crypto)
import Crypto
#endif
#if canImport(Security)
import Security
#endif

public enum PKCE {
    public static let challengeMethod = "S256"

    /// Generate a fresh PKCE pair using CSPRNG.
    public static func generate() throws -> PkceChallenge {
        let bytes = try secureRandomBytes(count: pkceVerifierBytes)
        let verifier = base64URLEncode(bytes)
        let challengeBytes = sha256(Data(verifier.utf8))
        let challenge = base64URLEncode(challengeBytes)
        return PkceChallenge(verifier: verifier, challenge: challenge, method: challengeMethod)
    }

    /// Verify that `challenge` corresponds to `verifier` under S256.
    public static func verify(verifier: String, challenge: String) -> Bool {
        let bytes = sha256(Data(verifier.utf8))
        return constantTimeEquals(base64URLEncode(bytes), challenge)
    }

    // MARK: - Helpers

    public static func sha256(_ data: Data) -> Data {
        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: data)
        return Data(digest)
        #elseif canImport(Crypto)
        let digest = Crypto.SHA256.hash(data: data)
        return Data(digest)
        #else
        // Pure-Swift SHA-256 not provided; CI Linux/macOS always has Crypto/CryptoKit.
        fatalError("SHA-256 unavailable on this platform")
        #endif
    }
}

/// PKCE challenge pair — RFC 7636.
public struct PkceChallenge: Sendable, Equatable {
    public let verifier: String
    public let challenge: String
    public let method: String

    public init(verifier: String, challenge: String, method: String = "S256") {
        self.verifier = verifier
        self.challenge = challenge
        self.method = method
    }
}

/// CSPRNG byte generator. iOS/macOS uses `SecRandomCopyBytes`. Linux falls
/// back to `/dev/urandom` via `swift-crypto` — when neither is available
/// the call throws `SdkError(reason:.unknown)`.
public func secureRandomBytes(count: Int) throws -> Data {
    #if canImport(Security)
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    guard status == errSecSuccess else {
        throw SdkError(
            code: .unknown,
            reason: .unknown,
            errorMessage: "secure_random_failed_status_\(status)"
        )
    }
    return Data(bytes)
    #elseif canImport(Crypto)
    return Data(Crypto.SymmetricKey(size: .init(bitCount: count * 8)).withUnsafeBytes { Data($0) })
    #else
    // Last-resort pure-Swift fallback using arc4random — NEVER used on Apple
    // platforms or CI runners (those always have one of the above).
    var bytes = [UInt8](repeating: 0, count: count)
    for i in 0..<count { bytes[i] = UInt8.random(in: 0...255) }
    return Data(bytes)
    #endif
}

/// Base64url encoding without `=` padding. RFC 7515 §2 / RFC 7636.
public func base64URLEncode(_ data: Data) -> String {
    var s = data.base64EncodedString()
    s = s.replacingOccurrences(of: "+", with: "-")
    s = s.replacingOccurrences(of: "/", with: "_")
    s = s.replacingOccurrences(of: "=", with: "")
    return s
}

/// Base64url decoding (re-pads as needed).
public func base64URLDecode(_ s: String) -> Data? {
    var s = s.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let pad = (4 - (s.count % 4)) % 4
    s += String(repeating: "=", count: pad)
    return Data(base64Encoded: s)
}

/// Constant-time string equality. Always reads all bytes of both inputs.
/// Mirrors RN `crypto.timingSafeEqual` and Flutter constant-time helper.
public func constantTimeEquals(_ a: String, _ b: String) -> Bool {
    return constantTimeEquals(Data(a.utf8), Data(b.utf8))
}

public func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
    // The length mismatch is folded in as a plain 0/1 flag, and MUST stay one.
    // Deriving it arithmetically from the two counts is unsafe in both
    // directions: a trapping conversion crashes on inputs it cannot represent,
    // and a truncating one can collapse a genuine mismatch to zero.
    var diff: UInt8 = (a.count == b.count) ? 0 : 1
    let len = min(a.count, b.count)
    a.withUnsafeBytes { ap in
        b.withUnsafeBytes { bp in
            // Fail CLOSED on a nil base address. Testing it INSIDE the loop
            // meant a nil pointer skipped every iteration and left `diff` at 0
            // — i.e. any two equal-length inputs compared EQUAL.
            guard let ax = ap.bindMemory(to: UInt8.self).baseAddress,
                let bx = bp.bindMemory(to: UInt8.self).baseAddress
            else {
                diff |= 1
                return
            }
            for i in 0..<len {
                diff |= ax[i] ^ bx[i]
            }
        }
    }
    return diff == 0
}
