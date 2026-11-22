// Wire shapes of the first-party auth endpoints.
//
// The API answers in snake_case (the RFC 6749 §5.1 token-response naming the
// whole surface follows). `JSONDecoder` matches property names verbatim, so
// every key is mapped explicitly here.
//
// `.keyDecodingStrategy = .convertFromSnakeCase` is deliberately NOT used: it
// would rewrite `verification_uri` to `verificationUri` and stop matching
// `DeviceAuthorizationStart.verificationURI`, trading one silent decode failure
// for another.

import Foundation

/// The token envelope returned by `/v1/auth/login`, `/v1/auth/refresh`,
/// `/v1/auth/mfa/verify-login` and the device-code token endpoint.
///
/// Every field is optional because one shape covers several branches: an
/// authenticated response carries the tokens, an MFA challenge carries
/// `mfa_challenge_token` and no tokens, and a device-code poll carries `error`
/// while the user has not approved yet. Callers branch on `nextStep`/`error`
/// and then require what that branch promises.
struct APITokenResponse: Decodable {
    let nextStep: String?
    let accessToken: String?
    let refreshToken: String?
    let expiresIn: Int?
    let tokenType: String?
    let mfaChallengeToken: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case nextStep = "next_step"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
        case mfaChallengeToken = "mfa_challenge_token"
        case error
    }
}

/// `next_step` values the token envelope can carry.
enum APINextStep {
    static let authenticated = "authenticated"
    static let mfaVerify = "mfa_verify"
    static let mfaSetupRequired = "mfa_setup_required"
}

/// `/v1/auth/register` answers with a message, never with tokens: the account
/// still has to verify its email address before it can sign in.
struct APIRegisterResponse: Decodable {
    let message: String
    let nextStep: String?

    enum CodingKeys: String, CodingKey {
        case message
        case nextStep = "next_step"
    }
}
