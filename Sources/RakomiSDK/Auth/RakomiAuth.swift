// Public top-level auth actor.
//
// `RakomiAuth.shared` is per-`RakomiAuthConfiguration`-instance, NOT a
// process-global singleton. Multiple configurations create independent
// `RakomiAuth` instances. Document this prominently in README.

import Foundation

public actor RakomiAuth {
    public nonisolated let configuration: RakomiAuthConfiguration
    public nonisolated let controller: RakomiAuthController
    private nonisolated let socialAuth: SocialAuth
    private nonisolated let mfa: MFA
    private nonisolated let deviceCode: DeviceCode
    private nonisolated let deepLink: DeepLinkHandler

    public init(configuration: RakomiAuthConfiguration, adapter: any RakomiNativeAdapter) {
        let ctrl = RakomiAuthController(configuration: configuration, adapter: adapter)
        self.configuration = configuration
        self.controller = ctrl
        self.socialAuth = SocialAuth(controller: ctrl)
        self.mfa = MFA(controller: ctrl)
        self.deviceCode = DeviceCode(controller: ctrl)
        self.deepLink = DeepLinkHandler(controller: ctrl)
    }

    public init(configuration: RakomiAuthConfiguration) {
        let adapter = DefaultRakomiNativeAdapter(accessGroup: configuration.keychainAccessGroup)
        let ctrl = RakomiAuthController(configuration: configuration, adapter: adapter)
        self.configuration = configuration
        self.controller = ctrl
        self.socialAuth = SocialAuth(controller: ctrl)
        self.mfa = MFA(controller: ctrl)
        self.deviceCode = DeviceCode(controller: ctrl)
        self.deepLink = DeepLinkHandler(controller: ctrl)
    }

    // MARK: - Default per-configuration registry

    nonisolated(unsafe) private static var registry: [String: RakomiAuth] = [:]
    nonisolated(unsafe) private static var defaultInstance: RakomiAuth?

    /// Convenience accessor used by SwiftUI `@Environment` injection. Set
    /// internally by `RakomiProvider` view modifier.
    public static var shared: RakomiAuth {
        guard let inst = defaultInstance else {
            fatalError("RakomiAuth.shared accessed before RakomiProvider mounted; install via .rakomi(configuration:)")
        }
        return inst
    }

    /// Internal — used by `RakomiProvider` to install the default instance.
    public static func _setDefault(_ instance: RakomiAuth) {
        defaultInstance = instance
        registry[instance.configuration.publishableKey] = instance
    }

    public static func instance(for publishableKey: String) -> RakomiAuth? {
        return registry[publishableKey]
    }

    // MARK: - Public API surface

    public nonisolated func authStateChanges() -> AsyncStream<AuthState> {
        return controller.stateStream
    }

    public nonisolated func events() -> AsyncStream<AuthEvent> {
        return controller.eventStream
    }

    public func signIn(email: String, password: String) async {
        await controller.signInPassword(email: email, password: password)
    }

    public func signUp(email: String, password: String) async {
        await controller.signUp(email: email, password: password)
    }

    public func signOut() async {
        await controller.signOut()
    }

    public func signIn(withProvider provider: SocialProvider) async {
        await socialAuth.signIn(provider: provider)
    }

    public func verifyMfa(challengeId: String, code: String) async {
        await mfa.verifyTotp(challengeId: challengeId, code: code)
    }

    public func currentUser() async -> User? {
        let state = await controller.currentState()
        return state.user
    }

    public func getToken() async throws -> String {
        return try await controller.getToken()
    }

    public func refreshTokens() async throws {
        _ = try await controller.refresh(force: true)
    }

    public func hasValidSession() async -> Bool {
        return await controller.hasValidSession()
    }

    public func handleCallbackURL(_ url: URL) async {
        await deepLink.handle(url)
    }

    public func startDeviceAuthorization() async throws -> DeviceAuthorizationStart {
        return try await deviceCode.start()
    }

    public func unlockWithBiometric(reason: String) async {
        let adapter = controller.adapter
        let result = await adapter.requestBiometric(reason: reason)
        switch result {
        case .success:
            await controller.hydrate()
        case .cancelled:
            await controller.emit(
                .error(
                    SdkError(
                        code: .biometricError,
                        reason: .biometricCancelled,
                        errorMessage: "biometric_cancelled"
                    )
                )
            )
        case .lockout:
            await controller.emit(
                .error(
                    SdkError(
                        code: .biometricError,
                        reason: .biometricLockout,
                        errorMessage: "biometric_lockout"
                    )
                )
            )
        case .notEnrolled:
            await controller.emit(
                .error(
                    SdkError(
                        code: .biometricError,
                        reason: .biometricNotEnrolled,
                        errorMessage: "biometric_not_enrolled"
                    )
                )
            )
        case .unavailable(let reason):
            await controller.emit(
                .error(
                    SdkError(
                        code: .biometricError,
                        reason: .biometricUnavailable,
                        errorMessage: reason ?? "biometric_unavailable"
                    )
                )
            )
        }
    }

    /// Force JWKS cache invalidation. Forward-compat seam for SSE/CAEP.
    public func invalidateJWKS() async {
        await controller.invalidateJWKS()
    }

    public func hydrate() async {
        await controller.hydrate()
    }
}
