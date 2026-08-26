// Native adapter protocol seam.
//
// Public protocol defining the OS-coupled surface: Keychain storage,
// system browser orchestration, biometric gate, deep-link ingest,
// connectivity polling, lifecycle bridge. Default implementation
// (`DefaultRakomiNativeAdapter`) wires Apple frameworks; tests inject a
// `TestRakomiNativeAdapter` conforming type.
//
// `@unchecked Sendable` — adapter implementations MUST be thread-safe.
// Methods are `async` where I/O is involved.

import Foundation

/// Result of a biometric prompt. Mirrors RN/Flutter `BiometricResult`.
public enum BiometricResult: Sendable, Equatable {
    case success
    case cancelled
    case lockout
    case notEnrolled
    case unavailable(reason: String?)
}

/// Result of an `ASWebAuthenticationSession` (or platform equivalent).
public enum BrowserAuthSessionResult: Sendable {
    case success(callbackURL: URL)
    case cancelled
    case failed(SdkError)
}

/// Connectivity state — `.satisfied` is "online", anything else is "offline".
public enum ConnectivityState: Sendable, Equatable {
    case satisfied
    case unsatisfied
    case requiresConnection
}

/// App-level lifecycle event.
public enum AppLifecycleEvent: Sendable {
    case becameActive
    case willResignActive
}

/// Storage write result — Keychain writes can fail when the device is
/// locked in DFU / post-restore-pre-unlock states.
public enum StorageWriteResult: Sendable {
    case success
    case failed(SdkError)
}

/// Native adapter contract. Adopt to swap implementations for testing or
/// custom platform behavior. The default implementation
/// `DefaultRakomiNativeAdapter` wires Apple frameworks.
public protocol RakomiNativeAdapter: Sendable {
    // MARK: - Keychain storage

    /// Read a UTF-8 string value for `key` from Keychain.
    func storageRead(key: String) async -> String?

    /// Write `value` for `key`. Returns `.failed` on `errSecInteractionNotAllowed`
    /// or other Keychain failure modes.
    func storageWrite(key: String, value: String) async -> StorageWriteResult

    /// Delete `key` from Keychain (idempotent — missing key is success).
    func storageDelete(key: String) async

    /// Delete all keys with prefix `prefix`. Used by fresh-install purge.
    /// Implementations MUST use exact-prefix-match, never substring — a substring
    /// match would delete keys belonging to a different tenant.
    func storageDeleteAll(prefix: String) async

    /// True iff Keychain has any value for `key` — used by purge probes.
    func storageHas(key: String) async -> Bool

    // MARK: - UserDefaults shim (lifecycle marker)

    /// Read a string from `UserDefaults.standard`. Used by the fresh-install
    /// detection — Keychain entries can survive uninstall on iOS,
    /// `UserDefaults` is cleared on uninstall.
    func userDefaultsRead(key: String) async -> String?

    func userDefaultsWrite(key: String, value: String) async

    func userDefaultsDelete(key: String) async

    // MARK: - System browser

    /// Launch `url` in the platform system browser (`ASWebAuthenticationSession`
    /// on iOS/macOS/visionOS). Returns the callback URL or maps to `.cancelled`
    /// / `.failed`. NEVER opens a `WKWebView` — codebase guard enforced.
    func launchSystemBrowser(url: URL, callbackScheme: String) async -> BrowserAuthSessionResult

    // MARK: - Biometric gate

    /// True iff the device has biometric hardware AND it is enrolled.
    /// Returns false on watchOS/tvOS unconditionally.
    func biometricAvailable() async -> Bool

    /// Prompt user for biometric. `reason` is shown in the system dialog.
    /// MUST map LAError codes to `BiometricResult` cases at the adapter
    /// boundary — never let `LAError` cross the protocol.
    func requestBiometric(reason: String) async -> BiometricResult

    // MARK: - Deep-link / native passkey hooks

    /// True iff this adapter supports a native platform passkey ceremony.
    /// Default adapter returns false; a native-passkey adapter overrides it.
    func supportsNativePasskey() async -> Bool

    // MARK: - Connectivity + lifecycle

    /// AsyncStream of connectivity transitions.
    var connectivityStream: AsyncStream<ConnectivityState> { get }

    /// AsyncStream of app-lifecycle transitions.
    var lifecycleStream: AsyncStream<AppLifecycleEvent> { get }

    // MARK: - Clock

    /// Current wall-clock time (replaceable in tests).
    func now() -> Date
}
