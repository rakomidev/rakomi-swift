// Default adapter wiring Apple frameworks.
//
// Storage = KeychainStorage, browser = BrowserSessionLauncher, biometric =
// BiometricGate, connectivity = NWPathMonitor, lifecycle =
// `UIApplication`/`NSApplication`/`WKExtension` notifications.

import Foundation

public actor DefaultRakomiNativeAdapter: RakomiNativeAdapter {
    public nonisolated let storage: KeychainStorage
    public nonisolated let biometricGate: BiometricGate
    public nonisolated let browser: BrowserSessionLauncher
    public nonisolated let connectivity: ConnectivityMonitor
    public nonisolated let lifecycle: LifecycleObserver
    private nonisolated let clock: @Sendable () -> Date

    public init(
        storage: KeychainStorage,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.storage = storage
        self.biometricGate = BiometricGate()
        self.browser = BrowserSessionLauncher()
        self.connectivity = ConnectivityMonitor()
        self.lifecycle = LifecycleObserver()
        self.clock = clock
    }

    public init(
        accessGroup: String? = nil,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.storage = KeychainStorage(accessGroup: accessGroup)
        self.biometricGate = BiometricGate()
        self.browser = BrowserSessionLauncher()
        self.connectivity = ConnectivityMonitor()
        self.lifecycle = LifecycleObserver()
        self.clock = clock
    }

    // MARK: - Storage

    public func storageRead(key: String) async -> String? {
        return await storage.read(key: key)
    }

    public func storageWrite(key: String, value: String) async -> StorageWriteResult {
        return await storage.write(key: key, value: value)
    }

    public func storageDelete(key: String) async {
        await storage.delete(key: key)
    }

    public func storageDeleteAll(prefix: String) async {
        await storage.deleteAll(prefix: prefix)
    }

    public func storageHas(key: String) async -> Bool {
        return await storage.has(key: key)
    }

    // MARK: - UserDefaults

    public func userDefaultsRead(key: String) async -> String? {
        return UserDefaults.standard.string(forKey: key)
    }

    public func userDefaultsWrite(key: String, value: String) async {
        UserDefaults.standard.set(value, forKey: key)
    }

    public func userDefaultsDelete(key: String) async {
        UserDefaults.standard.removeObject(forKey: key)
    }

    // MARK: - System browser

    public func launchSystemBrowser(url: URL, callbackScheme: String) async -> BrowserAuthSessionResult {
        return await browser.launch(url: url, callbackScheme: callbackScheme)
    }

    // MARK: - Biometric

    public func biometricAvailable() async -> Bool {
        return await biometricGate.available()
    }

    public func requestBiometric(reason: String) async -> BiometricResult {
        return await biometricGate.request(reason: reason)
    }

    // MARK: - Native passkey

    public func supportsNativePasskey() async -> Bool {
        // Reserved for a future native-passkey implementation.
        return false
    }

    // MARK: - Streams

    nonisolated public var connectivityStream: AsyncStream<ConnectivityState> {
        return connectivity.states
    }

    nonisolated public var lifecycleStream: AsyncStream<AppLifecycleEvent> {
        return lifecycle.events
    }

    // MARK: - Clock

    public nonisolated func now() -> Date {
        return clock()
    }
}
