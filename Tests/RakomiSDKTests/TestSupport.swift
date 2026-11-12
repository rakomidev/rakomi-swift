// Test-only adapter conforming to `RakomiNativeAdapter` — purely in-memory.

import Foundation

@testable import RakomiSDK

actor InMemoryDictStore {
    var values: [String: String] = [:]

    func read(_ key: String) -> String? { values[key] }
    func write(_ key: String, _ value: String) { values[key] = value }
    func delete(_ key: String) { values[key] = nil }
    func has(_ key: String) -> Bool { values[key] != nil }
    func deleteAllPrefix(_ prefix: String) {
        for k in values.keys where k.hasPrefix(prefix) { values[k] = nil }
    }
    func snapshot() -> [String: String] { values }
}

public actor TestAdapter: RakomiNativeAdapter {
    let storage: InMemoryDictStore
    let userDefaults: InMemoryDictStore
    public var browserResult: BrowserAuthSessionResult = .cancelled
    public var biometricResult: BiometricResult = .success
    public var biometricAvailableValue: Bool = true

    private let connectivityCont: AsyncStream<ConnectivityState>.Continuation
    public nonisolated let connectivityStream: AsyncStream<ConnectivityState>
    private let lifecycleCont: AsyncStream<AppLifecycleEvent>.Continuation
    public nonisolated let lifecycleStream: AsyncStream<AppLifecycleEvent>

    public init() {
        self.storage = InMemoryDictStore()
        self.userDefaults = InMemoryDictStore()
        var cCont: AsyncStream<ConnectivityState>.Continuation!
        self.connectivityStream = AsyncStream { c in cCont = c }
        self.connectivityCont = cCont
        var lCont: AsyncStream<AppLifecycleEvent>.Continuation!
        self.lifecycleStream = AsyncStream { c in lCont = c }
        self.lifecycleCont = lCont
    }

    public func storageRead(key: String) async -> String? {
        await storage.read(key)
    }
    public func storageWrite(key: String, value: String) async -> StorageWriteResult {
        await storage.write(key, value)
        return .success
    }
    public func storageDelete(key: String) async {
        await storage.delete(key)
    }
    public func storageDeleteAll(prefix: String) async {
        await storage.deleteAllPrefix(prefix)
    }
    public func storageHas(key: String) async -> Bool {
        await storage.has(key)
    }

    public func userDefaultsRead(key: String) async -> String? {
        await userDefaults.read(key)
    }
    public func userDefaultsWrite(key: String, value: String) async {
        await userDefaults.write(key, value)
    }
    public func userDefaultsDelete(key: String) async {
        await userDefaults.delete(key)
    }

    /// How many times a browser was asked for. A guard that is supposed to stop
    /// before the browser opens can only be proven by counting.
    public private(set) var browserLaunchCount = 0
    public private(set) var lastBrowserURL: URL?

    public func launchSystemBrowser(url: URL, callbackScheme: String) async -> BrowserAuthSessionResult {
        browserLaunchCount += 1
        lastBrowserURL = url
        return browserResult
    }

    public func biometricAvailable() async -> Bool { biometricAvailableValue }
    public private(set) var biometricRequestCount: Int = 0
    public func requestBiometric(reason: String) async -> BiometricResult {
        biometricRequestCount += 1
        return biometricResult
    }

    public func supportsNativePasskey() async -> Bool { false }

    public nonisolated func now() -> Date { Date() }

    // Test injection helpers
    public func setBrowserResult(_ r: BrowserAuthSessionResult) { browserResult = r }
    public func setBiometricResult(_ r: BiometricResult) { biometricResult = r }
    public func setBiometricAvailable(_ v: Bool) { biometricAvailableValue = v }
    public func injectConnectivity(_ s: ConnectivityState) { connectivityCont.yield(s) }
    public func injectLifecycle(_ e: AppLifecycleEvent) { lifecycleCont.yield(e) }
    public func storageSnapshot() async -> [String: String] { await storage.snapshot() }
}
