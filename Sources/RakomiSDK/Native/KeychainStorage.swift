// Keychain Services wrapper.
//
// Tenant-scoped via `kSecAttrService = "com.rakomi.swift-sdk"` +
// `kSecAttrAccount = key`. Refresh tokens use
// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` to prevent iCloud
// Keychain sync (matches RN's `THIS_DEVICE_ONLY`).

import Foundation

#if canImport(Security)
import Security
#endif

/// Keychain-backed string storage. Linux test target compiles this file with
/// the no-op fallback below.
public actor KeychainStorage {
    public let service: String
    public let accessGroup: String?

    public init(service: String = StorageKeys.keychainService, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    // MARK: - Read

    public func read(key: String) -> String? {
        #if canImport(Security) && (os(iOS) || os(macOS) || os(watchOS) || os(tvOS) || os(visionOS))
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
        #else
        return nil
        #endif
    }

    // MARK: - Write

    public func write(key: String, value: String) -> StorageWriteResult {
        #if canImport(Security) && (os(iOS) || os(macOS) || os(watchOS) || os(tvOS) || os(visionOS))
        guard let data = value.data(using: .utf8) else {
            return .failed(
                SdkError(
                    code: .storageError,
                    reason: .unknown,
                    errorMessage: "keychain_encoding_failed"
                )
            )
        }
        var attributes: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if let group = accessGroup { attributes[kSecAttrAccessGroup] = group }

        // Upsert: try add; on duplicate, update.
        let addStatus = SecItemAdd(attributes as CFDictionary, nil)
        if addStatus == errSecSuccess { return .success }

        if addStatus == errSecDuplicateItem {
            var query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: key,
            ]
            if let group = accessGroup { query[kSecAttrAccessGroup] = group }
            let updates: [CFString: Any] = [
                kSecValueData: data,
                kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
            let updateStatus = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
            return updateStatus == errSecSuccess
                ? .success
                : .failed(
                    SdkError(
                        code: .storageError,
                        reason: .unknown,
                        errorMessage: "keychain_update_failed_status_\(updateStatus)"
                    )
                )
        }

        // errSecInteractionNotAllowed = device locked; surface so controller
        // can keep refresh in-memory only. A write failure is never silent.
        return .failed(
            SdkError(
                code: .storageError,
                reason: .unknown,
                errorMessage: "keychain_write_failed_status_\(addStatus)"
            )
        )
        #else
        _ = (key, value)
        return .failed(
            SdkError(
                code: .storageError,
                reason: .unknown,
                errorMessage: "keychain_unavailable_on_linux"
            )
        )
        #endif
    }

    // MARK: - Delete

    public func delete(key: String) {
        #if canImport(Security) && (os(iOS) || os(macOS) || os(watchOS) || os(tvOS) || os(visionOS))
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }
        SecItemDelete(query as CFDictionary)
        #endif
    }

    /// Delete all entries whose `kSecAttrAccount` starts with `prefix`.
    /// EXACT-prefix-match: a substring match would purge unrelated entries.
    public func deleteAll(prefix: String) {
        #if canImport(Security) && (os(iOS) || os(macOS) || os(watchOS) || os(tvOS) || os(visionOS))
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitAll,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[CFString: Any]] else { return }

        for item in items {
            guard let account = item[kSecAttrAccount] as? String,
                account.hasPrefix(prefix)
            else { continue }
            delete(key: account)
        }
        #endif
    }

    public func has(key: String) -> Bool {
        return read(key: key) != nil
    }
}
