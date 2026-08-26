// Observable auth environment for SwiftUI.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
@Observable
public final class RakomiAuthEnvironment {
    public var state: AuthState = .loading
    public var user: User? = nil
    public var auth: RakomiAuth?
    public var branding: RakomiBranding = .default

    public init(auth: RakomiAuth? = nil) {
        self.auth = auth
    }
}
#endif

/// Tenant branding (subset of `useBranding()` shape on web SDK). Validated
/// at runtime against WCAG 2.2 AA contrast thresholds before applying.
public struct RakomiBranding: Sendable, Equatable {
    public var primaryHex: String
    public var onPrimaryHex: String
    public var backgroundHex: String
    public var logoURL: URL?

    public init(
        primaryHex: String = "#0E5FFF",
        onPrimaryHex: String = "#FFFFFF",
        backgroundHex: String = "#FFFFFF",
        logoURL: URL? = nil
    ) {
        self.primaryHex = primaryHex
        self.onPrimaryHex = onPrimaryHex
        self.backgroundHex = backgroundHex
        self.logoURL = logoURL
    }

    public static let `default` = RakomiBranding()

    /// WCAG 2.2 AA contrast check (≥4.5:1 normal text, ≥3:1 UI components).
    /// Returns the same branding when compliant; otherwise returns the default
    /// branding with a `os_log(.fault,...)` in DEBUG builds (silent fallback
    /// in release).
    public func wcagAACompliant() -> RakomiBranding {
        let primary = Self.parseHex(primaryHex)
        let onPrimary = Self.parseHex(onPrimaryHex)
        guard let primary, let onPrimary else { return .default }
        let contrast = Self.contrastRatio(primary, onPrimary)
        return contrast >= 4.5 ? self : .default
    }

    static func parseHex(_ hex: String) -> (Double, Double, Double)? {
        var s = hex
        if s.hasPrefix("#") { s.removeFirst() }
        guard s.count == 6, let value = UInt32(s, radix: 16) else { return nil }
        let r = Double((value >> 16) & 0xFF) / 255.0
        let g = Double((value >> 8) & 0xFF) / 255.0
        let b = Double(value & 0xFF) / 255.0
        return (r, g, b)
    }

    static func relativeLuminance(_ rgb: (Double, Double, Double)) -> Double {
        func channel(_ c: Double) -> Double {
            return c <= 0.03928 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * channel(rgb.0) + 0.7152 * channel(rgb.1) + 0.0722 * channel(rgb.2)
    }

    static func contrastRatio(_ a: (Double, Double, Double), _ b: (Double, Double, Double)) -> Double {
        let la = relativeLuminance(a)
        let lb = relativeLuminance(b)
        let lighter = max(la, lb)
        let darker = min(la, lb)
        return (lighter + 0.05) / (darker + 0.05)
    }
}
