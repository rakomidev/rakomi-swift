// App-level convenience Scene.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
public struct RakomiAuthScene<Content: View>: Scene {
    let configuration: RakomiAuthConfiguration
    let content: () -> Content

    public init(
        configuration: RakomiAuthConfiguration,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.configuration = configuration
        self.content = content
    }

    public var body: some Scene {
        WindowGroup {
            content().rakomi(configuration: configuration)
        }
    }
}
#endif
