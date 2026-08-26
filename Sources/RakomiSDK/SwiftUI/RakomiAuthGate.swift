// RakomiAuthGate ViewBuilder.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
public struct RakomiAuthGate<SignedIn: View, SignedOut: View, Loading: View, ErrorView: View>: View {
    @Environment(RakomiAuthEnvironment.self) private var env

    let signedIn: (User) -> SignedIn
    let signedOut: () -> SignedOut
    let loading: () -> Loading
    let errorView: (SdkError) -> ErrorView

    public init(
        @ViewBuilder signedIn: @escaping (User) -> SignedIn,
        @ViewBuilder signedOut: @escaping () -> SignedOut,
        @ViewBuilder loading: @escaping () -> Loading = { ProgressView() },
        @ViewBuilder error: @escaping (SdkError) -> ErrorView = { _ in EmptyView() }
    ) {
        self.signedIn = signedIn
        self.signedOut = signedOut
        self.loading = loading
        self.errorView = error
    }

    public var body: some View {
        Group {
            switch env.state {
            case .authenticated(let user, _): signedIn(user)
            case .signedOut: signedOut()
            case .loading: loading()
            case .error(let err): errorView(err)
            }
        }
    }
}
#endif
