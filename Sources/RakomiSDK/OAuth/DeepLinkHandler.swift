// Deep-link callback ingestion.
//
// SwiftUI `.onOpenURL` and UIKit `application(_:open:)` bridge to
// `RakomiAuth.shared.handleCallbackURL(_:)` which dispatches to the
// SocialAuth flow that issued the original `state`.

import Foundation

public actor DeepLinkHandler {
    public let controller: RakomiAuthController
    public let socialAuth: SocialAuth

    private var consumed: Set<String> = []

    public init(controller: RakomiAuthController) {
        self.controller = controller
        self.socialAuth = SocialAuth(controller: controller)
    }

    /// Ingest a deep-link callback URL. Idempotent — second call with the
    /// same `state` is dropped.
    public func handle(_ url: URL) async {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let items = comps.queryItems
        else { return }
        let state = items.first { $0.name == "state" }?.value
        let oneTimeId = items.first { $0.name == "ott" }?.value
        guard let state, let oneTimeId else { return }
        if consumed.contains(state) { return }
        consumed.insert(state)
        do {
            try await socialAuth.processCallback(
                callbackURL: url,
                oneTimeId: oneTimeId,
                expectedState: state
            )
        } catch let err as SdkError {
            await controller.emit(.error(err))
        } catch {
            await controller.emit(
                .error(
                    SdkError(
                        code: .oauthCallbackError,
                        reason: .oauthProviderError,
                        errorMessage: "deep_link_unknown"
                    )
                )
            )
        }
        // Trim consumed set to avoid unbounded growth.
        if consumed.count > 100 {
            consumed.removeAll(keepingCapacity: true)
        }
    }
}
