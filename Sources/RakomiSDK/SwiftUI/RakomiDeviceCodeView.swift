// tvOS device-code SwiftUI view.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
public struct RakomiDeviceCodeView: View {
    @Environment(RakomiAuthEnvironment.self) private var env
    @State private var start: DeviceAuthorizationStart?
    @State private var error: SdkError?

    public init() {}

    public var body: some View {
        VStack(spacing: 24) {
            Text("Sign in to continue").font(.title)
            if let start {
                Text("Visit:").foregroundStyle(.secondary)
                Text(start.verificationURI)
                    .font(.title2)
                    .accessibilityIdentifier("rakomi.deviceCode.uri")
                Text("Code:").foregroundStyle(.secondary)
                Text(start.userCode)
                    .font(.system(.largeTitle, design: .monospaced))
                    .accessibilityIdentifier("rakomi.deviceCode.code")
            } else if let err = error {
                Text("Could not start sign-in: \(err.errorDescription ?? "")")
                    .foregroundStyle(.red)
            } else {
                ProgressView()
            }
        }
        .padding()
        .task {
            guard let auth = env.auth else { return }
            do {
                start = try await auth.startDeviceAuthorization()
            } catch let err as SdkError {
                error = err
            } catch {
                self.error = SdkError(reason: .unknown, errorMessage: "device_auth_unknown")
            }
        }
    }
}
#endif
