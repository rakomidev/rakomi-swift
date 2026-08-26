// Pre-built sign-in form.

import Foundation

#if canImport(SwiftUI)
import SwiftUI
#endif

#if canImport(SwiftUI)
@available(iOS 17, macOS 14, watchOS 10, tvOS 17, visionOS 1, *)
public struct RakomiSignInForm: View {
    @Environment(RakomiAuthEnvironment.self) private var env

    @State private var email: String = ""
    @State private var password: String = ""
    @State private var totpCode: String = ""
    @State private var mfaChallengeId: String? = nil
    @State private var submitting: Bool = false

    public init() {}

    public var body: some View {
        Form {
            if let challengeId = mfaChallengeId {
                totpSection(challengeId: challengeId)
            } else {
                credentialsSection
                socialSection
            }
        }
        .accessibilityIdentifier("rakomi.signInForm")
        .task {
            guard let auth = env.auth else { return }
            for await event in auth.events() {
                if case .mfaChallengeRequired(let cid) = event {
                    mfaChallengeId = cid
                } else if case .mfaChallengeVerified = event {
                    mfaChallengeId = nil
                }
            }
        }
    }

    private var credentialsSection: some View {
        Section {
            TextField("Email", text: $email)
                .accessibilityLabel("Email address")
                .accessibilityIdentifier("rakomi.signInForm.email")
                #if os(iOS) || os(visionOS)
            .keyboardType(.emailAddress)
            .textInputAutocapitalization(.never)
            .textContentType(.emailAddress)
            .disableAutocorrection(true)
                #endif

            SecureField("Password", text: $password)
                .accessibilityLabel("Password")
                .accessibilityIdentifier("rakomi.signInForm.password")
                #if os(iOS) || os(visionOS)
            .textContentType(.password)
                #endif

            Button {
                Task { await submit() }
            } label: {
                Text(submitting ? "Signing in…" : "Sign in")
                    .frame(maxWidth: .infinity)
            }
            .disabled(email.isEmpty || password.isEmpty || submitting)
            .accessibilityIdentifier("rakomi.signInForm.submit")
        }
    }

    private var socialSection: some View {
        Section("Or continue with") {
            ForEach(SocialProvider.allCases, id: \.rawValue) { provider in
                RakomiSignInButton(provider: provider)
            }
        }
    }

    private func totpSection(challengeId: String) -> some View {
        Section("Two-factor authentication") {
            TextField("6-digit code", text: $totpCode)
                #if os(iOS) || os(visionOS)
            .keyboardType(.numberPad)
            .textContentType(.oneTimeCode)
            .textInputAutocapitalization(.never)
                #endif
                .disableAutocorrection(true)
                .accessibilityLabel("One-time MFA code")
                .accessibilityIdentifier("rakomi.signInForm.totp")
                .onChange(of: totpCode) { _, newValue in
                    totpCode = String(newValue.prefix(6).filter { $0.isNumber })
                }
                .font(.system(.body, design: .monospaced))
            Button("Verify") {
                Task { await submitTotp(challengeId: challengeId) }
            }
            .disabled(totpCode.count != 6)
            .accessibilityIdentifier("rakomi.signInForm.totp.submit")
        }
    }

    private func submit() async {
        submitting = true
        defer { submitting = false }
        guard let auth = env.auth else { return }
        await auth.signIn(email: email, password: password)
    }

    private func submitTotp(challengeId: String) async {
        submitting = true
        defer { submitting = false }
        guard let auth = env.auth else { return }
        await auth.verifyMfa(challengeId: challengeId, code: totpCode)
        totpCode = ""
    }
}
#endif
