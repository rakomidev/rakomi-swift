// swift-tools-version: 5.10
// RakomiSDK — native Swift SDK for Apple platforms.
//
// Library distribution: Swift Package Manager only (no CocoaPods, no Carthage).
// Module: RakomiSDK. Identity: rakomi-swift.
// Zero production runtime dependencies — Apple frameworks + Swift stdlib only.
// Test-only dependencies (swift-snapshot-testing, swift-crypto) are scoped
// to .testTarget per CRA / NIS2 supply-chain posture.
//
// API VERSION TARGETED: /v1. This SDK is versioned independently of the Rakomi API and independently
// of every other Rakomi SDK, pinned to the API surface it was built and tested against — a
// documentation/release-process discipline, not a runtime negotiation mechanism. State the targeted
// API version in the CHANGELOG entry for every release.

import PackageDescription

let package = Package(
    name: "rakomi-swift",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .watchOS(.v9),
        .tvOS(.v16),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "RakomiSDK", targets: ["RakomiSDK"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "RakomiSDK",
            dependencies: [],
            path: "Sources/RakomiSDK",
            resources: [
                .process("Resources"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("BareSlashRegexLiterals"),
                .enableUpcomingFeature("ConciseMagicFile"),
            ]
        )
    ]
)
