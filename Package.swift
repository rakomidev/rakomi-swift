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
    dependencies: [
        // PRODUCTION DEPS: NONE. Do not add any dependency at this top level.
        // Test-only deps live under the .testTarget below.
        .package(url: "https://github.com/pointfreeco/swift-snapshot-testing", from: "1.17.0"),
        .package(url: "https://github.com/apple/swift-crypto", from: "3.15.1"),
    ],
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
        ),
        .testTarget(
            name: "RakomiSDKTests",
            dependencies: [
                "RakomiSDK",
                .product(name: "SnapshotTesting", package: "swift-snapshot-testing"),
                .product(
                    name: "Crypto",
                    package: "swift-crypto",
                    condition: .when(platforms: [.linux])
                ),
            ],
            path: "Tests/RakomiSDKTests",
            // `.copy("__Snapshots__")` was declared here for a directory that
            // has never existed — a build error the moment the Apple CI lane is
            // re-enabled. It is removed rather than satisfied with an empty
            // directory: `assertSnapshot` appears nowhere in this tree (0
            // occurrences), so a placeholder would restore the green without
            // restoring any capability. Re-add it in the same change that adds
            // the first real recorded snapshot.
            resources: [
                .copy("Fixtures"),
            ]
        ),
    ]
)
