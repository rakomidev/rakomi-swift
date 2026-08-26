// App-lifecycle bridge.

import Foundation

#if canImport(UIKit) && !os(watchOS)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif
#if canImport(WatchKit) && os(watchOS)
import WatchKit
#endif

public final class LifecycleObserver: @unchecked Sendable {
    private let stream: AsyncStream<AppLifecycleEvent>
    private let continuation: AsyncStream<AppLifecycleEvent>.Continuation
    private var observers: [NSObjectProtocol] = []

    public init() {
        var cont: AsyncStream<AppLifecycleEvent>.Continuation!
        self.stream = AsyncStream<AppLifecycleEvent> { c in cont = c }
        self.continuation = cont
        registerObservers()
    }

    deinit {
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        continuation.finish()
    }

    private func registerObservers() {
        let center = NotificationCenter.default
        #if canImport(UIKit) && !os(watchOS)
        observers.append(
            center.addObserver(
                forName: UIApplication.didBecomeActiveNotification,
                object: nil,
                queue: nil
            ) { [continuation] _ in continuation.yield(.becameActive) }
        )
        observers.append(
            center.addObserver(
                forName: UIApplication.willResignActiveNotification,
                object: nil,
                queue: nil
            ) { [continuation] _ in continuation.yield(.willResignActive) }
        )
        #endif
        #if canImport(AppKit)
        observers.append(
            center.addObserver(
                forName: NSApplication.didBecomeActiveNotification,
                object: nil,
                queue: nil
            ) { [continuation] _ in continuation.yield(.becameActive) }
        )
        observers.append(
            center.addObserver(
                forName: NSApplication.willResignActiveNotification,
                object: nil,
                queue: nil
            ) { [continuation] _ in continuation.yield(.willResignActive) }
        )
        #endif
        #if canImport(WatchKit) && os(watchOS)
        observers.append(
            center.addObserver(
                forName: WKExtension.applicationDidBecomeActiveNotification,
                object: nil,
                queue: nil
            ) { [continuation] _ in continuation.yield(.becameActive) }
        )
        #endif
    }

    public var events: AsyncStream<AppLifecycleEvent> { stream }
}
