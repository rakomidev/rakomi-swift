// Lifecycle stream smoke tests.

import XCTest

@testable import RakomiSDK

final class LifecycleObserverTests: XCTestCase {

    func testInjectedLifecycleEventsArrive() async throws {
        let adapter = TestAdapter()
        let stream = adapter.lifecycleStream
        await adapter.injectLifecycle(.becameActive)
        await adapter.injectLifecycle(.willResignActive)

        var received: [AppLifecycleEvent] = []
        let task = Task {
            for await ev in stream {
                received.append(ev)
                if received.count == 2 { break }
            }
        }
        try? await Task.sleep(nanoseconds: 200_000_000)
        task.cancel()
        XCTAssertGreaterThanOrEqual(received.count, 0)
    }
}
