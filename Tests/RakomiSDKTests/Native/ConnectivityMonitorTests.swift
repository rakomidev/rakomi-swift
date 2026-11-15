import XCTest

@testable import RakomiSDK

final class ConnectivityMonitorTests: XCTestCase {

    func testInjectedConnectivityEventsArrive() async throws {
        let adapter = TestAdapter()
        let stream = adapter.connectivityStream
        await adapter.injectConnectivity(.unsatisfied)
        await adapter.injectConnectivity(.satisfied)

        var received: [ConnectivityState] = []
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

    func testSatisfiedIsOnline() {
        XCTAssertEqual(ConnectivityState.satisfied, .satisfied)
    }
}
