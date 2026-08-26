// NWPathMonitor wrapper.

import Foundation

#if canImport(Network)
import Network
#endif

public final class ConnectivityMonitor: @unchecked Sendable {
    private let stream: AsyncStream<ConnectivityState>
    private let continuation: AsyncStream<ConnectivityState>.Continuation
    #if canImport(Network)
    private let monitor: NWPathMonitor
    private let queue = DispatchQueue(label: "com.rakomi.swift-sdk.connectivity")
    #endif

    public init() {
        var cont: AsyncStream<ConnectivityState>.Continuation!
        self.stream = AsyncStream<ConnectivityState> { c in cont = c }
        self.continuation = cont
        #if canImport(Network)
        self.monitor = NWPathMonitor()
        self.monitor.pathUpdateHandler = { [continuation] path in
            switch path.status {
            case .satisfied: continuation.yield(.satisfied)
            case .unsatisfied: continuation.yield(.unsatisfied)
            case .requiresConnection: continuation.yield(.requiresConnection)
            @unknown default: continuation.yield(.unsatisfied)
            }
        }
        monitor.start(queue: queue)
        #endif
    }

    deinit {
        #if canImport(Network)
        monitor.cancel()
        #endif
        continuation.finish()
    }

    public var states: AsyncStream<ConnectivityState> { stream }
}
