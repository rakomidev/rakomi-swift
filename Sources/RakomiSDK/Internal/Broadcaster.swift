// Fan-out behind `authStateChanges()` and `events()`.
//
// Both used to hand every caller the SAME `AsyncStream`. An AsyncStream has one
// consumer by construction: when two tasks iterate one, each value goes to
// whichever is waiting, so the two split the sequence instead of both seeing it.
// That is not a theoretical concern for this SDK — `RakomiProvider` iterates the
// state stream to drive the SwiftUI environment, `RakomiSignInForm` iterates the
// event stream to catch an MFA challenge, and `RakomiAuthUIKitObserver.attach`
// iterates the state stream again. An app that listens for itself, exactly as
// the public API invites, silently takes transitions away from the SDK's own UI.
//
// So each call now gets its OWN stream and every value reaches all of them.

import Foundation

/// Multi-subscriber fan-out over a value stream.
///
/// `replaysLatest` decides what a late subscriber sees. State replays: a view
/// that subscribes after sign-in has to learn it is signed in, and the previous
/// buffered-single-stream arrangement gave it that. Events do not replay: they
/// are discrete occurrences, and handing an analytics consumer a stale one would
/// make it count the same sign-in twice.
final class Broadcaster<Element: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuations: [Int: AsyncStream<Element>.Continuation] = [:]
    private var nextId = 0
    private var latest: Element?
    private let replaysLatest: Bool
    private let bufferSize: Int

    /// `initial` is the value a subscriber is handed before anything has been
    /// yielded — the state stream starts every subscriber on `loading`, which is
    /// what `RakomiProvider` documents as the first frame.
    init(replaysLatest: Bool, bufferSize: Int, initial: Element? = nil) {
        self.replaysLatest = replaysLatest
        self.bufferSize = bufferSize
        self.latest = initial
    }

    /// A fresh stream for one consumer. Iterating it never competes with any
    /// other subscriber, and dropping it deregisters on termination.
    func subscribe() -> AsyncStream<Element> {
        return AsyncStream<Element>(bufferingPolicy: .bufferingNewest(bufferSize)) { continuation in
            lock.lock()
            let id = nextId
            nextId += 1
            continuations[id] = continuation
            let replay = replaysLatest ? latest : nil
            lock.unlock()

            continuation.onTermination = { [weak self] _ in
                self?.remove(id)
            }
            if let replay { continuation.yield(replay) }
        }
    }

    func yield(_ value: Element) {
        lock.lock()
        if replaysLatest { latest = value }
        let targets = Array(continuations.values)
        lock.unlock()
        for continuation in targets { continuation.yield(value) }
    }

    /// Subscriber count — the substrate a test needs to prove a cancelled
    /// consumer really is deregistered rather than merely idle.
    var subscriberCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return continuations.count
    }

    private func remove(_ id: Int) {
        lock.lock()
        continuations[id] = nil
        lock.unlock()
    }
}
