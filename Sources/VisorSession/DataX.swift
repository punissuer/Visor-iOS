import Foundation
import VisorProtocol

public struct DataXMessage {
    public let info: MessageInfo
    public let payload: [UInt8]
    /// On a close, the channel's service.
    public var closedService = 0
}

public struct ChannelRefused: Error, CustomStringConvertible {
    public let description: String
}

public let originatorBit = 0x8000
public func hasOriginatorBit(_ ch: Int) -> Bool { ch & originatorBit != 0 }
/// The ack channel for a peer-opened channel: the originator bit cleared.
public func mirror(_ ch: Int) -> Int { ch & (originatorBit - 1) }
/// The reply channel: bit flipped, so our own channels get it back and the glasses' get their mirror.
public func own(_ ch: Int) -> Int { ch ^ originatorBit }

/// Which DataX channel is talking to which service.
struct ChannelRegistry {
    private var local: [Int: Int] = [:], peer: [Int: Int] = [:]
    private var next = 2   // Not 1: 0x8001 is the link setup channel.
    private func key(_ ch: Int) -> Int { ch & (originatorBit - 1) }

    mutating func nextLocalChannel() -> Int { defer { next += 1 }; return originatorBit | next }
    mutating func bindLocal(_ ch: Int, _ svc: Int) { local[key(ch)] = svc }
    func localService(_ ch: Int) -> Int { local[key(ch)] ?? 0 }
    mutating func bindInbound(_ ch: Int, _ svc: Int) {
        if hasOriginatorBit(ch) { peer[key(ch)] = svc } else { local[key(ch)] = svc }
    }
    func serviceForInbound(_ ch: Int) -> Int { (hasOriginatorBit(ch) ? peer : local)[key(ch)] ?? 0 }
    mutating func closeInbound(_ ch: Int) -> Int {
        hasOriginatorBit(ch) ? (peer.removeValue(forKey: key(ch)) ?? 0) : (local.removeValue(forKey: key(ch)) ?? 0)
    }
}

/// The channel mux riding on one `SecureLink`.
public actor DataXConnection {
    private let link: SecureLink
    private var registry = ChannelRegistry()
    private var rxLastType: [Int: Int] = [:]
    private var carry: [UInt8] = []

    private var inbox: [DataXMessage] = []
    private var waiters: [(id: Int, cont: CheckedContinuation<DataXMessage?, Error>)] = []
    private var nextWaiter = 0
    private var failure: Error?
    private var reader: Task<Void, Never>?
    private var serviceChannels: [Int: Int] = [:]

    public init(link: SecureLink) { self.link = link }

    public var hasReader: Bool { reader != nil }

    /// Start the one task that reads the link into this connection.
    public func startReader() {
        precondition(reader == nil, "this connection already has a reader")
        reader = Task { [link] in
            do {
                while true {
                    let plaintext = try await link.receive()
                    for m in try self.decode(plaintext) { self.deliver(m) }
                }
            } catch { self.fail(error) }
        }
    }

    public func stop() { reader?.cancel(); fail(CancellationError()) }

    private func deliver(_ m: DataXMessage) {
        var m = m
        if m.info.flags.isClosed && m.closedService == 0 { m.closedService = registry.closeInbound(m.info.channelId) }
        if waiters.isEmpty { inbox.append(m) } else { waiters.removeFirst().cont.resume(returning: m) }
    }

    private func fail(_ e: Error) {
        failure = e
        let w = waiters; waiters = []
        for x in w { x.cont.resume(throwing: e) }
    }

    /// The next message, or nil after `timeout` seconds.
    public func receive(timeout: TimeInterval? = nil) async throws -> DataXMessage? {
        if !inbox.isEmpty { return inbox.removeFirst() }
        if let f = failure { throw f }
        let id = nextWaiter; nextWaiter += 1
        if let t = timeout {
            Task { try? await Task.sleep(nanoseconds: UInt64(t * 1e9)); self.expire(id) }
        }
        return try await withCheckedThrowingContinuation { waiters.append((id, $0)) }
    }

    private func expire(_ id: Int) {
        if let i = waiters.firstIndex(where: { $0.id == id }) { waiters.remove(at: i).cont.resume(returning: nil) }
    }

    /// Return messages to the front of the inbox, in their original order.
    public func pushback(_ messages: [DataXMessage]) { inbox.insert(contentsOf: messages, at: 0) }

    /// Allocate a local channel id for `serviceId` and bind it.
    public func openChannel(_ serviceId: Int) -> Int {
        let ch = registry.nextLocalChannel()
        registry.bindLocal(ch, serviceId)
        return ch
    }

    public func localService(_ ch: Int) -> Int { registry.localService(ch) }

    /// Send one DataX message. A channel with the originator bit must be open here, for `serviceId` if given.
    public func send(channel: Int, payload: [UInt8], messageType: Int? = nil, serviceId: Int? = nil) async throws {
        if hasOriginatorBit(channel) {
            let bound = registry.localService(channel)
            if bound == 0 || (serviceId != nil && serviceId != bound) {
                throw ChannelRefused(description: "refused a send on channel \(String(channel, radix: 16)): tag \(serviceId.map(String.init) ?? "none"), open for \(bound)")
            }
        }
        try await write(Header.build(channelId: channel, dataLen: payload.count, serviceId: serviceId, messageType: messageType) + payload)
    }

    /// Send on this connection's one channel for `serviceId`, opening it the first time. The glasses answer on every
    /// open channel of a service, so a channel per request would multiply every reply.
    public func sendOnService(_ serviceId: Int, messageType: Int, payload: [UInt8]) async throws {
        if let known = serviceChannels[serviceId], registry.localService(known) == serviceId {
            try await send(channel: known, payload: payload, messageType: messageType)
            return
        }
        let ch = openChannel(serviceId)
        serviceChannels[serviceId] = ch
        try await send(channel: ch, payload: payload, messageType: messageType, serviceId: serviceId)
    }

    /// Forget a channel as its service's channel, so the next `sendOnService` opens a new one.
    public func forgetServiceChannel(_ ch: Int) {
        serviceChannels = serviceChannels.filter { mirror($0.value) != mirror(ch) }
    }

    /// A bare DataX status frame: an error id tag, zero payload.
    public func sendStatus(channel: Int, errorId: Int) async throws {
        try await write(Header.build(channelId: channel, dataLen: 0, errorId: errorId))
    }

    private func write(_ plaintext: [UInt8]) async throws {
        if failure != nil { throw TransportClosedError("the link under this connection has gone") }
        try await link.send(plaintext)
    }

    private func decode(_ plaintext: [UInt8]) throws -> [DataXMessage] {
        // Pad off first, then messages of `4 + length`, which may run across frames.
        let stream = carry + AirShieldCipher.stripPad(plaintext)
        var out: [DataXMessage] = []
        var pos = 0
        while stream.count - pos >= 4 {
            let total = try Header.parse(Array(stream[pos..<pos + 4])).wireTotal
            if stream.count - pos < total { break }
            let whole = Array(stream[pos..<pos + total])
            let info = applyTypeCache(try Header.parse(whole))
            out.append(DataXMessage(info: info, payload: Array(whole[min(info.headerLen, whole.count)...])))
            pos += total
        }
        carry = Array(stream[pos...])
        return out
    }

    /// Per-channel messageType cache: a frame without a type tag takes the last one.
    private func applyTypeCache(_ info: MessageInfo) -> MessageInfo {
        var info = info
        if info.flags.setType || info.messageType != 0 { rxLastType[info.channelId] = info.messageType; return info }
        if !info.flags.hasError, let cached = rxLastType[info.channelId] { info.messageType = cached }
        return info
    }
}
