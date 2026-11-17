import Foundation

/// The byte pipe under AirShield. Implementations deliver whole SDUs.
public protocol Transport: AnyObject {
    func connect() async throws
    func send(_ frame: [UInt8]) async throws
    /// Exactly one SDU; suspends until a whole one arrives.
    func receive() async throws -> [UInt8]
    func close()
    /// The handshake is done: a leading bit 7 now starts a COMMAND frame, not a bare DataX message.
    func handshakeDone()
}

public extension Transport { func handshakeDone() {} }

public struct TransportClosedError: Error, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

/// Why a link would not open; says what a person could do about it.
public enum ConnectFailure { case bluetoothUnsupported, bluetoothOff, permissionRefused, badAddress, notPaired, noAnswer }

public struct TransportConnectError: Error, CustomStringConvertible {
    public let failure: ConnectFailure
    public let description: String
    public init(_ failure: ConnectFailure, _ description: String) { self.failure = failure; self.description = description }
}

/// How long the message starting at these bytes is (SDU framing on a byte stream).
public enum Sdu {
    public static let dataxHeader = 4, airshieldHeader = 10, longCommandHeader = 5, aesBlock = 16, minHead = 2

    /// Total length of the message at `head`, or nil if `head` is too short to say. Bit 7 means a bare DataX
    /// message until the handshake is done, and a COMMAND frame after it.
    public static func length(_ head: [UInt8], encrypted: Bool = false) -> Int? {
        guard head.count >= minHead else { return nil }
        let first = Int(head[0])
        if first & 0x80 != 0 {
            if !encrypted { return dataxHeader + ((first & 0x3F) << 8 | Int(head[1])) }
            if Int(head[1]) & 0x80 == 0 { return minHead }
            guard head.count >= longCommandHeader else { return nil }
            return longCommandHeader + (Int(head[2]) << 8 | Int(head[3]))
        }
        // Type 00: a sub-stream's PLAINTEXT frame, `[stream][length - 1]` and length bytes.
        if first & 0xC0 == 0 { return 3 + Int(head[1]) }
        guard head.count >= airshieldHeader else { return nil }
        return airshieldHeader + aesBlock * (Int(head[9]) + 1)
    }

    public static func headSize(_ head: [UInt8]) -> Int { head[0] & 0x80 != 0 ? longCommandHeader : airshieldHeader }

    /// Cuts a growing byte buffer into whole SDUs. Feed it what a stream delivers.
    public struct Reader {
        private var buffer: [UInt8] = []
        public var encrypted = false
        public init() {}
        public mutating func feed(_ bytes: [UInt8]) { buffer += bytes }
        public mutating func next() -> [UInt8]? {
            guard let total = Sdu.length(buffer, encrypted: encrypted), buffer.count >= total else { return nil }
            defer { buffer.removeFirst(total) }
            return Array(buffer[0..<total])
        }
    }
}
