import Foundation

/// DataX message ceiling, imposed by the 14-bit length field.
public let dataxMaxMessage = 16383
/// The BLE key exchange curve is P-256, not x25519.
public let resignProvisioningCapabilities: UInt64 = 2

/// AirShield substream frame type: the top two bits of the one-byte stream header.
public enum FrameType: Int { case data = 0x40, command = 0x80 }

public enum LinkSetupMsgType: Int { case requestEncryption = 1, enableEncryption = 2, endLinkSetup = 0x1000 }

public enum ServiceId: Int {
    case linkSetup = 5, identity = 36, connDeviceLease = 150, wirelessInput = 52822
}

public let svcAirship = 20, svcOTA = 29, svcLease = 56, svcTranslation = 72, svcMediaStreamingControl = 51350

public enum IdentityMsgType: Int {
    case enableTrust = 0x1000, enableTrustEC = 0x1001
    case skipChallenge = 0x2000, skipChallengeAck = 0x2001
    case startChangeOwnerReq = 0x2002, startChangeOwnerResp = 0x2003
    case finishChangeOwnerReq = 0x2004, finishChangeOwnerResp = 0x2005
    case identityRequest = 0x3000, identityResponse = 0x3001
    case manifestKey = 0x5000, enableECAuth = 0x5001
}

public enum IdentityStatus: Int {
    case success = 0x1000, failure = 0x1001, notSupported = 0x1002, unavailable = 0x1003
    case keyNotFound = 0x1010, invalidReceipt = 0x1040, invalidNonce = 0x1041, invalidUserId = 0x1042
    case invalidAppIdentity = 0x1043, invalidSignature = 0x1044, invalidTime = 0x1045
}

public struct HeaderFlags: Equatable {
    public var setType = false, hasError = false, isClosed = false
    public init(setType: Bool = false, hasError: Bool = false, isClosed: Bool = false) {
        self.setType = setType; self.hasError = hasError; self.isClosed = isClosed
    }
}

public struct MessageInfo: Equatable {
    public var flags: HeaderFlags
    /// The 14-bit payload length. It includes the extension tags.
    public var length: Int
    /// The 16-bit channel id. Its high bit says who opened the channel.
    public var channelId: Int
    public var serviceId = 0, messageType = 0, errorId = 0
    /// 4 plus four per extension tag.
    public var headerLen = 4
    /// Bytes on the wire: `4 + length`, never `headerLen + length`.
    public var wireTotal: Int { 4 + length }
}

public enum Header {
    private static let tagService = 1, tagMessageType = 2, tagError = 3, tagMessageTypeClosed = 4

    public static func parse(_ buf: [UInt8]) throws -> MessageInfo {
        guard buf.count >= 4 else { throw ProtocolFormatError("Buffer too short for fixed header: \(buf.count) < 4") }
        let b0 = Int(buf[0]), b1 = Int(buf[1]), b2 = Int(buf[2]), b3 = Int(buf[3])
        let hasExtension = b0 & 0x80 != 0
        let payloadLen = (b0 & 0x3F) << 8 | b1
        var info = MessageInfo(flags: HeaderFlags(), length: payloadLen, channelId: b2 << 8 | b3)
        if hasExtension {
            var offset = 4
            let available = min(buf.count, 4 + payloadLen)
            while offset + 4 <= available {
                let tagByte = Int(buf[offset])
                let continuation = tagByte >> 7 & 1
                let value = Int(buf[offset + 2]) << 8 | Int(buf[offset + 3])
                switch tagByte & 0x7F {
                case tagService:
                    info.serviceId = value; info.flags.setType = true
                    if value == 0 { info.flags.isClosed = true }
                case tagMessageType: info.messageType = value; info.flags.setType = true
                case tagError: info.errorId = value; info.flags.hasError = true
                case tagMessageTypeClosed: info.messageType = value; info.flags.isClosed = true
                default: break
                }
                info.headerLen += 4
                offset += 4
                if continuation == 0 { break }
            }
        }
        return info
    }

    public static func build(channelId: Int, dataLen: Int, serviceId: Int? = nil, messageType: Int? = nil, errorId: Int? = nil) -> [UInt8] {
        var tags: [(Int, Int)] = []
        if let s = serviceId { tags.append((tagService, s & 0xFFFF)) }
        if let m = messageType { tags.append((tagMessageType, m & 0xFFFF)) }
        if let e = errorId { tags.append((tagError, e & 0xFFFF)) }
        let payloadLen = tags.count * 4 + dataLen
        precondition(payloadLen <= dataxMaxMessage, "payload length \(payloadLen) exceeds \(dataxMaxMessage)")
        var out = [UInt8](repeating: 0, count: 4 + tags.count * 4)
        out[0] = UInt8((tags.isEmpty ? 0 : 0x80) | (payloadLen >> 8 & 0x3F))
        out[1] = UInt8(payloadLen & 0xFF)
        out[2] = UInt8(channelId >> 8 & 0xFF)
        out[3] = UInt8(channelId & 0xFF)
        for (i, (id, value)) in tags.enumerated() {
            let at = 4 + 4 * i
            out[at] = UInt8((i < tags.count - 1 ? 0x80 : 0) | (id & 0x7F))
            out[at + 2] = UInt8(value >> 8 & 0xFF)
            out[at + 3] = UInt8(value & 0xFF)
        }
        return out
    }
}

/// The one-byte outer header on each CoC frame: `[2-bit type | 6-bit stream id]`.
public enum Framing {
    public static let streamMask = 0x3F, typeMask = 0xC0

    public static func pack(_ type: FrameType, streamId: Int, body: [UInt8]) -> [UInt8] {
        precondition((0...streamMask).contains(streamId), "stream id out of range")
        return [UInt8(type.rawValue & typeMask | streamId & streamMask)] + body
    }

    public struct Frame { public let type: Int, streamId: Int, body: [UInt8] }

    public static func unpack(_ data: [UInt8]) throws -> Frame {
        guard let first = data.first else { throw ProtocolFormatError("empty frame") }
        return Frame(type: Int(first) & typeMask, streamId: Int(first) & streamMask, body: Array(data.dropFirst()))
    }
}
