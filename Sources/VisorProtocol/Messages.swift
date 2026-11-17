import Foundation

public struct RequestEncryption {
    public var publicKey: [UInt8], challenge: [UInt8]
    public var ellipticCurve = 0, supportedParameters: Int
    public var keyHint: [[UInt8]] = []
    public var quirks = 0, airshieldVersion = 16
    public var hasSupportedParameters = true

    public init(publicKey: [UInt8], challenge: [UInt8], supportedParameters: Int) {
        self.publicKey = publicKey; self.challenge = challenge; self.supportedParameters = supportedParameters
    }

    public func encode() -> [UInt8] {
        var p = Wire.fieldBytes(1, publicKey) + Wire.fieldBytes(2, challenge)
        p += Wire.fieldVarint(3, UInt64(ellipticCurve)) + Wire.fieldVarint(4, UInt64(supportedParameters))
        for h in keyHint { p += Wire.fieldBytes(5, h) }
        return p + Wire.fieldVarintNonZero(6, UInt64(quirks)) + Wire.fieldVarint(7, UInt64(airshieldVersion))
    }

    public static func decode(_ data: [UInt8]) throws -> RequestEncryption {
        let f = try Wire.parse(data)
        var r = RequestEncryption(publicKey: f.bytes(1), challenge: f.bytes(2), supportedParameters: Int(f.varint(4)))
        r.ellipticCurve = Int(f.varint(3)); r.keyHint = f.repeatedBytes(5)
        r.quirks = Int(f.varint(6)); r.airshieldVersion = Int(f.varint(7)); r.hasSupportedParameters = f.has(4)
        return r
    }
}

public struct EnableEncryption {
    public var publicKey: [UInt8], seed: [UInt8], iv: [UInt8]
    /// The sender's preamble seq, unsigned 32-bit.
    public var base: UInt64 = 0
    public var parameters: Int
    public var quirks = 0, phasedLinkSetupSupported = 0
    public var supportedLinkSetupServices: UInt64 = 0
    public var linkSwitchVersionSupported = 0
    public var hasParameters = true

    public init(publicKey: [UInt8], seed: [UInt8], iv: [UInt8], base: UInt64 = 0, parameters: Int) {
        self.publicKey = publicKey; self.seed = seed; self.iv = iv; self.base = base; self.parameters = parameters
    }

    /// Fields 1 to 5 always; 6 to 9 only when non-zero.
    public func encode() -> [UInt8] {
        Wire.fieldBytes(1, publicKey) + Wire.fieldBytes(2, seed) + Wire.fieldBytes(3, iv)
            + Wire.fieldVarint(4, base) + Wire.fieldVarint(5, UInt64(parameters))
            + Wire.fieldVarintNonZero(6, UInt64(quirks)) + Wire.fieldVarintNonZero(7, UInt64(phasedLinkSetupSupported))
            + Wire.fieldVarintNonZero(8, supportedLinkSetupServices) + Wire.fieldVarintNonZero(9, UInt64(linkSwitchVersionSupported))
    }

    public static func decode(_ data: [UInt8]) throws -> EnableEncryption {
        let f = try Wire.parse(data)
        let has = f.has(5)
        // Left out, the glasses mean 31: Multikey on.
        var e = EnableEncryption(publicKey: f.bytes(1), seed: f.bytes(2), iv: f.bytes(3), base: f.varint(4),
                                 parameters: has ? Int(f.varint(5)) : 31)
        e.quirks = Int(f.varint(6)); e.phasedLinkSetupSupported = Int(f.varint(7))
        e.supportedLinkSetupServices = f.varint(8); e.linkSwitchVersionSupported = Int(f.varint(9)); e.hasParameters = has
        return e
    }
}

/// The 16-byte UUIDs EndLinkSetup carries; the glasses drop the channel silently on a non-v4 uuid.
public enum LinkUuid {
    public static func random() -> [UInt8] { withUnsafeBytes(of: UUID().uuid) { Array($0) } }
    public static func isValid(_ b: [UInt8]) -> Bool { b.count == 16 && b[6] & 0xF0 == 0x40 && b[8] & 0xC0 == 0x80 }
}

public enum EndLinkSetup {
    public static let ready = 0, main = 1
    public static func encode(state: Int, streamUuid: [UInt8], linkUuid: [UInt8]) -> [UInt8] {
        precondition(LinkUuid.isValid(streamUuid) && LinkUuid.isValid(linkUuid), "EndLinkSetup uuids must be RFC 4122 v4")
        return Wire.fieldVarint(1, UInt64(state)) + Wire.fieldBytes(2, streamUuid) + Wire.fieldBytes(3, linkUuid)
    }
}
