import Foundation

public struct ProtocolFormatError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// Minimal protobuf-lite primitives, enough for link-setup and service messages without generated stubs.
public enum Wire {
    public static func varint(_ value: UInt64) -> [UInt8] {
        var out: [UInt8] = []
        var v = value
        repeat {
            let b = UInt8(v & 0x7F)
            v >>= 7
            out.append(v != 0 ? b | 0x80 : b)
        } while v != 0
        return out
    }

    private static func tag(_ field: Int, _ wireType: Int) -> [UInt8] { varint(UInt64(field << 3 | wireType)) }

    public static func fieldVarint(_ field: Int, _ value: UInt64) -> [UInt8] { tag(field, 0) + varint(value) }
    /// Nothing for 0, as the firmware writes it.
    public static func fieldVarintNonZero(_ field: Int, _ value: UInt64) -> [UInt8] { value == 0 ? [] : fieldVarint(field, value) }
    public static func fieldBytes(_ field: Int, _ value: [UInt8]) -> [UInt8] { tag(field, 2) + varint(UInt64(value.count)) + value }
    public static func fieldString(_ field: Int, _ value: String) -> [UInt8] { fieldBytes(field, Array(value.utf8)) }
    public static func fieldFloat(_ field: Int, _ value: Float) -> [UInt8] {
        tag(field, 5) + (0..<4).map { UInt8(truncatingIfNeeded: value.bitPattern >> (8 * UInt32($0))) }
    }
    public static func fieldDouble(_ field: Int, _ value: Double) -> [UInt8] {
        tag(field, 1) + (0..<8).map { UInt8(truncatingIfNeeded: value.bitPattern >> (8 * UInt64($0))) }
    }

    public static func decodeVarint(_ data: [UInt8], _ offset: Int) throws -> (value: UInt64, offset: Int) {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        var at = offset
        while true {
            guard at < data.count else { throw ProtocolFormatError("truncated varint") }
            let b = data[at]
            at += 1
            result |= UInt64(b & 0x7F) << shift
            if b & 0x80 == 0 { return (result, at) }
            shift += 7
            if shift >= 64 { throw ProtocolFormatError("varint too long") }
        }
    }

    /// A parsed protobuf message: field number to the values read for it, in wire order.
    public struct Fields {
        enum Value { case varint(UInt64), bytes([UInt8]), fixed32(UInt32), fixed64(UInt64) }
        var byField: [Int: [Value]] = [:]

        public func bytes(_ fn: Int, default d: [UInt8] = []) -> [UInt8] {
            for case .bytes(let b) in byField[fn] ?? [] { return b }
            return d
        }
        public func varint(_ fn: Int, default d: UInt64 = 0) -> UInt64 {
            for case .varint(let v) in byField[fn] ?? [] { return v }
            return d
        }
        public func float(_ fn: Int, default d: Float = 0) -> Float {
            for case .fixed32(let v) in byField[fn] ?? [] { return Float(bitPattern: v) }
            return d
        }
        public func double(_ fn: Int, default d: Double = 0) -> Double {
            for case .fixed64(let v) in byField[fn] ?? [] { return Double(bitPattern: v) }
            return d
        }
        public func repeatedBytes(_ fn: Int) -> [[UInt8]] { (byField[fn] ?? []).compactMap { if case .bytes(let b) = $0 { return b }; return nil } }
        public func repeatedVarints(_ fn: Int) -> [UInt64] { (byField[fn] ?? []).compactMap { if case .varint(let v) = $0 { return v }; return nil } }
        public func has(_ fn: Int) -> Bool { byField[fn] != nil }
        public var fieldNumbers: [Int] { byField.keys.sorted() }
    }

    private static func littleEndian(_ data: [UInt8], _ at: Int, _ size: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in stride(from: size - 1, through: 0, by: -1) { v = v << 8 | UInt64(data[at + i]) }
        return v
    }

    /// Parse a flat protobuf message: varint, fixed and length-delimited fields.
    public static func parse(_ data: [UInt8]) throws -> Fields {
        var fields = Fields()
        var offset = 0
        let n = data.count
        while offset < n {
            let key = try decodeVarint(data, offset)
            offset = key.offset
            let fn = Int(truncatingIfNeeded: key.value >> 3)
            switch Int(key.value & 7) {
            case 0:
                let v = try decodeVarint(data, offset)
                offset = v.offset
                fields.byField[fn, default: []].append(.varint(v.value))
            case 2:
                let l = try decodeVarint(data, offset)
                offset = l.offset
                // A length past the end takes what is there and ends the parse.
                let remaining = UInt64(n - offset)
                let fits = l.value <= remaining
                let take = fits ? Int(l.value) : Int(remaining)
                fields.byField[fn, default: []].append(.bytes(Array(data[offset..<offset + take])))
                offset = fits ? offset + take : n
            case 5:
                if offset + 4 <= n { fields.byField[fn, default: []].append(.fixed32(UInt32(littleEndian(data, offset, 4)))) }
                offset += 4
            case 1:
                if offset + 8 <= n { fields.byField[fn, default: []].append(.fixed64(littleEndian(data, offset, 8))) }
                offset += 8
            default:
                throw ProtocolFormatError("unsupported wire type \(key.value & 7) for field \(fn)")
            }
        }
        return fields
    }
}
