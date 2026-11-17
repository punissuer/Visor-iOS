import Foundation
import CryptoKit
import Security
import VisorProtocol
import VisorSession

public struct CredentialsError: Error, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

/// The owner key of one identity, from a PKCS#8 or SEC1 PEM.
public struct BundleCredentials {
    let key: P256.Signing.PrivateKey
    public init(pem: String) throws {
        do { key = try P256.Signing.PrivateKey(pemRepresentation: pem) }
        catch { throw CredentialsError("the owner key is not a P-256 PEM key") }
    }
    /// The public key as 64 raw bytes, x then y.
    public var appPublicKey: [UInt8] { Array(key.publicKey.x963Representation.dropFirst()) }
}

private let order = Array(hex: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
private let halfOrder = Array(hex: "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8")

extension Array where Element == UInt8 {
    init(hex: String) {
        var out: [UInt8] = []; var i = hex.startIndex
        while i < hex.endIndex { let j = hex.index(i, offsetBy: 2); out.append(UInt8(hex[i..<j], radix: 16)!); i = j }
        self = out
    }
}

/// Big-endian 32-byte compare.
private func gt(_ a: [UInt8], _ b: [UInt8]) -> Bool { a.lexicographicallyPrecedes(b) ? false : a != b }

/// order - s, both 32 bytes big endian.
private func negate(_ s: [UInt8]) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: 32); var borrow = 0
    for i in stride(from: 31, through: 0, by: -1) {
        var d = Int(order[i]) - Int(s[i]) - borrow
        if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
        out[i] = UInt8(d)
    }
    return out
}

private func fixed32(_ b: ArraySlice<UInt8>) -> [UInt8] {
    var v = Array(b.drop(while: { $0 == 0 }))
    if v.count > 32 { v = Array(v.suffix(32)) }
    return [UInt8](repeating: 0, count: 32 - v.count) + v
}

/// r and s out of a DER ECDSA signature.
func decodeDerSignature(_ der: [UInt8]) throws -> ([UInt8], [UInt8]) {
    func readLen(_ at: inout Int) throws -> Int {
        guard at < der.count else { throw CredentialsError("bad signature") }
        let b = Int(der[at]); at += 1
        if b < 0x80 { return b }
        let n = b & 0x7F; var l = 0
        for _ in 0..<n { guard at < der.count else { throw CredentialsError("bad signature") }; l = l << 8 | Int(der[at]); at += 1 }
        return l
    }
    var at = 0
    guard der.first == 0x30 else { throw CredentialsError("bad signature") }
    at = 1; _ = try readLen(&at)
    var ints: [[UInt8]] = []
    for _ in 0..<2 {
        guard at < der.count, der[at] == 0x02 else { throw CredentialsError("bad signature") }
        at += 1
        let l = try readLen(&at)
        guard at + l <= der.count else { throw CredentialsError("bad signature") }
        ints.append(fixed32(der[at..<at + l])); at += l
    }
    return (ints[0], ints[1])
}

/// A SHA-256 digest signed as the glasses check signatures: no further hashing, r then low s, 64 bytes.
public func signDigest(_ key: P256.Signing.PrivateKey, digest: [UInt8]) throws -> [UInt8] {
    var err: Unmanaged<CFError>?
    let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
    guard let sk = SecKeyCreateWithData(key.x963Representation as CFData, attrs as CFDictionary, &err),
          let der = SecKeyCreateSignature(sk, .ecdsaSignatureDigestX962SHA256, Data(digest) as CFData, &err) as Data? else {
        throw CredentialsError("signing failed")
    }
    let (r, s) = try decodeDerSignature(Array(der))
    return r + (gt(s, halfOrder) ? negate(s) : s)
}

public func sha256(_ d: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: d)) }

/// SHA256(SHA256(key) ‖ salt)[:8]: a key hint's hash.
func hintHash(_ publicKey: [UInt8], _ salt: [UInt8]) -> [UInt8] { Array(sha256(sha256(publicKey) + salt).prefix(8)) }

/// Whether `hint` names `publicKey`: salt as long as the high nibble of its first byte plus one (none below 0x10).
public func keyHintMatches(_ hint: [UInt8], _ publicKey: [UInt8]) -> Bool {
    guard let f = hint.first, publicKey.count == 64 else { return false }
    let saltSize = f > 0x0F ? Int(f >> 4) + 1 : 0
    let rest = hint.count - saltSize
    guard rest > 0, rest <= 32 else { return false }
    let digest = sha256(sha256(publicKey) + Array(hint[0..<saltSize]))
    return Array(digest.prefix(rest)) == Array(hint[saltSize...])
}

/// A 12-byte key hint: 4-byte salt with first byte's high nibble 3 so the Display reads its length, then 8 hash bytes.
public func keyHint(_ publicKey: [UInt8]) -> [UInt8] {
    var salt = (0..<4).map { _ in UInt8.random(in: 0...255) }
    salt[0] = 0x30 | salt[0] & 0x0F
    return salt + hintHash(publicKey, salt)
}

public struct TrustResult { public var txOk = false, rxOk = false, refusal: Int?; public var complete: Bool { txOk && rxOk } }

/// The svc36 exchange the session runs between the handshake and EndLinkSetup.
public struct IdentityTrustExchange {
    let credentials: BundleCredentials
    public init(credentials: BundleCredentials) { self.credentials = credentials }

    func enableTrust(_ txChallenge: [UInt8]) throws -> [UInt8] {
        Wire.fieldBytes(1, sha256(credentials.appPublicKey)) + Wire.fieldBytes(2, try signDigest(credentials.key, digest: txChallenge))
            + Wire.fieldVarint(3, resignProvisioningCapabilities)
    }

    public func run(connection: DataXConnection, binding: HandshakeBinding, timeout: TimeInterval = 5) async throws -> TrustResult {
        let ch = await connection.openChannel(ServiceId.identity.rawValue)
        try await connection.send(channel: ch, payload: try enableTrust(binding.txChallenge()),
                                  messageType: IdentityMsgType.enableTrust.rawValue, serviceId: ServiceId.identity.rawValue)
        let statusChannel = mirror(ch)
        var result = TrustResult()
        var deferred: [DataXMessage] = []
        let deadline = Date().addingTimeInterval(timeout)
        while !result.complete {
            let left = deadline.timeIntervalSinceNow
            guard left > 0, let m = try await connection.receive(timeout: left) else { break }
            let i = m.info
            if i.flags.hasError && i.channelId == statusChannel {
                if i.errorId == IdentityStatus.success.rawValue { result.txOk = true } else { result.refusal = i.errorId }
            } else if hasOriginatorBit(i.channelId) && i.serviceId == ServiceId.identity.rawValue
                        && [IdentityMsgType.enableTrustEC.rawValue, IdentityMsgType.enableTrust.rawValue].contains(i.messageType) {
                try await connection.sendStatus(channel: mirror(i.channelId), errorId: IdentityStatus.success.rawValue)
                result.rxOk = true
            } else { deferred.append(m) }
        }
        await connection.pushback(deferred)
        return result
    }
}
