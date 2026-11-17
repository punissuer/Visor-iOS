import Foundation
import CryptoKit
import CommonCrypto

public struct AuthenticationError: Error, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

/// One direction's key set: AES-256, HMAC-SHA256, and the initial CBC IV.
public struct SessionKeys {
    public let aesKey: [UInt8], hmacKey: [UInt8], iv: [UInt8]
    public init(aesKey: [UInt8], hmacKey: [UInt8], iv: [UInt8]) { self.aesKey = aesKey; self.hmacKey = hmacKey; self.iv = iv }
}

private func sha256(_ parts: [UInt8]...) -> [UInt8] {
    var h = SHA256()
    for p in parts { h.update(data: p) }
    return Array(h.finalize())
}

private func hmac(_ key: [UInt8], _ data: [UInt8]) -> [UInt8] {
    Array(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
}

/// AirShield key schedule.
public enum Kdf {
    private static let airshieldInfo = Array("AirShield".utf8)
    private static let hmacDeriveLabel = Array("hmac_derive".utf8)
    private static let qcs7Info: [UInt8] = airshieldInfo + [UInt8](repeating: 0, count: 128 - airshieldInfo.count) + [32, 0, 0, 0, 0, 1, 0, 0]

    /// EncryptionParameters flag 0x04: a separate HMAC key.
    public static let multikey = 4
    public static let quirksQcs7 = 1

    public static func deriveDirectionKeys(ecdhSecret: [UInt8], nonce: [UInt8], seed: [UInt8], preambleIv: [UInt8],
                                           multikey: Bool = true, quirks: Int = 0) -> SessionKeys {
        precondition(ecdhSecret.count == 32 && preambleIv.count == 16)
        let info = quirks == quirksQcs7 ? qcs7Info : airshieldInfo
        func expand(_ salt: [UInt8]) -> [UInt8] { hmac(hmac(salt, ecdhSecret), info + [1]) }
        let aes = expand(sha256(nonce, seed))
        if !multikey { return SessionKeys(aesKey: aes, hmacKey: aes, iv: preambleIv) }
        return SessionKeys(aesKey: aes, hmacKey: expand(sha256(seed, nonce, hmacDeriveLabel)), iv: preambleIv)
    }
}

public enum AirShieldCipher {
    public static let tagSize = 8, block = 16, padOffset = 0xC0
    /// The 4-byte LE word ahead of the seq in the MAC: 02 02 00, then the link's quirks.
    public static let counterPrefix: UInt32 = 0x0000_0202

    /// Modified PKCS#7: pad byte is `padLen + 0xC0`; aligned input gets a whole block.
    public static func pad(_ data: [UInt8]) -> [UInt8] {
        let n = block - data.count % block
        return data + [UInt8](repeating: UInt8((n + padOffset) & 0xFF), count: n)
    }

    /// Data without the pad `pad` adds; data not ending in one comes back whole.
    public static func stripPad(_ data: [UInt8]) -> [UInt8] {
        guard let last = data.last else { return data }
        let n = (Int(last) - padOffset) & 0xFF
        guard (1...block).contains(n), n <= data.count else { return data }
        if data[(data.count - n)...].contains(where: { $0 != last }) { return data }
        return Array(data.dropLast(n))
    }

    static func aesCbc(key: [UInt8], iv: [UInt8], data: [UInt8], encrypt: Bool) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: data.count)
        var moved = 0
        let status = CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), 0,
                             key, key.count, iv, data, data.count, &out, out.count, &moved)
        precondition(status == kCCSuccess && moved == data.count, "AES-CBC failed")
        return out
    }

    static func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * UInt32($0))) } }
}

/// One direction's crypto on AirShield DATA frame bodies.
public final class FrameCrypto {
    private let aesKey: [UInt8], hmacKey: [UInt8]
    private var iv: [UInt8]
    private var seq: UInt32
    private let macPrefix: [UInt8]

    public init(keys: SessionKeys, initSeq: UInt32 = 0, quirks: Int = 0) {
        precondition(keys.aesKey.count == 32 && keys.hmacKey.count == 32 && keys.iv.count == 16)
        aesKey = keys.aesKey; hmacKey = keys.hmacKey; iv = keys.iv; seq = initSeq
        macPrefix = AirShieldCipher.le32(AirShieldCipher.counterPrefix | UInt32(quirks & 0xFF) << 24)
    }

    private func mac(_ blockCount: Int, _ ct: [UInt8]) -> [UInt8] {
        Array(hmac(hmacKey, macPrefix + AirShieldCipher.le32(seq) + [UInt8(blockCount)] + ct).prefix(AirShieldCipher.tagSize))
    }

    public func seal(_ plaintext: [UInt8]) -> [UInt8] {
        let ct = AirShieldCipher.aesCbc(key: aesKey, iv: iv, data: AirShieldCipher.pad(plaintext), encrypt: true)
        let blockCount = ct.count / AirShieldCipher.block - 1
        precondition((0...0xFF).contains(blockCount), "plaintext too large for a single AirShield frame")
        let frame = mac(blockCount, ct) + [UInt8(blockCount)] + ct
        iv = Array(ct.suffix(AirShieldCipher.block))
        seq &+= 1
        return frame
    }

    /// Verify and decrypt one DATA frame body. The pad stays: DataX strips it.
    public func unseal(_ frame: [UInt8]) throws -> [UInt8] {
        guard frame.count >= AirShieldCipher.tagSize + 1 + AirShieldCipher.block else { throw AuthenticationError("frame too short") }
        let tag = Array(frame[0..<AirShieldCipher.tagSize])
        let blockCount = Int(frame[AirShieldCipher.tagSize])
        let ct = Array(frame[(AirShieldCipher.tagSize + 1)...])
        guard ct.count == (blockCount + 1) * AirShieldCipher.block else { throw AuthenticationError("ciphertext length does not match the block count") }
        guard tag == mac(blockCount, ct) else { throw AuthenticationError("MAC verification failed") }
        let pt = AirShieldCipher.aesCbc(key: aesKey, iv: iv, data: ct, encrypt: false)
        iv = Array(ct.suffix(AirShieldCipher.block))
        seq &+= 1
        return pt
    }
}

/// ECDH on P-256. Wire form of a public key is 64 raw bytes `x ‖ y`.
public struct EphemeralKeyPair {
    public let privateKey: P256.KeyAgreement.PrivateKey
    public var publicKey64: [UInt8] { Array(privateKey.publicKey.x963Representation.dropFirst()) }
}

public enum Ecdh {
    public static func generateEphemeral() -> EphemeralKeyPair { EphemeralKeyPair(privateKey: P256.KeyAgreement.PrivateKey()) }

    public static func computeSharedSecret(_ priv: P256.KeyAgreement.PrivateKey, peerPublic64: [UInt8]) throws -> [UInt8] {
        guard peerPublic64.count == 64 else { throw ProtocolFormatError("peer public key must be 64 bytes") }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04] + peerPublic64))
        // The raw X coordinate of the shared point, which is what CryptoKit's secret holds.
        return try priv.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Array($0) }
    }
}

/// The reconnect channel binding svc36 trust signs.
public struct HandshakeBinding {
    public let glChallenge: [UInt8], mySeed: [UInt8], glReqPub: [UInt8], myPub: [UInt8]
    public init(glChallenge: [UInt8], mySeed: [UInt8], glReqPub: [UInt8], myPub: [UInt8]) {
        self.glChallenge = glChallenge; self.mySeed = mySeed; self.glReqPub = glReqPub; self.myPub = myPub
    }
    /// `SHA256(SHA256(glChallenge ‖ glReqPub) ‖ SHA256(mySeed ‖ myPub))`.
    public func txChallenge() -> [UInt8] { sha256(sha256(glChallenge, glReqPub), sha256(mySeed, myPub)) }
}
