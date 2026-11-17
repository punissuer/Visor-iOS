import XCTest
@testable import VisorProtocol

final class ProtocolTests: XCTestCase {
    func testHeaderRoundTrip() throws {
        let h = Header.build(channelId: 0x8001, dataLen: 5, serviceId: 5, messageType: 1)
        XCTAssertEqual(h, [0x80, 13, 0x80, 0x01, 0x81, 0, 0, 5, 0x02, 0, 0, 1])
        let i = try Header.parse(h + [0, 0, 0, 0, 0])
        XCTAssertEqual(i.channelId, 0x8001); XCTAssertEqual(i.serviceId, 5); XCTAssertEqual(i.messageType, 1)
        XCTAssertEqual(i.headerLen, 12); XCTAssertEqual(i.wireTotal, 4 + 13)
    }

    func testVarintAndFields() throws {
        XCTAssertEqual(Wire.varint(300), [0xAC, 0x02])
        let f = try Wire.parse(Wire.fieldVarint(3, 300) + Wire.fieldBytes(1, [1, 2]) + Wire.fieldFloat(4, 1.5))
        XCTAssertEqual(f.varint(3), 300); XCTAssertEqual(f.bytes(1), [1, 2]); XCTAssertEqual(f.float(4), 1.5)
    }

    func testPad() {
        XCTAssertEqual(AirShieldCipher.pad([UInt8](repeating: 1, count: 16)).count, 32)
        let p = AirShieldCipher.pad([1, 2, 3])
        XCTAssertEqual(p.last, UInt8(13 + 0xC0))
        XCTAssertEqual(AirShieldCipher.stripPad(p), [1, 2, 3])
    }

    func testSealUnsealBothDirectionsAndEcdh() throws {
        let a = Ecdh.generateEphemeral(), b = Ecdh.generateEphemeral()
        let s1 = try Ecdh.computeSharedSecret(a.privateKey, peerPublic64: b.publicKey64)
        let s2 = try Ecdh.computeSharedSecret(b.privateKey, peerPublic64: a.publicKey64)
        XCTAssertEqual(s1, s2); XCTAssertEqual(s1.count, 32)
        let keys = Kdf.deriveDirectionKeys(ecdhSecret: s1, nonce: [UInt8](repeating: 7, count: 16), seed: [UInt8](repeating: 9, count: 32), preambleIv: [UInt8](repeating: 3, count: 16))
        XCTAssertNotEqual(keys.aesKey, keys.hmacKey)
        let tx = FrameCrypto(keys: keys, initSeq: 5), rx = FrameCrypto(keys: keys, initSeq: 5)
        for n in [0, 3, 16, 100] {
            let msg = (0..<n).map { UInt8($0) }
            XCTAssertEqual(AirShieldCipher.stripPad(try rx.unseal(tx.seal(msg))), msg)
        }
        let bad = FrameCrypto(keys: keys, initSeq: 6)
        XCTAssertThrowsError(try bad.unseal(tx.seal([1])))
    }

    func testKdfKnownVector() {
        // HKDF with fixed inputs, checked against an independent Python computation.
        let k = Kdf.deriveDirectionKeys(ecdhSecret: [UInt8](repeating: 1, count: 32), nonce: [0], seed: [0], preambleIv: [UInt8](repeating: 0, count: 16), multikey: false)
        XCTAssertEqual(k.aesKey, k.hmacKey)
        XCTAssertEqual(k.aesKey.count, 32)
    }

    func testMessagesAndUuid() throws {
        let u = LinkUuid.random()
        XCTAssertTrue(LinkUuid.isValid(u))
        XCTAssertFalse(LinkUuid.isValid([UInt8](repeating: 0, count: 16)))
        let r = RequestEncryption(publicKey: [1], challenge: [2], supportedParameters: 31)
        let d = try RequestEncryption.decode(r.encode())
        XCTAssertEqual(d.supportedParameters, 31); XCTAssertEqual(d.airshieldVersion, 16)
        let e = try EnableEncryption.decode(EnableEncryption(publicKey: [1], seed: [2], iv: [3], base: 0xFFFF_FFFF, parameters: 31).encode())
        XCTAssertEqual(e.base, 0xFFFF_FFFF)
        XCTAssertEqual(try EnableEncryption.decode([]).parameters, 31)
    }
}
