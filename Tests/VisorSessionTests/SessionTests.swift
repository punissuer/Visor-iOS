import XCTest
import CryptoKit
import Security
@testable import VisorProtocol
@testable import VisorSession
@testable import VisorIdentity

/// Two in-memory ends joined by queues.
final class Pipe: Transport {
    var inbox: [[UInt8]] = []; var peer: Pipe!
    var waiter: CheckedContinuation<[UInt8], Error>?
    func connect() async throws {}
    func send(_ f: [UInt8]) async throws { peer.push(f) }
    func push(_ f: [UInt8]) { if let w = waiter { waiter = nil; w.resume(returning: f) } else { inbox.append(f) } }
    func receive() async throws -> [UInt8] {
        if !inbox.isEmpty { return inbox.removeFirst() }
        return try await withCheckedThrowingContinuation { waiter = $0 }
    }
    func close() {}
}

final class SessionTests: XCTestCase {
    func testSduReader() {
        var r = Sdu.Reader()
        let msg = Header.build(channelId: 1, dataLen: 3, serviceId: 5) + [9, 9, 9]
        r.feed(Array(msg.prefix(3))); XCTAssertNil(r.next())
        r.feed(Array(msg.dropFirst(3)) + [0x40]); XCTAssertEqual(r.next(), msg)
    }

    func testHandshakeAndDataXBothWays() async throws {
        let a = Pipe(), b = Pipe(); a.peer = b; b.peer = a
        let la = SecureLink(transport: a), lb = SecureLink(transport: b)
        async let oa: Void = la.open(); async let ob: Void = lb.open()
        _ = try await (oa, ob)
        let ca = DataXConnection(link: la), cb = DataXConnection(link: lb)
        await ca.startReader(); await cb.startReader()
        let ch = await ca.openChannel(36)
        try await ca.send(channel: ch, payload: [1, 2, 3], messageType: 0x1000, serviceId: 36)
        let m = try await cb.receive(timeout: 2)
        XCTAssertEqual(m?.payload, [1, 2, 3]); XCTAssertEqual(m?.info.serviceId, 36); XCTAssertEqual(m?.info.messageType, 0x1000)
        // A message bigger than one frame crosses intact.
        let big = (0..<9000).map { UInt8($0 % 251) }
        try await cb.send(channel: mirror(ch), payload: big, messageType: 7, serviceId: nil)
        let n = try await ca.receive(timeout: 2)
        XCTAssertEqual(n?.payload, big)
        // Refuses a send on a channel it did not open.
        do { try await ca.send(channel: 0x8099, payload: []); XCTFail() } catch is ChannelRefused {}
    }

    func testSignatureLowSAndValid() throws {
        let key = P256.Signing.PrivateKey()
        for _ in 0..<20 {
            let digest = sha256((0..<8).map { _ in UInt8.random(in: 0...255) })
            let sig = try signDigest(key, digest: digest)
            XCTAssertEqual(sig.count, 64)
            XCTAssertFalse(sig[32...].lexicographicallyPrecedes([UInt8](repeating: 0, count: 32)))
            XCTAssertTrue(Array(sig[32...]).lexicographicallyPrecedes(Array(hex: "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A9")))
            // Verify through Security with a DER re-encoding.
            func der(_ v: [UInt8]) -> [UInt8] { var t = Array(v.drop(while: { $0 == 0 })); if (t.first ?? 0) >= 0x80 { t.insert(0, at: 0) }; if t.isEmpty { t = [0] }; return [0x02, UInt8(t.count)] + t }
            let body = der(Array(sig[0..<32])) + der(Array(sig[32...]))
            let pk = SecKeyCreateWithData(key.publicKey.x963Representation as CFData, [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, nil)!
            XCTAssertTrue(SecKeyVerifySignature(pk, .ecdsaSignatureDigestX962SHA256, Data(digest) as CFData, Data([0x30, UInt8(body.count)] + body) as CFData, nil))
        }
    }

    func testKeyHint() {
        let pub = (0..<64).map { UInt8($0) }
        let h = keyHint(pub)
        XCTAssertEqual(h.count, 12); XCTAssertEqual(h[0] >> 4, 3)
        XCTAssertTrue(keyHintMatches(h, pub))
        XCTAssertFalse(keyHintMatches(h, pub.reversed()))
    }

    func testTrustExchange() async throws {
        let a = Pipe(), b = Pipe(); a.peer = b; b.peer = a
        let la = SecureLink(transport: a), lb = SecureLink(transport: b)
        async let oa: Void = la.open(); async let ob: Void = lb.open()
        _ = try await (oa, ob)
        let phone = DataXConnection(link: la), glasses = DataXConnection(link: lb)
        await phone.startReader(); await glasses.startReader()
        let key = P256.Signing.PrivateKey()
        let creds = try BundleCredentials(pem: key.pemRepresentation)
        // The fake glasses: ack the phone's trust, then push their own.
        let g = Task {
            let m = try await glasses.receive(timeout: 2)!
            XCTAssertEqual(m.info.messageType, IdentityMsgType.enableTrust.rawValue)
            XCTAssertEqual(try Wire.parse(m.payload).bytes(1), sha256(creds.appPublicKey))
            try await glasses.sendStatus(channel: mirror(m.info.channelId), errorId: IdentityStatus.success.rawValue)
            let ch = await glasses.openChannel(36)
            try await glasses.send(channel: ch, payload: [], messageType: IdentityMsgType.enableTrustEC.rawValue, serviceId: 36)
        }
        let binding = HandshakeBinding(glChallenge: [1], mySeed: [2], glReqPub: [3], myPub: [4])
        let r = try await IdentityTrustExchange(credentials: creds).run(connection: phone, binding: binding)
        _ = try await g.value
        XCTAssertTrue(r.complete)
    }
}
