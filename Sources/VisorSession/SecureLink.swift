import Foundation
import VisorProtocol

/// RequestEncryption and EndLinkSetup ride the secure variant of channel 1, bit 15 set.
let linkSetupChannel = 0x8001
let enableChannel = 0x0001
let handshakeReads = 8
let ourParameters = 31
/// The most one frame holds: 256 blocks, less the pad's one byte at least.
let framePlaintext = 256 * 16 - 1

public struct HandshakeError: Error, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

/// The AirShield handshake plus the per-direction frame cipher.
public actor SecureLink {
    private let transport: Transport
    private var txCrypto: FrameCrypto?
    private var rxCrypto: FrameCrypto?
    private var pending: [[UInt8]] = []

    /// Channel binding material for the svc36 exchange. Nil until `open()` succeeds.
    public private(set) var binding: HandshakeBinding?
    public private(set) var handshake = ""
    public private(set) var peerAirshieldVersion = 0
    public nonisolated let linkUuid = LinkUuid.random()

    public init(transport: Transport) { self.transport = transport }

    private static func random(_ n: Int) -> [UInt8] { (0..<n).map { _ in UInt8.random(in: 0...255) } }

    public func open() async throws {
        let keyPair = Ecdh.generateEphemeral()
        let myPublic = keyPair.publicKey64
        let myChallenge = Self.random(16), mySeed = Self.random(32), myIv = Self.random(16)
        let mySeq = UInt32.random(in: 0...UInt32.max)

        try await sendLinkSetup(linkSetupChannel, .requestEncryption,
                                RequestEncryption(publicKey: myPublic, challenge: myChallenge, supportedParameters: ourParameters).encode())
        // Send our EnableEncryption immediately.
        try await sendLinkSetup(enableChannel, .enableEncryption,
                                EnableEncryption(publicKey: myPublic, seed: mySeed, iv: myIv, base: UInt64(mySeq), parameters: ourParameters).encode())

        var peerRequest: RequestEncryption?, peerEnable: EnableEncryption?
        for _ in 0..<handshakeReads {
            let sdu = try await transport.receive()
            if let f = sdu.first, Int(f) & Framing.typeMask == FrameType.data.rawValue {
                pending.append(sdu)   // An early encrypted frame, handled after open() returns.
                continue
            }
            let info = try Header.parse(sdu)
            guard sdu.count >= info.headerLen else { continue }
            let payload = Array(sdu[info.headerLen...])
            switch info.messageType {
            case LinkSetupMsgType.requestEncryption.rawValue: peerRequest = try RequestEncryption.decode(payload)
            case LinkSetupMsgType.enableEncryption.rawValue: peerEnable = try EnableEncryption.decode(payload)
            default: break
            }
            if peerRequest != nil && peerEnable != nil { break }
        }
        guard let request = peerRequest, let enable = peerEnable else {
            throw HandshakeError("handshake: missing RequestEncryption / EnableEncryption from peer")
        }
        // From here only DATA and COMMAND frames follow.
        transport.handshakeDone()

        let secret = try Ecdh.computeSharedSecret(keyPair.privateKey, peerPublic64: enable.publicKey)
        binding = HandshakeBinding(glChallenge: request.challenge, mySeed: mySeed, glReqPub: request.publicKey, myPub: myPublic)

        // What both ends support is what the link uses: the band offers 27, no Multikey.
        let multikey = ourParameters & request.supportedParameters & enable.parameters & Kdf.multikey != 0
        // RX takes our challenge and the peer's seed; TX takes the peer's challenge and our seed.
        // Each peer message's quirks pick its direction's HKDF info and MAC word.
        let rxKeys = Kdf.deriveDirectionKeys(ecdhSecret: secret, nonce: myChallenge, seed: enable.seed, preambleIv: enable.iv, multikey: multikey, quirks: enable.quirks)
        let txKeys = Kdf.deriveDirectionKeys(ecdhSecret: secret, nonce: request.challenge, seed: mySeed, preambleIv: myIv, multikey: multikey, quirks: request.quirks)
        rxCrypto = FrameCrypto(keys: rxKeys, initSeq: UInt32(truncatingIfNeeded: enable.base), quirks: enable.quirks)
        txCrypto = FrameCrypto(keys: txKeys, initSeq: mySeq, quirks: request.quirks)
        peerAirshieldVersion = request.airshieldVersion
        handshake = "peer quirks=\(request.quirks)/\(enable.quirks) airshield=\(request.airshieldVersion) multikey=\(multikey) queued=\(pending.count)"
        // EndLinkSetup is NOT sent here; see finishLinkSetup.
    }

    /// Send EndLinkSetup as the first encrypted DATA frame.
    public func finishLinkSetup(main: Bool = true) async throws {
        let body = EndLinkSetup.encode(state: main ? EndLinkSetup.main : EndLinkSetup.ready, streamUuid: LinkUuid.random(), linkUuid: linkUuid)
        try await send(Header.build(channelId: linkSetupChannel, dataLen: body.count, messageType: LinkSetupMsgType.endLinkSetup.rawValue) + body)
    }

    /// Seal and send. A message longer than one frame runs on into the next frames; the actor keeps others out of the middle.
    public func send(_ plaintext: [UInt8]) async throws {
        guard let crypto = txCrypto else { throw HandshakeError("link not open") }
        var at = 0
        repeat {
            let end = min(plaintext.count, at + framePlaintext)
            try await transport.send(Framing.pack(.data, streamId: 0, body: crypto.seal(Array(plaintext[at..<end]))))
            at = end
        } while at < plaintext.count
    }

    /// The plaintext of the next DATA frame; COMMAND frames and relay sub-streams are skipped.
    public func receive() async throws -> [UInt8] {
        while true {
            let sdu = pending.isEmpty ? try await transport.receive() : pending.removeFirst()
            guard let crypto = rxCrypto else { throw HandshakeError("link not open") }
            let frame = try Framing.unpack(sdu)
            if frame.streamId != 0 || frame.type != FrameType.data.rawValue { continue }
            return try crypto.unseal(frame.body)
        }
    }

    private func sendLinkSetup(_ channel: Int, _ type: LinkSetupMsgType, _ body: [UInt8]) async throws {
        // The service tag goes on the first message of the exchange only.
        let service = type == .requestEncryption ? ServiceId.linkSetup.rawValue : nil
        try await transport.send(Header.build(channelId: channel, dataLen: body.count, serviceId: service, messageType: type.rawValue) + body)
    }
}
