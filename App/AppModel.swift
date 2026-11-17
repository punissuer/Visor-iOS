import Foundation
import VisorProtocol
import VisorSession
import VisorIdentity
import VisorTransport

enum LinkPhase: Equatable {
    case idle, connecting, handshaking, up, failed(String)
}

/// The chosen glasses and the one session to them.
@MainActor
final class AppModel: ObservableObject {
    @Published var phase: LinkPhase = .idle
    @Published var log: [String] = []
    @Published var glassesId: UUID? = UserDefaults.standard.string(forKey: "glasses").flatMap(UUID.init)
    @Published var glassesName: String = UserDefaults.standard.string(forKey: "glassesName") ?? ""
    @Published var hasIdentity = false

    let store = IdentityStore()
    private var transport: BluetoothLeTransport?
    private var connection: DataXConnection?
    private var task: Task<Void, Never>?

    init() { refreshIdentity() }

    func refreshIdentity() { hasIdentity = ((try? store.chosen()) ?? nil) != nil }

    func choose(_ g: FoundGlasses) {
        glassesId = g.id; glassesName = g.name
        UserDefaults.standard.set(g.id.uuidString, forKey: "glasses")
        UserDefaults.standard.set(g.name, forKey: "glassesName")
    }

    func forget() {
        disconnect()
        glassesId = nil; glassesName = ""
        UserDefaults.standard.removeObject(forKey: "glasses")
        UserDefaults.standard.removeObject(forKey: "glassesName")
    }

    private func note(_ s: String) {
        let t = DateFormatter(); t.dateFormat = "HH:mm:ss"
        log.append("\(t.string(from: Date()))  \(s)")
        if log.count > 500 { log.removeFirst(100) }
    }

    func connect() {
        guard let id = glassesId, task == nil else { return }
        log = []
        phase = .connecting
        task = Task { [weak self] in
            guard let self else { return }
            do { try await self.run(id) }
            catch is CancellationError { }
            catch { self.phase = .failed("\(error)"); self.note("failed: \(error)") }
            self.task = nil
        }
    }

    func disconnect() {
        task?.cancel(); task = nil
        transport?.close(); transport = nil
        if let c = connection { Task { await c.stop() } }
        connection = nil
        phase = .idle
    }

    private func run(_ id: UUID) async throws {
        let t = BluetoothLeTransport(identifier: id)
        transport = t
        note("opening Bluetooth LE link")
        try await t.connect()
        note("L2CAP channel open")
        phase = .handshaking
        let link = SecureLink(transport: t)
        try await link.open()
        note("AirShield handshake done: \(await link.handshake)")
        let conn = DataXConnection(link: link)
        connection = conn
        await conn.startReader()

        if let bundle = try store.chosen(), let binding = await link.binding {
            let creds = try BundleCredentials(pem: bundle.privateKeyPem)
            let r = try await IdentityTrustExchange(credentials: creds).run(connection: conn, binding: binding)
            note("trust: tx=\(r.txOk) rx=\(r.rxOk)" + (r.refusal.map { " refusal=0x\(String($0, radix: 16))" } ?? ""))
            guard r.complete else { throw HandshakeError("the glasses did not accept this phone's identity") }
        } else {
            note("no owner identity on this phone yet, so trust is skipped (setup is not ported yet)")
        }
        try await link.finishLinkSetup()
        note("EndLinkSetup sent")
        phase = .up
        while true {
            guard let m = try await conn.receive() else { continue }
            let i = m.info
            note(String(format: "svc%d type 0x%04x ch 0x%04x %d bytes", i.serviceId, i.messageType, i.channelId, m.payload.count))
        }
    }
}
