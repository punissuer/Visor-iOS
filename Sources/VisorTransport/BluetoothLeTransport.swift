import Foundation
import CoreBluetooth
import VisorSession

/// The GATT service the glasses expose, and the characteristic that holds their L2CAP PSM.
public let metaLEService = CBUUID(string: "FD5F")
public let metaPSMCharacteristic = CBUUID(string: "05acbe9f-6f61-4ca9-80bf-c8bbb52991c0")
/// The glasses' usual L2CAP PSM, tried before GATT is read.
public let metaLEDefaultPSM = 0x80

/// The PSM characteristic is 16-bit little-endian words, e.g. `00 00 81 00`; the channel's PSM is the word in the
/// LE dynamic range, else the fixed one.
public func parsePsm(_ value: [UInt8]) -> Int? {
    let words = (0..<value.count / 2).map { Int(value[$0 * 2]) | Int(value[$0 * 2 + 1]) << 8 }
    return words.first { (0x80...0xFF).contains($0) } ?? words.first { (0x01...0x7F).contains($0) }
}

private final class Once<T> {
    var c: CheckedContinuation<T, Error>?
    init(_ c: CheckedContinuation<T, Error>) { self.c = c }
    func resume(_ v: T) { c?.resume(returning: v); c = nil }
    func fail(_ e: Error) { c?.resume(throwing: e); c = nil }
}

/// One thread whose run loop serves every L2CAP stream.
private enum StreamThread {
    static let runLoop: RunLoop = {
        var rl: RunLoop!
        let ready = DispatchSemaphore(value: 0)
        let t = Thread {
            rl = RunLoop.current
            rl.add(Port(), forMode: .default)   // keeps the loop alive
            ready.signal()
            while true { rl.run(mode: .default, before: .distantFuture) }
        }
        t.name = "visor.l2cap"
        t.start()
        ready.wait()
        return rl
    }()
}

/// The byte pipe under AirShield over Bluetooth LE: an L2CAP channel to the glasses, found by the peripheral
/// identifier iOS gave them when they were first seen (iOS never shows a Bluetooth address).
public final class BluetoothLeTransport: NSObject, Transport, CBCentralManagerDelegate, CBPeripheralDelegate, StreamDelegate {
    private let identifier: UUID
    private let defaultPsm: Int
    private let q = DispatchQueue(label: "visor.ble")

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var channel: CBL2CAPChannel?

    private var stateWait: Once<CBManagerState>?
    private var scanWait: Once<CBPeripheral>?
    private var connectWait: Once<Void>?
    private var l2capWait: Once<CBL2CAPChannel>?
    private var psmWait: Once<Int?>?

    private var reader = Sdu.Reader()
    private var rxQueue: [[UInt8]] = []
    private var rxWaiter: CheckedContinuation<[UInt8], Error>?
    private var closedError: Error?
    private var outBuf: [UInt8] = []

    /// `identifier` is the glasses' CBPeripheral identifier. The Neural Band's PSM is 129.
    public init(identifier: UUID, defaultPsm: Int = metaLEDefaultPSM) {
        self.identifier = identifier
        self.defaultPsm = defaultPsm
    }

    private func wait<T>(_ seconds: Double, onTimeout: Error, start: @escaping (Once<T>) -> Void) async throws -> T {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<T, Error>) in
            q.async {
                let o = Once(c)
                start(o)
                self.q.asyncAfter(deadline: .now() + seconds) { o.fail(onTimeout) }
            }
        }
    }

    // MARK: connect

    public func connect() async throws {
        close()
        q.sync { closedError = nil; reader = Sdu.Reader(); rxQueue = []; outBuf = [] }

        let state: CBManagerState = try await wait(5, onTimeout: TransportConnectError(.bluetoothOff, "Bluetooth did not start")) { o in
            self.stateWait = o
            self.central = CBCentralManager(delegate: self, queue: self.q, options: nil)
            if self.central!.state != .unknown { self.stateWait = nil; o.resume(self.central!.state) }
        }
        switch state {
        case .poweredOn: break
        case .unsupported: throw TransportConnectError(.bluetoothUnsupported, "this device has no Bluetooth LE")
        case .unauthorized: throw TransportConnectError(.permissionRefused, "Visor may not use Bluetooth yet")
        default: throw TransportConnectError(.bluetoothOff, "Bluetooth is off")
        }

        let found = try await findPeripheral()
        peripheral = found
        found.delegate = self
        try await wait(8, onTimeout: TransportConnectError(.noAnswer, "the glasses did not connect")) { (o: Once<Void>) in
            self.connectWait = o
            self.central!.connect(found, options: nil)
        }

        do {
            channel = try await openL2cap(found, psm: defaultPsm)
        } catch let refused as TransportConnectError {
            // Read the PSM over GATT only when the usual one fails.
            guard let read = try await readPsm(found), read != defaultPsm else { throw refused }
            channel = try await openL2cap(found, psm: read)
        }
        let ch = channel!
        q.sync { self.attach(ch) }
    }

    private func findPeripheral() async throws -> CBPeripheral {
        if let known = central!.retrievePeripherals(withIdentifiers: [identifier]).first { return known }
        // Not known to iOS yet: it has to be heard advertising once.
        return try await wait(8, onTimeout: TransportConnectError(.noAnswer, "the glasses were not found")) { (o: Once<CBPeripheral>) in
            self.scanWait = o
            self.central!.scanForPeripherals(withServices: [metaLEService], options: nil)
        }
    }

    private func openL2cap(_ p: CBPeripheral, psm: Int) async throws -> CBL2CAPChannel {
        try await wait(8, onTimeout: TransportConnectError(.noAnswer, "the glasses did not open L2CAP psm \(psm): no answer in 8 s")) { o in
            self.l2capWait = o
            p.openL2CAPChannel(CBL2CAPPSM(psm))
        }
    }

    private func readPsm(_ p: CBPeripheral) async throws -> Int? {
        try await wait(6, onTimeout: TransportConnectError(.noAnswer, "the glasses did not give their PSM")) { (o: Once<Int?>) in
            self.psmWait = o
            p.discoverServices([metaLEService])
        }
    }

    // MARK: streams

    private func attach(_ ch: CBL2CAPChannel) {
        for s in [ch.inputStream, ch.outputStream] as [Stream] {
            s.delegate = self
            let rl = StreamThread.runLoop
            rl.perform { s.schedule(in: rl, forMode: .default); s.open() }
            CFRunLoopWakeUp(rl.getCFRunLoop())
        }
    }

    public func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        switch eventCode {
        case .hasBytesAvailable:
            guard let input = aStream as? InputStream else { return }
            var buf = [UInt8](repeating: 0, count: 4096)
            let n = input.read(&buf, maxLength: buf.count)
            if n > 0 { let bytes = Array(buf[0..<n]); q.async { self.received(bytes) } }
            else if n < 0 { q.async { self.closed("the link went away while reading") } }
        case .hasSpaceAvailable:
            q.async { self.pump() }
        case .endEncountered:
            q.async { self.closed("the peer closed the link") }
        case .errorOccurred:
            q.async { self.closed("the link went away") }
        default: break
        }
    }

    private func received(_ bytes: [UInt8]) {
        reader.feed(bytes)
        while let sdu = reader.next() { rxQueue.append(sdu) }
        if let w = rxWaiter, !rxQueue.isEmpty { rxWaiter = nil; w.resume(returning: rxQueue.removeFirst()) }
    }

    private func closed(_ why: String) {
        guard closedError == nil else { return }
        let e = TransportClosedError(why)
        closedError = e
        rxWaiter?.resume(throwing: e); rxWaiter = nil
    }

    private func pump() {
        guard let out = channel?.outputStream, out.hasSpaceAvailable, !outBuf.isEmpty else { return }
        let n = outBuf.withUnsafeBufferPointer { out.write($0.baseAddress!, maxLength: $0.count) }
        if n > 0 { outBuf.removeFirst(n) } else if n < 0 { closed("the link went away while sending") }
        if !outBuf.isEmpty && out.hasSpaceAvailable { pump() }
    }

    // MARK: Transport

    public func send(_ frame: [UInt8]) async throws {
        try q.sync {
            if let e = closedError { throw e }
            guard channel != nil else { throw TransportClosedError("not connected") }
            outBuf += frame
            pump()
        }
    }

    public func receive() async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<[UInt8], Error>) in
            q.async {
                if !self.rxQueue.isEmpty { c.resume(returning: self.rxQueue.removeFirst()) }
                else if let e = self.closedError { c.resume(throwing: e) }
                else { self.rxWaiter = c }
            }
        }
    }

    public func handshakeDone() { q.sync { reader.encrypted = true } }

    public func close() {
        q.sync {
            closed("closed")
            if let ch = channel {
                for s in [ch.inputStream, ch.outputStream] as [Stream] { s.delegate = nil; s.close() }
            }
            channel = nil
            if let p = peripheral, let c = central { c.cancelPeripheralConnection(p) }
            central?.stopScan()
            peripheral = nil
        }
    }

    // MARK: CoreBluetooth delegates

    public func centralManagerDidUpdateState(_ c: CBCentralManager) {
        if c.state != .unknown, let w = stateWait { stateWait = nil; w.resume(c.state) }
    }

    public func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard p.identifier == identifier, let w = scanWait else { return }
        scanWait = nil; c.stopScan(); w.resume(p)
    }

    public func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        connectWait?.resume(()); connectWait = nil
    }

    public func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        connectWait?.fail(TransportConnectError(.noAnswer, "the glasses did not connect: \(error?.localizedDescription ?? "no reason")")); connectWait = nil
    }

    public func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        closed("the glasses disconnected")
        psmWait?.resume(nil); psmWait = nil
    }

    public func peripheral(_ p: CBPeripheral, didOpen ch: CBL2CAPChannel?, error: Error?) {
        if let ch = ch { l2capWait?.resume(ch) }
        else { l2capWait?.fail(TransportConnectError(.noAnswer, "the glasses did not open L2CAP: \(error?.localizedDescription ?? "refused")")) }
        l2capWait = nil
    }

    public func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == metaLEService }) else { psmWait?.resume(nil); psmWait = nil; return }
        p.discoverCharacteristics([metaPSMCharacteristic], for: s)
    }

    public func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        guard let c = s.characteristics?.first(where: { $0.uuid == metaPSMCharacteristic }) else { psmWait?.resume(nil); psmWait = nil; return }
        p.readValue(for: c)
    }

    public func peripheral(_ p: CBPeripheral, didUpdateValueFor c: CBCharacteristic, error: Error?) {
        psmWait?.resume(error == nil ? c.value.flatMap { parsePsm([UInt8]($0)) } : nil); psmWait = nil
    }
}
