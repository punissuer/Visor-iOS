import Foundation
import CoreBluetooth
import VisorTransport

struct FoundGlasses: Identifiable, Equatable {
    let id: UUID
    var name: String
    var rssi: Int
}

/// Looks for devices advertising Meta's GATT service (FD5F).
final class Scanner: NSObject, ObservableObject, CBCentralManagerDelegate {
    @Published var found: [FoundGlasses] = []
    @Published var status = "Starting Bluetooth…"
    private var central: CBCentralManager?

    func start() {
        if central == nil { central = CBCentralManager(delegate: self, queue: .main) }
        else if central?.state == .poweredOn { scan() }
    }

    func stop() { central?.stopScan() }

    private func scan() {
        found = []
        status = "Looking for glasses. Put them in pairing mode if they don't show up."
        central?.scanForPeripherals(withServices: [metaLEService], options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    }

    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        switch c.state {
        case .poweredOn: scan()
        case .unauthorized: status = "Bluetooth is off for Visor. Allow it in Settings."
        case .poweredOff: status = "Bluetooth is off."
        case .unsupported: status = "This device has no Bluetooth LE."
        default: break
        }
    }

    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let name = p.name ?? (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? "Meta glasses"
        let item = FoundGlasses(id: p.identifier, name: name, rssi: RSSI.intValue)
        if let i = found.firstIndex(where: { $0.id == item.id }) { found[i] = item } else { found.append(item) }
    }
}
