import XCTest
import CryptoKit
@testable import VisorIdentity

final class IdentityStoreTests: XCTestCase {
    func bundle(_ serial: String, _ created: String, key: Data? = nil) -> IdentityBundle {
        IdentityBundle(privateKeyPem: P256.Signing.PrivateKey().pemRepresentation, glassesAddress: "uuid-\(serial)",
                       serial: serial, createdAt: created, provenance: "change-owner", state: BundleState.unverified, devicePublicKey: key)
    }

    func testCrud() throws {
        let s = IdentityStore(secrets: MemorySecretStore())
        XCTAssertNil(try s.chosen()); XCTAssertNil(try s.ownerKeyPem())
        let a = bundle("A", "2026-01-01T00:00:00Z"), b = bundle("B", "2026-02-01T00:00:00Z", key: Data(repeating: 7, count: 64))
        try s.save(a); try s.save(b)
        XCTAssertEqual(try s.chosen()?.serial, "B")          // newest, none chosen
        try s.choose(serial: "A")
        XCTAssertEqual(try s.chosen()?.serial, "A")
        XCTAssertEqual(try s.load(serial: "B")?.devicePublicKey, Data(repeating: 7, count: 64))
        XCTAssertEqual(try s.ownerKeyPem(), a.privateKeyPem) // first saved
        XCTAssertTrue(try s.update(serial: "A") { $0.state = BundleState.verified })
        XCTAssertFalse(try s.update(serial: "A") { $0.state = BundleState.verified })
        XCTAssertFalse(try s.update(serial: "nope") { _ in })
        try s.save(bundle("A", "2026-03-01T00:00:00Z"))      // replace by serial
        XCTAssertEqual(try s.all().count, 2)
        try s.remove(serial: "A")
        XCTAssertNil(try s.currentSerial()); XCTAssertEqual(try s.chosen()?.serial, "B")
    }

    func testJsonMatchesAndroidFormat() throws {
        let b = bundle("S", "t", key: Data([1, 2]))
        let obj = try JSONSerialization.jsonObject(with: JSONEncoder().encode(b)) as! [String: Any]
        XCTAssertEqual(Set(obj.keys), ["private_key_pem", "glasses_address", "serial", "created_at", "provenance", "state", "device_public_key"])
        XCTAssertEqual(obj["device_public_key"] as? String, "AQI=")   // base64, as Android writes it
    }

    func testKeychainRoundTrip() throws {
        let k = KeychainSecretStore(service: "visor.test.\(UUID())")
        do { try k.write("x", Data([1])) } catch let e as KeychainError { throw XCTSkip("no usable keychain here: \(e)") }
        try k.write("x", Data([2]))
        XCTAssertEqual(try k.read("x"), Data([2]))
        try k.delete("x")
        XCTAssertNil(try k.read("x"))
    }
}
