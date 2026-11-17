import Foundation
import Security

/// What the app knows about one identity. The JSON keys match the Android app's bundle format.
public struct IdentityBundle: Codable, Equatable {
    /// The owner key, PEM encoded.
    public var privateKeyPem: String
    /// On iOS: the glasses' CBPeripheral identifier (iOS never shows a Bluetooth address).
    public var glassesAddress: String
    public var serial: String
    public var createdAt: String
    /// How this pair was set up: `change-owner` or `band`.
    public var provenance: String
    public var state: String
    /// The glasses' key as Meta's final receipt names it, 64 raw bytes, base64.
    public var devicePublicKey: Data?

    public init(privateKeyPem: String, glassesAddress: String, serial: String, createdAt: String,
                provenance: String, state: String, devicePublicKey: Data? = nil) {
        self.privateKeyPem = privateKeyPem; self.glassesAddress = glassesAddress; self.serial = serial
        self.createdAt = createdAt; self.provenance = provenance; self.state = state; self.devicePublicKey = devicePublicKey
    }

    enum CodingKeys: String, CodingKey {
        case privateKeyPem = "private_key_pem", glassesAddress = "glasses_address", serial
        case createdAt = "created_at", provenance, state, devicePublicKey = "device_public_key"
    }
}

public enum BundleState {
    public static let unverified = "unverified", verified = "verified", evicted = "evicted"
}

/// UTC now as yyyy-MM-ddTHH:mm:ssZ.
public func nowIso() -> String {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f.string(from: Date())
}

/// Where secrets live: the Keychain on a device, memory in tests.
public protocol SecretStore: AnyObject {
    func read(_ name: String) throws -> Data?
    func write(_ name: String, _ data: Data) throws
    func delete(_ name: String) throws
}

public struct KeychainError: Error, CustomStringConvertible {
    public let status: OSStatus
    public var description: String { "Keychain error \(status)" }
}

/// Generic-password items, readable after first unlock and never leaving this device (no backup, no iCloud).
public final class KeychainSecretStore: SecretStore {
    private let service: String
    public init(service: String = "com.macedonga.visor.identity") { self.service = service }

    private func query(_ name: String) -> [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: name]
    }

    public func read(_ name: String) throws -> Data? {
        var q = query(name)
        q[kSecReturnData] = true; q[kSecMatchLimit] = kSecMatchLimitOne
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return nil }
        guard s == errSecSuccess else { throw KeychainError(status: s) }
        return out as? Data
    }

    public func write(_ name: String, _ data: Data) throws {
        let update = SecItemUpdate(query(name) as CFDictionary, [kSecValueData: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw KeychainError(status: update) }
        var add = query(name)
        add[kSecValueData] = data
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let s = SecItemAdd(add as CFDictionary, nil)
        guard s == errSecSuccess else { throw KeychainError(status: s) }
    }

    public func delete(_ name: String) throws {
        let s = SecItemDelete(query(name) as CFDictionary)
        guard s == errSecSuccess || s == errSecItemNotFound else { throw KeychainError(status: s) }
    }
}

public final class MemorySecretStore: SecretStore {
    private var items: [String: Data] = [:]
    public init() {}
    public func read(_ name: String) throws -> Data? { items[name] }
    public func write(_ name: String, _ data: Data) throws { items[name] = data }
    public func delete(_ name: String) throws { items[name] = nil }
}

/// Where bundles live: one JSON array in the secret store, and the chosen serial beside it.
public final class IdentityStore {
    private let secrets: SecretStore
    private let lock = NSLock()
    private static let bundlesKey = "identities", currentKey = "current"

    public init(secrets: SecretStore = KeychainSecretStore()) { self.secrets = secrets }

    public func all() throws -> [IdentityBundle] {
        lock.lock(); defer { lock.unlock() }
        return try allLocked()
    }

    private func allLocked() throws -> [IdentityBundle] {
        guard let data = try secrets.read(Self.bundlesKey) else { return [] }
        return try JSONDecoder().decode([IdentityBundle].self, from: data)
    }

    private func write(_ bundles: [IdentityBundle]) throws {
        try secrets.write(Self.bundlesKey, try JSONEncoder().encode(bundles))
    }

    public func load(serial: String) throws -> IdentityBundle? { try all().first { $0.serial == serial } }

    public func currentSerial() throws -> String? {
        guard let d = try secrets.read(Self.currentKey), let s = String(data: d, encoding: .utf8) else { return nil }
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }

    /// The pair last chosen, else the newest set up.
    public func chosen() throws -> IdentityBundle? {
        let bundles = try all()
        let current = try currentSerial()
        return bundles.first { $0.serial == current } ?? bundles.max { $0.createdAt < $1.createdAt }
    }

    public func choose(serial: String) throws {
        if try currentSerial() == serial { return }
        try secrets.write(Self.currentKey, Data(serial.utf8))
    }

    /// The one owner key this account uses, or nil before the first setup.
    public func ownerKeyPem() throws -> String? { try all().first?.privateKeyPem }

    /// Add or replace by serial.
    public func save(_ bundle: IdentityBundle) throws {
        lock.lock(); defer { lock.unlock() }
        try write(try allLocked().filter { $0.serial != bundle.serial } + [bundle])
    }

    /// Change the bundle for `serial` in place; false when it is gone or unchanged.
    @discardableResult
    public func update(serial: String, _ change: (inout IdentityBundle) -> Void) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        var bundles = try allLocked()
        guard let i = bundles.firstIndex(where: { $0.serial == serial }) else { return false }
        let old = bundles[i]
        change(&bundles[i])
        if bundles[i] == old { return false }
        try write(bundles)
        return true
    }

    /// Forget the glasses with `serial`: their bundle goes, the others stay.
    public func remove(serial: String) throws {
        lock.lock(); defer { lock.unlock() }
        try write(try allLocked().filter { $0.serial != serial })
        if try currentSerial() == serial { try secrets.delete(Self.currentKey) }
    }
}
