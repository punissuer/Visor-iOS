import XCTest
@testable import VisorTransport

final class PsmTests: XCTestCase {
    func testParsePsm() {
        XCTAssertEqual(parsePsm([0x00, 0x00, 0x81, 0x00]), 0x81)   // dynamic-range word wins
        XCTAssertEqual(parsePsm([0x05, 0x00]), 5)                  // else the fixed one
        XCTAssertNil(parsePsm([0x00, 0x10]))
        XCTAssertNil(parsePsm([]))
    }
}
