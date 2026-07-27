import XCTest

@testable import AirPortUtilityCore

final class WirelessRegionOptionTests: XCTestCase {
  func testWirelessRegionOptionsMatchBundledAirPortRegionCodes() {
    XCTAssertEqual(WirelessRegionOption.allCases.first?.code, "0")
    XCTAssertEqual(WirelessRegionOption.allCases.first?.name, "United States")
    XCTAssertEqual(WirelessRegionOption.allCases.count, 172)
    XCTAssertTrue(
      WirelessRegionOption.allCases.contains { $0.code == "36" && $0.name == "United Kingdom" })
    XCTAssertTrue(
      WirelessRegionOption.allCases.contains { $0.code == "172" && $0.name == "Myanmar" })
  }
}
