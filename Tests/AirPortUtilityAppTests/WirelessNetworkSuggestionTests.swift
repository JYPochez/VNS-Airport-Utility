import XCTest

@testable import AirPortUtilityCore

@MainActor
final class WirelessNetworkSuggestionTests: XCTestCase {
  func testExtendableWirelessNetworkNamesDeduplicateScanResultsAndIncludeCurrentExtendName() {
    let model = AirportAppModel()
    model.wirelessScanNetworkNames = [
      "Jack's Network",
      " jack's network ",
      "Off",
      "",
      "Studio Wi-Fi",
    ]
    model.wireless.mode = "extend"
    model.wireless.networkName = "Manual Network"

    XCTAssertEqual(
      model.extendableWirelessNetworkNames,
      [
        "Jack's Network",
        "Studio Wi-Fi",
        "Manual Network",
      ])
  }

  func testExtendableWirelessNetworkNamesDoNotIncludeCurrentNameOutsideExtendMode() {
    let model = AirportAppModel()
    model.wirelessScanNetworkNames = ["Studio Wi-Fi"]
    model.wireless.mode = "create"
    model.wireless.networkName = "Created Network"

    XCTAssertEqual(model.extendableWirelessNetworkNames, ["Studio Wi-Fi"])
  }
}
