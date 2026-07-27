import XCTest

@testable import AirPortUtilityCore

@MainActor
final class ConfigurationFileTests: XCTestCase {
  func testSpaceshipBaseConfigurationRoundTripsSupportedLegacyOptions() throws {
    let model = AirportAppModel()
    model.applyAuthoritativeBaseStationIdentity(
      readName: "AirPort Extreme",
      serialNumber: "SPACESHIP",
      version: "5.7",
      productID: "3")
    model.legacyDeviceOptions.baseStation.contact = "Network Admin"
    model.legacyDeviceOptions.baseStation.location = "New York"
    model.legacyDeviceOptions.baseStation.setTimeAutomatically = true
    model.legacyDeviceOptions.baseStation.timeServer = "time.apple.com"
    model.legacyDeviceOptions.wireless.multicastRate = 85
    model.legacyDeviceOptions.wireless.transmitPower = 50
    model.legacyDeviceOptions.wireless.groupKeyTimeoutSeconds = 7_200
    model.legacyDeviceOptions.wireless.interferenceRobustness = true
    model.legacyDeviceOptions.dhcp.message = "Welcome"
    model.legacyDeviceOptions.dhcp.ldapServer = "ldap.example.test"
    model.legacyDeviceOptions.accessControl.mode = "local"
    model.legacyDeviceOptions.accessControl.entries = [
      AccessControlEntry(macAddress: "44:23:33:33:33:33", description: "test")
    ]
    let url = try temporaryURL(named: "Spaceship.baseconfig")

    try model.exportConfiguration(to: url)
    let imported = AirportAppModel()
    try imported.importConfiguration(from: url)

    XCTAssertEqual(imported.legacyDeviceOptions.baseStation.contact, "Network Admin")
    XCTAssertEqual(imported.legacyDeviceOptions.baseStation.location, "New York")
    XCTAssertTrue(imported.legacyDeviceOptions.baseStation.setTimeAutomatically)
    XCTAssertEqual(imported.legacyDeviceOptions.baseStation.timeServer, "time.apple.com")
    XCTAssertEqual(imported.legacyDeviceOptions.wireless.multicastRate, 85)
    XCTAssertEqual(imported.legacyDeviceOptions.wireless.transmitPower, 50)
    XCTAssertEqual(imported.legacyDeviceOptions.wireless.groupKeyTimeoutSeconds, 7_200)
    XCTAssertTrue(imported.legacyDeviceOptions.wireless.interferenceRobustness)
    XCTAssertEqual(imported.legacyDeviceOptions.dhcp.message, "Welcome")
    XCTAssertEqual(imported.legacyDeviceOptions.dhcp.ldapServer, "ldap.example.test")
    XCTAssertEqual(imported.legacyDeviceOptions.accessControl.mode, "local")
    XCTAssertEqual(imported.legacyDeviceOptions.accessControl.entries.first?.description, "test")
  }

  func testImportsProvidedRealAirPortUtilityBaseConfigurationWhenAvailable() throws {
    let url = URL(fileURLWithPath: NSHomeDirectory())
      .appendingPathComponent("Desktop/time capsule.baseconfig")
    guard FileManager.default.fileExists(atPath: url.path) else {
      throw XCTSkip("The user-provided real AirPort Utility export is not present.")
    }

    let model = AirportAppModel()
    try model.importConfiguration(from: url)

    XCTAssertEqual(model.baseStation.name, "time capsule")
    XCTAssertEqual(model.baseStation.newAdminPassword, "password")
    XCTAssertEqual(model.baseStation.verifyAdminPassword, "password")
    XCTAssertEqual(model.internet.connectUsing, .dhcp)
    XCTAssertEqual(model.internet.ipv4Address, "192.168.4.45")
    XCTAssertEqual(model.internet.subnetMask, "255.255.252.0")
    XCTAssertEqual(model.internet.routerAddress, "192.168.4.1")
    XCTAssertEqual(model.internet.configureIPv6, "link-local")
    XCTAssertEqual(model.internet.globalHostname, "capsule.example.test")
    XCTAssertEqual(model.internet.globalHostnameUser, "airport-live")
    XCTAssertEqual(model.internet.globalHostnamePassword, "hostname#543210")
    XCTAssertEqual(model.wireless.mode, "off")
    XCTAssertEqual(model.wireless.networkName, "Off")
    XCTAssertEqual(model.wireless.security, "none")
    XCTAssertEqual(model.network.lanIPAddress, "192.168.4.45")
    XCTAssertEqual(model.network.dhcpRangeStart, "192.168.4.2")
    XCTAssertEqual(model.network.dhcpRangeEnd, "192.168.4.200")
    XCTAssertEqual(model.network.dhcpLease, "1")
    XCTAssertEqual(model.network.dhcpLeaseUnit, "days")
    XCTAssertTrue(model.network.natPMP)
    XCTAssertEqual(model.network.defaultHost, "")
    XCTAssertTrue(model.isEditingDevice)
    XCTAssertEqual(model.selectedPane, .baseStation)
  }

  func testExportsBaseConfigurationAsRealXMLPlistWithCFB0Profile() throws {
    let model = configuredStaticModel()
    let url = try temporaryURL(named: "Lab Capsule.baseconfig")

    try model.exportConfiguration(to: url)

    let data = try Data(contentsOf: url)
    XCTAssertTrue(String(data: data.prefix(80), encoding: .utf8)?.contains("plist") == true)

    let plist = try XCTUnwrap(
      PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        as? [String: Any])
    XCTAssertEqual(plist["syNm"] as? String, "Lab Capsule")
    XCTAssertEqual(plist["waCV"] as? Int, 0x8400)
    XCTAssertEqual(plist["waD1"] as? String, "1.1.1.1")
    XCTAssertEqual(plist["waD2"] as? String, "8.8.8.8")
    XCTAssertEqual(plist["6cfg"] as? Int, 5)
    XCTAssertNil(plist["syPW"])

    let marker = try XCTUnwrap(plist["APPLE-CONFIG"] as? Data)
    XCTAssertTrue(marker.starts(with: Data("APPLE-CONFIG".utf8)))

    let profile = try XCTUnwrap(plist["Prof"] as? Data)
    XCTAssertTrue(profile.starts(with: Data("CFB0".utf8)))
    XCTAssertTrue(profile.suffix(4) == Data("END!".utf8))

    let imported = AirportAppModel()
    try imported.importConfiguration(from: url)
    assertVisibleConfiguration(imported, equals: model)
  }

  func testPropertyListExtensionExportsImportableBaseConfiguration() throws {
    let model = configuredStaticModel()
    let url = try temporaryURL(named: "Lab Capsule.plist")

    try model.exportConfiguration(to: url)

    let data = try Data(contentsOf: url)
    let plist = try XCTUnwrap(
      PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        as? [String: Any])
    XCTAssertEqual(plist["syNm"] as? String, "Lab Capsule")
    XCTAssertNotNil(plist["APPLE-CONFIG"] as? Data)
    XCTAssertNotNil(plist["Prof"] as? Data)

    let imported = AirportAppModel()
    try imported.importConfiguration(from: url)
    assertVisibleConfiguration(imported, equals: model)
  }

  func testBaseConfigurationRoundTripsSeveralSettingCombinations() throws {
    let cases = [
      configuredDHCPBridgeWirelessOffModel(),
      configuredStaticModel(),
      configuredPPPoEModel(),
      configuredDiskAccountsModel(),
    ]

    for model in cases {
      let url = try temporaryURL(named: "\(model.baseStation.name).baseconfig")
      try model.exportConfiguration(to: url)

      let imported = AirportAppModel()
      try imported.importConfiguration(from: url)

      assertVisibleConfiguration(imported, equals: model, file: #filePath, line: #line)
    }
  }

  func testImportsFlatRealStylePropertyListWhenProfileBlobIsAbsent() throws {
    let url = try temporaryURL(named: "Flat Only.baseconfig")
    let plist: [String: Any] = [
      "APPLE-CONFIG": Data("APPLE-CONFIG".utf8),
      "syNm": "Flat Capsule",
      "waCV": 0x8900,
      "waIP": "198.51.100.12",
      "waSM": "255.255.255.0",
      "waRA": "198.51.100.1",
      "peUN": "flat-account",
      "pePW": "flat-password",
      "peSN": "flat-service",
      "peAC": true,
      "peSC": false,
      "6cfg": 1,
      "6aut": true,
      "WiFi": [
        "radios": [
          [
            "raSt": 0,
            "raNm": "Flat Wi-Fi",
            "raWM": 7,
            "raCr": Data("flat-wifi".utf8),
            "raCl": true,
            "raMd": 6,
            "raCh": 11,
          ]
        ]
      ],
      "bsRM": 2,
      "laIP": "10.0.1.1",
      "naFl": 1,
      "nDMZ": "10.0.1.253",
    ]
    let data = try PropertyListSerialization.data(
      fromPropertyList: plist, format: .xml, options: 0)
    try data.write(to: url)

    let model = AirportAppModel()
    try model.importConfiguration(from: url)

    XCTAssertEqual(model.baseStation.name, "Flat Capsule")
    XCTAssertEqual(model.internet.connectUsing, .pppoe)
    XCTAssertEqual(model.internet.pppoeAccount, "flat-account")
    XCTAssertEqual(model.internet.pppoePassword, "flat-password")
    XCTAssertEqual(model.internet.pppoeConnection, "automatic")
    XCTAssertEqual(model.internet.configureIPv6, "automatic")
    XCTAssertEqual(model.wireless.networkName, "Flat Wi-Fi")
    XCTAssertEqual(model.wireless.password, "flat-wifi")
    XCTAssertTrue(model.wireless.hiddenNetwork)
    XCTAssertEqual(model.wireless.radioChannel, "11")
    XCTAssertEqual(model.network.routerMode, .natOnly)
    XCTAssertEqual(model.network.defaultHost, "10.0.1.253")
  }

  func testJSONConfigurationExportAndImportRemainSupported() throws {
    let model = configuredStaticModel()
    let url = try temporaryURL(named: "Lab Capsule.json")

    try model.exportConfiguration(to: url)

    let data = try Data(contentsOf: url)
    let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    XCTAssertEqual(json["format"] as? String, "AirPortUtility.Configuration")

    let imported = AirportAppModel()
    try imported.importConfiguration(from: url)
    assertVisibleConfiguration(imported, equals: model)
  }

  private func configuredStaticModel() -> AirportAppModel {
    let model = AirportAppModel()
    model.baseStation = BaseStationState(
      name: "Lab Capsule",
      serialNumber: "TESTSERIAL1",
      version: "7.8.1",
      newAdminPassword: "admin-secret",
      verifyAdminPassword: "admin-secret"
    )
    model.internet = InternetState(
      connectUsing: .static,
      ipv4Address: "192.168.4.45",
      subnetMask: "255.255.252.0",
      routerAddress: "192.168.4.1",
      dnsServers: "1.1.1.1, 8.8.8.8",
      domainName: "example.test",
      ipv6Address: "2001:db8::10",
      ipv6DNSServers: "2001:4860:4860::8888",
      configureIPv6: "manual",
      ipv6Mode: "router",
      dynamicGlobalHostname: true,
      globalHostname: "capsule.example.test",
      globalHostnameUser: "airport-live",
      globalHostnamePassword: "hostname#543210"
    )
    model.wireless = WirelessState(
      mode: "create",
      networkName: "Lab Wi-Fi",
      security: "wpa2-personal",
      password: "wireless-secret",
      verifyPassword: "wireless-secret",
      regionCode: "0",
      hiddenNetwork: true,
      radioMode: "80211n-bg",
      radioChannel: "11"
    )
    model.network = NetworkState(
      lanIPAddress: "10.0.1.1",
      routerMode: .dhcpAndNat,
      dhcpRangeStart: "10.0.1.2",
      dhcpRangeEnd: "10.0.1.200",
      natPMP: true,
      dhcpLease: "1",
      dhcpLeaseUnit: "days",
      defaultHost: "10.0.1.253"
    )
    model.disks = DisksState(
      fileSharing: true,
      secureSharedDisks: "disk-password",
      guestAccess: "read-only",
      shareOverWAN: true,
      diskPassword: "disk-secret",
      verifyDiskPassword: "disk-secret",
      windowsWorkgroup: "WORKGROUP",
      winsServer: "10.0.0.5"
    )
    return model
  }

  private func configuredDHCPBridgeWirelessOffModel() -> AirportAppModel {
    let model = AirportAppModel()
    model.baseStation = BaseStationState(
      name: "Bridge Capsule",
      serialNumber: "BRIDGE1",
      version: "7.8.1",
      newAdminPassword: "bridge-admin",
      verifyAdminPassword: "bridge-admin"
    )
    model.internet = InternetState(
      connectUsing: .dhcp,
      ipv4Address: "192.168.1.20",
      subnetMask: "255.255.255.0",
      routerAddress: "192.168.1.1",
      configureIPv6: "link-local"
    )
    model.wireless = WirelessState(
      mode: "off",
      networkName: "Off",
      security: "none",
      regionCode: "",
      radioMode: "",
      radioChannel: ""
    )
    model.network = NetworkState(
      lanIPAddress: "192.168.1.20",
      routerMode: .bridge,
      dhcpRangeStart: "192.168.1.2",
      dhcpRangeEnd: "192.168.1.200",
      dhcpLease: "1",
      dhcpLeaseUnit: "days"
    )
    model.disks = DisksState(
      fileSharing: false,
      secureSharedDisks: "device-password",
      guestAccess: "not-allowed",
      shareOverWAN: false
    )
    return model
  }

  private func configuredPPPoEModel() -> AirportAppModel {
    let model = AirportAppModel()
    model.baseStation = BaseStationState(
      name: "PPPoE Capsule",
      serialNumber: "PPPOE1",
      version: "7.7.9",
      newAdminPassword: "pppoe-admin",
      verifyAdminPassword: "pppoe-admin"
    )
    model.internet = InternetState(
      connectUsing: .pppoe,
      ipv4Address: "203.0.113.44",
      subnetMask: "255.255.255.0",
      routerAddress: "203.0.113.1",
      ipv6Address: "2001:db8:1::44",
      ipv6DNSServers: "2001:4860:4860::8888, 2001:4860:4860::8844",
      pppoeAccount: "pppoe-account",
      pppoePassword: "pppoe-password",
      pppoeService: "fiber",
      pppoeConnection: "manual",
      configureIPv6: "automatic",
      ipv6Mode: "tunnel"
    )
    model.wireless = WirelessState(
      mode: "create",
      networkName: "PPPoE Wi-Fi",
      security: "wpa-wpa2-personal",
      password: "pppoe-wifi",
      verifyPassword: "pppoe-wifi",
      regionCode: "5",
      hiddenNetwork: false,
      radioMode: "80211n-a",
      radioChannel: "automatic"
    )
    model.network = NetworkState(
      lanIPAddress: "172.16.1.1",
      routerMode: .natOnly,
      dhcpRangeStart: "172.16.1.2",
      dhcpRangeEnd: "172.16.1.200",
      natPMP: true,
      dhcpLease: "2",
      dhcpLeaseUnit: "hours",
      defaultHost: "172.16.1.50"
    )
    model.disks = DisksState(
      fileSharing: true,
      secureSharedDisks: "device-password",
      guestAccess: "read-write",
      shareOverWAN: false,
      windowsWorkgroup: "STUDIO",
      winsServer: ""
    )
    return model
  }

  private func configuredDiskAccountsModel() -> AirportAppModel {
    let model = AirportAppModel()
    model.baseStation = BaseStationState(
      name: "Accounts Capsule",
      serialNumber: "ACCOUNTS1",
      version: "7.6.9",
      newAdminPassword: "accounts-admin",
      verifyAdminPassword: "accounts-admin"
    )
    model.internet = InternetState(
      connectUsing: .static,
      ipv4Address: "10.10.0.2",
      subnetMask: "255.255.255.0",
      routerAddress: "10.10.0.1",
      dnsServers: "9.9.9.9",
      configureIPv6: "link-local"
    )
    model.wireless = WirelessState(
      mode: "create",
      networkName: "Open Lab",
      security: "none",
      regionCode: "1",
      radioMode: "80211bg",
      radioChannel: "6"
    )
    model.network = NetworkState(
      lanIPAddress: "10.0.2.1",
      routerMode: .dhcpOnly,
      dhcpRangeStart: "10.0.2.2",
      dhcpRangeEnd: "10.0.2.200",
      natPMP: false,
      dhcpLease: "1",
      dhcpLeaseUnit: "weeks"
    )
    model.disks = DisksState(
      fileSharing: true,
      secureSharedDisks: "accounts",
      guestAccess: "not-allowed",
      shareOverWAN: true,
      windowsWorkgroup: "ACCOUNTS",
      winsServer: "10.0.2.5"
    )
    return model
  }

  private func assertVisibleConfiguration(
    _ actual: AirportAppModel,
    equals expected: AirportAppModel,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertEqual(actual.baseStation, expected.baseStation, file: file, line: line)
    XCTAssertEqual(actual.internet, expected.internet, file: file, line: line)
    XCTAssertEqual(actual.wireless, expected.wireless, file: file, line: line)
    XCTAssertEqual(actual.network, expected.network, file: file, line: line)
    XCTAssertEqual(actual.disks, expected.disks, file: file, line: line)
    XCTAssertTrue(actual.isEditingDevice, file: file, line: line)
    XCTAssertEqual(actual.selectedPane, .baseStation, file: file, line: line)
  }

  private func temporaryURL(named name: String) throws -> URL {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    addTeardownBlock {
      try? FileManager.default.removeItem(at: directory)
    }
    return directory.appendingPathComponent(name)
  }
}
