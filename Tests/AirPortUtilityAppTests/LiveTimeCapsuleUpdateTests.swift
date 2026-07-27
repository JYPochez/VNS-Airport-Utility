import Foundation
import XCTest

@testable import AirPortUtilityCore

@MainActor
private final class LiveBonjourMatchState {
  var didFulfill = false
  var matchedDevice: AirportDiscoveredDevice?
}

private final class LiveMemoryAirportPasswordStore: AirportPasswordStore, @unchecked Sendable {
  var passwords: [String: String] = [:]

  func password(for host: String) -> String? {
    passwords[AirportConnection.normalizedHost(host)]
  }

  func savePassword(_ password: String, for host: String) {
    passwords[AirportConnection.normalizedHost(host)] = password
  }

  func deletePassword(for host: String) {
    passwords.removeValue(forKey: AirportConnection.normalizedHost(host))
  }

  func retainOnly(host: String) {
    let host = AirportConnection.normalizedHost(host)
    passwords = passwords[host].map { [host: $0] } ?? [:]
  }
}

final class LiveTimeCapsuleUpdateTests: XCTestCase {
  @MainActor
  func testLiveBonjourDiscoveryIncludesStableIdentifiers() async throws {
    try requireFlag("AIRPORT_LIVE_TESTS")
    let expectedHost = AirportConnection.normalizedHost(
      try requireEnvironmentValue("AIRPORT_UTILITY_HOST"))
    let foundDevice = expectation(description: "Found Time Capsule Bonjour TXT identity")
    let state = LiveBonjourMatchState()
    let browser = AirPortBonjourBrowser { devices in
      guard !state.didFulfill else { return }
      guard
        let device = devices.first(where: {
          ($0.matchesConnectionHost(expectedHost) || expectedHost.isEmpty)
            && !$0.identifiers.isEmpty
        }),
        !device.identifiers.isEmpty
      else {
        return
      }
      state.didFulfill = true
      state.matchedDevice = device
      foundDevice.fulfill()
    }
    browser.start()
    defer { browser.stop() }

    await fulfillment(of: [foundDevice], timeout: 20)

    let matchedDevice = state.matchedDevice
    let device = try XCTUnwrap(matchedDevice)
    XCTAssertTrue(device.identifiers.contains { $0.hasPrefix("wama:") || $0.hasPrefix("rama:") })
  }

  func testLiveBaseStationPaneUpdatesName() async throws {
    let live = try liveHarness()
    let originalName = try await live.readSettingText("syNm")
    let testName = "Live Test Capsule"

    try await live.withRestore(
      restore: {
        try await live.writeRaw(
          setting: "syNm", value: originalName, title: "Restore Base Station Name")
        try await live.expectSetting("syNm", equals: originalName)
      },
      operation: {
        try await live.writeRaw(setting: "syNm", value: testName, title: "Base Station Name")
        try await live.expectSetting("syNm", equals: testName)
      })
  }

  func testLiveRenamedBaseStationReusesSavedPasswordFromPreviousBonjourHost() async throws {
    let live = try liveHarness()
    let liveHost = live.connection.host
    let livePassword = live.connection.password
    let liveRepoPath = live.connection.repoPath
    let originalName = try await live.readSettingText("syNm")
    let originalDevice = try await Self.liveBonjourDevice(matchingHost: liveHost)
    let originalHost = originalDevice.connectionHost
    let stableIdentifier = try XCTUnwrap(originalDevice.normalizedStableIdentifiers.first)
    let testName =
      originalName == "Live Password Reuse Capsule"
      ? "Live Password Reuse Capsule 2" : "Live Password Reuse Capsule"

    let store = LiveMemoryAirportPasswordStore()
    let model = await MainActor.run {
      let model = AirportAppModel(passwordStore: store)
      model.connection.repoPath = liveRepoPath
      model.connection.host = originalHost
      model.connection.password = livePassword
      model.rememberConnectionPassword = true
      model.updateDiscoveredDevices([originalDevice])
      model.selectTopologyDevice(originalDevice)
      model.saveConnectionPasswordIfRequested()
      return model
    }

    store.retainOnly(host: originalHost)
    let promptedBeforeRename = await MainActor.run {
      model.connection.password = ""
      return model.shouldShowDeviceConnectionPrompt
    }
    XCTAssertTrue(promptedBeforeRename)

    try await live.withRestore(
      restore: {
        try await live.writeRaw(
          setting: "syNm", value: originalName, title: "Restore Base Station Name")
        try await live.expectSetting("syNm", equals: originalName)
      },
      operation: {
        try await live.writeRaw(setting: "syNm", value: testName, title: "Base Station Name")
        try await live.expectSetting("syNm", equals: testName)
        let renamedDevice = try await Self.liveBonjourDevice(
          sharingStableIdentityWith: originalDevice,
          expectedName: testName)

        let state = await MainActor.run {
          model.updateDiscoveredDevices([renamedDevice])
          return (
            host: model.connection.host,
            password: model.connection.password,
            shouldPrompt: model.shouldShowDeviceConnectionPrompt
          )
        }

        XCTAssertEqual(state.host, renamedDevice.connectionHost)
        XCTAssertEqual(state.password, livePassword)
        XCTAssertFalse(state.shouldPrompt)
        XCTAssertEqual(
          store.passwords["airport-device-id:\(stableIdentifier)"],
          livePassword)
      })
  }

  func testLiveBaseStationPaneUpdatesAdminPasswordWhenAllowed() async throws {
    let live = try liveHarness()
    try requireFlag("AIRPORT_LIVE_ALLOW_PASSWORD_CHANGES")

    let originalPassword = live.connection.password
    let temporaryPassword =
      environmentValue("AIRPORT_LIVE_TEMP_ADMIN_PASSWORD") ?? "airport-admin#543210"
    XCTAssertNotEqual(originalPassword, temporaryPassword)

    try await live.withRestore(
      restore: {
        var temporaryConnection = live.connection
        temporaryConnection.password = temporaryPassword
        let temporaryLive = LiveAirPortHarness(connection: temporaryConnection)
        try await temporaryLive.writeRaw(
          setting: "syPW", value: originalPassword, title: "Restore Admin Password")
        try await live.waitForReachable()
      },
      operation: {
        try await live.writeRaw(setting: "syPW", value: temporaryPassword, title: "Admin Password")
        var temporaryConnection = live.connection
        temporaryConnection.password = temporaryPassword
        let temporaryLive = LiveAirPortHarness(connection: temporaryConnection)
        _ = try await temporaryLive.readSettingText("syNm")
      })
  }

  func testLiveInternetPaneUpdatesDHCPFields() async throws {
    let live = try liveHarness()
    let restore = try await live.internetRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Internet Pane") },
      operation: {
        try await live.writeFlags(
          [
            ("--connect-using", "dhcp"),
            ("--dns-server", "1.1.1.1"),
            ("--dns-server", "8.8.8.8"),
            ("--ipv6-dns-server", "2606:4700:4700::1111"),
            ("--ipv6-dns-server", "2001:4860:4860::8888"),
            ("--domain-name", "example.test"),
          ],
          title: "Internet DHCP Fields")

        try await live.expectSettingJSONInt("waCV", equals: 0x8300)
        try await live.expectSettingJSONString("waD1", equals: "1.1.1.1")
        try await live.expectSettingJSONString("waD2", equals: "8.8.8.8")
        try await live.expectSettingJSONString("6NS1", equals: "2606:4700:4700::1111")
        try await live.expectSettingJSONString("6NS2", equals: "2001:4860:4860::8888")
        try await live.expectSettingJSONString("waDN", equals: "example.test")
      })
  }

  func testLiveInternetConnectUsingDropdownUpdatesStaticAndPPPoEWhenAllowed() async throws {
    let live = try liveHarness()
    try requireFlag("AIRPORT_LIVE_ALLOW_NETWORK_DISRUPTION")
    let restore = try await live.internetRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Internet Connection Mode") },
      operation: {
        try await live.writeFlags(
          [
            ("--connect-using", "static"),
            ("--ipv4-address", environmentValue("AIRPORT_LIVE_STATIC_IPV4") ?? "192.168.4.45"),
            ("--subnet-mask", environmentValue("AIRPORT_LIVE_STATIC_SUBNET") ?? "255.255.252.0"),
            ("--router-address", environmentValue("AIRPORT_LIVE_STATIC_ROUTER") ?? "192.168.4.1"),
            ("--dns-server", "1.1.1.1"),
          ],
          title: "Internet Static Mode")
        try await live.expectSettingJSONInt("waCV", equals: 0x8400)

        try await live.writeFlags(
          [
            ("--connect-using", "pppoe"),
            ("--pppoe-account", "live-test@example.com"),
            ("--pppoe-password", "pppoe#543210"),
            ("--pppoe-service", "airport-live"),
          ],
          title: "Internet PPPoE Mode")
        try await live.expectSettingJSONInt("waCV", equals: 0x8900)
        try await live.expectSettingJSONString("peUN", equals: "live-test@example.com")
        try await live.expectSettingJSONString("peSN", equals: "airport-live")
      })
  }

  func testLiveInternetOptionsDropdownsAndDynamicGlobalHostname() async throws {
    let live = try liveHarness()
    let restore = try await live.internetRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Internet Options") },
      operation: {
        for option in ["link-local", "automatic", "manual"] {
          try await live.writeFlags(
            [("--configure-ipv6", option)], title: "Configure IPv6 \(option)")
          switch option {
          case "link-local":
            try await live.expectSettingJSONInt("6cfg", equals: 0)
          case "automatic":
            try await live.expectSettingJSONBool("6aut", equals: true)
          case "manual":
            try await live.expectSettingJSONBool("6aut", equals: false)
          default:
            XCTFail("unexpected Configure IPv6 option \(option)")
          }
        }

        try await live.writeFlags(
          [
            ("--dynamic-global-hostname", nil),
            ("--global-hostname", "capsule.example.test"),
            ("--global-hostname-user", "airport-live"),
            ("--global-hostname-password", "hostname#543210"),
          ],
          title: "Dynamic Global Hostname On")
        try await live.expectSettingJSONBool("wbEn", equals: true)
        try await live.expectSettingJSONString("wbHN", equals: "capsule.example.test")
        try await live.expectSettingJSONString("wbHU", equals: "airport-live")

        try await live.writeFlags(
          [("--no-dynamic-global-hostname", nil)], title: "Dynamic Global Hostname Off")
        try await live.expectSettingJSONBool("wbEn", equals: false)
      })
  }

  func testLiveInternetPPPoEConnectionPoliciesWhenAllowed() async throws {
    let live = try liveHarness()
    try requireFlag("AIRPORT_LIVE_ALLOW_NETWORK_DISRUPTION")
    let restore = try await live.internetRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore PPPoE Policy") },
      operation: {
        let expectations: [(String, Bool, Bool)] = [
          ("always-on", true, true),
          ("automatic", true, false),
          ("manual", false, false),
        ]
        for (policy, active, stayConnected) in expectations {
          try await live.writeFlags([("--pppoe-connection", policy)], title: "PPPoE \(policy)")
          try await live.expectSettingJSONBool("peAC", equals: active)
          try await live.expectSettingJSONBool("peSC", equals: stayConnected)
        }
      })
  }

  func testLiveWirelessPaneUpdatesCreateModeAndSecurityOptions() async throws {
    let live = try liveHarness()
    let restore = try await live.wirelessRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Wireless Pane") },
      operation: {
        let securedOptions: [(String, Int)] = [
          ("wpa-wpa2-personal", 5),
          ("wpa2-personal", 7),
        ]
        for (security, expectedMode) in securedOptions {
          try await live.writeFlags(
            [
              ("--wireless-mode", "create"),
              ("--wireless-name", "airport-live-test"),
              ("--wireless-security", security),
              ("--wireless-password", "airport#543210"),
            ],
            title: "Wireless Security \(security)")
          try await live.expectSettingInt("raSt", equals: 0)
          try await live.expectSetting("raNm", equals: "airport-live-test")
          try await live.expectSettingInt("raWM", equals: expectedMode)
        }

        try await live.writeFlags(
          [
            ("--wireless-mode", "create"),
            ("--wireless-name", "airport-live-open"),
            ("--wireless-security", "none"),
          ],
          title: "Wireless Security none")
        try await live.expectSettingInt("raSt", equals: 0)
        try await live.expectSetting("raNm", equals: "airport-live-open")
        try await live.expectSettingInt("raWM", equals: 1)
      })
  }

  func testLiveWirelessNetworkModeDropdownUpdatesOffAndExtendWhenAllowed() async throws {
    let live = try liveHarness()
    try requireFlag("AIRPORT_LIVE_ALLOW_WIRELESS_DISRUPTION")
    let extendName = try requireEnvironmentValue("AIRPORT_LIVE_EXTEND_SSID")
    let extendPassword = environmentValue("AIRPORT_LIVE_EXTEND_PASSWORD") ?? "airport#543210"
    let restore = try await live.wirelessRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Wireless Network Mode") },
      operation: {
        try await live.writeFlags([("--wireless-mode", "off")], title: "Wireless Off")
        try await live.expectSettingInt("raSt", equals: 3)

        try await live.writeFlags(
          [
            ("--wireless-mode", "extend"),
            ("--wireless-name", extendName),
            ("--wireless-security", "wpa2-personal"),
            ("--wireless-password", extendPassword),
          ],
          title: "Wireless Extend")
        try await live.expectSettingInt("raSt", equals: 20)
        try await live.expectSetting("raNm", equals: extendName)
      })
  }

  func testLiveWirelessOptionsRegionAndHiddenNetwork() async throws {
    let live = try liveHarness()
    let restore = try await live.wirelessRestoreFlags()

    try await live.withRestore(
      restore: {
        try await live.writeFlags(restore, title: "Restore Wireless Region and Hidden Network")
      },
      operation: {
        try await live.writeFlags([("--region-code", "0")], title: "Wireless Region United States")
        try await live.expectSettingInt("syRe", equals: 0)

        for hidden in [true, false] {
          let flag = hidden ? "--hidden-network" : "--no-hidden-network"
          try await live.writeFlags([(flag, nil)], title: "Hidden Network \(hidden)")
          try await live.expectSettingBool("raCl", equals: hidden)
        }
      })
  }

  func testLiveWirelessRadioModeDropdowns() async throws {
    let live = try liveHarness()
    let restore = try await live.wirelessRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Wireless Radio Mode") },
      operation: {
        var radioModes: [(String, Int)] = [
          ("80211n-bg", 6)
        ]
        if ProcessInfo.processInfo.environment["AIRPORT_LIVE_ALLOW_WIRELESS_DISRUPTION"] == "1" {
          radioModes += [
            ("80211n-only-24", 7),
            ("80211n-only-5", 8),
            ("80211g", 3),
          ]
        }
        for (mode, expectedValue) in radioModes {
          try await live.writeFlags([("--radio-mode", mode)], title: "Radio Mode \(mode)")
          try await live.expectSettingInt("raMd", equals: expectedValue)
        }
      })
  }

  func testLiveWirelessRadioChannelDropdownOptions() async throws {
    let live = try liveHarness()
    let restore = try await live.wirelessRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Wireless Radio Channel") },
      operation: {
        var channels: [(String, Int, TimeInterval)] = [("automatic", 1000, 90)]
        if ProcessInfo.processInfo.environment["AIRPORT_LIVE_ALLOW_WIRELESS_DISRUPTION"] == "1" {
          channels.append(("11", 11, 240))
        }
        for (channel, expectedValue, timeout) in channels {
          try await live.writeFlags(
            [("--radio-channel", channel)], title: "Radio Channel \(channel)")
          try await live.expectRadioChannel(equals: expectedValue, timeout: timeout)
        }
      })
  }

  func testLiveNetworkRouterModeDropdownOptionsWhenAllowed() async throws {
    let live = try liveHarness()
    try requireFlag("AIRPORT_LIVE_ALLOW_NETWORK_DISRUPTION")
    let restore = try await live.networkRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Router Mode") },
      operation: {
        let modes: [(String, Int, [(String, String?)])] = [
          (
            "dhcp-and-nat", 0,
            [
              ("--dhcp-range-start", "10.0.1.2"),
              ("--dhcp-range-end", "10.0.1.200"),
              ("--dhcp-lease", "1"),
              ("--dhcp-lease-unit", "days"),
            ]
          ),
          (
            "dhcp-only", 1,
            [
              ("--dhcp-range-start", "192.168.4.2"),
              ("--dhcp-range-end", "192.168.4.200"),
              ("--dhcp-lease", "12"),
              ("--dhcp-lease-unit", "hours"),
            ]
          ),
          ("nat-only", 2, []),
          ("bridge", 3, []),
        ]

        for (mode, expectedValue, requiredFlags) in modes {
          try await live.writeFlags(
            [("--router-mode", mode)] + requiredFlags, title: "Router Mode \(mode)")
          try await live.expectProfileInt("restoreProfile.bsRM", equals: expectedValue)
        }
      })
  }

  func testLiveNetworkOptionsDropdownsAndTogglesWhenAllowed() async throws {
    let live = try liveHarness()
    try requireFlag("AIRPORT_LIVE_ALLOW_NETWORK_DISRUPTION")
    let restore = try await live.networkRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Network Options") },
      operation: {
        let leaseUnits: [(String, String, Int)] = [
          ("12", "hours", 43_200),
          ("1", "days", 86_400),
          ("1", "weeks", 604_800),
        ]
        for (value, unit, expectedSeconds) in leaseUnits {
          try await live.writeFlags(
            [
              ("--router-mode", "dhcp-and-nat"),
              ("--dhcp-range-start", "10.0.1.2"),
              ("--dhcp-range-end", "10.0.1.200"),
              ("--dhcp-lease", value),
              ("--dhcp-lease-unit", unit),
            ],
            title: "DHCP Lease \(value) \(unit)")
          try await live.expectProfileInt("restoreProfile.dhLe", equals: expectedSeconds)
        }

        let ranges: [(String, String, String)] = [
          ("10.0", "10.0.1.2", "10.0.1.200"),
          ("172.16", "172.16.1.2", "172.16.1.200"),
          ("192.168", "192.168.4.2", "192.168.4.200"),
        ]
        for (prefix, start, end) in ranges {
          try await live.writeFlags(
            [
              ("--router-mode", "dhcp-and-nat"),
              ("--dhcp-range-start", start),
              ("--dhcp-range-end", end),
              ("--dhcp-lease", "1"),
              ("--dhcp-lease-unit", "days"),
            ],
            title: "DHCP Range \(prefix)")
          try await live.expectProfileString("restoreProfile.dhBg", equals: start)
          try await live.expectProfileString("restoreProfile.dhEn", equals: end)
        }

        for natPMP in [true, false] {
          let flag = natPMP ? "--nat-pmp" : "--no-nat-pmp"
          try await live.writeFlags(
            [("--router-mode", "nat-only"), (flag, nil)], title: "NAT-PMP \(natPMP)")
          try await live.expectProfileInt("restoreProfile.naFl", equals: natPMP ? 1 : 0)
        }

        try await live.writeFlags(
          [("--router-mode", "nat-only"), ("--default-host", "10.0.1.253")],
          title: "Default Host")
        try await live.expectProfileString("restoreProfile.nDMZ", equals: "10.0.1.253")

        try await live.writeFlags(
          [("--router-mode", "nat-only"), ("--clear-default-host", nil)],
          title: "Clear Default Host")
        try await live.expectProfileString("restoreProfile.nDMZ", equals: "0.0.0.0")
      })
  }

  func testLiveDisksPaneUpdatesSharingAndSecurityOptions() async throws {
    let live = try liveHarness()
    guard try await live.supportsFlags([("--file-sharing", nil)]) else {
      throw XCTSkip("This Time Capsule rejects the Disk pane file sharing key bsFS.")
    }
    guard try await live.supportsFlags([("--disk-security", "device-password")]) else {
      throw XCTSkip("This Time Capsule rejects the Disk pane security mode key bsFM.")
    }
    let restore = try await live.diskRestoreFlags()

    try await live.withRestore(
      restore: { try await live.writeFlags(restore, title: "Restore Disk Sharing") },
      operation: {
        for enabled in [true, false] {
          let flag = enabled ? "--file-sharing" : "--no-file-sharing"
          try await live.writeFlags([(flag, nil)], title: "File Sharing \(enabled)")
          try await live.expectProfileInt("restoreProfile.bsFS", equals: enabled ? 1 : 0)
        }

        let securityOptions: [(String, Int, [(String, String?)])] = [
          ("accounts", 0, []),
          ("disk-password", 1, [("--disk-password", "disk#543210")]),
          ("device-password", 2, []),
        ]
        for (option, expectedValue, extraFlags) in securityOptions {
          try await live.writeFlags(
            [("--disk-security", option)] + extraFlags, title: "Disk Security \(option)")
          try await live.expectProfileInt("restoreProfile.bsFM", equals: expectedValue)
        }
      })
  }

  func testLiveDiskEraseSheetRunsEverySecurityMethod() async throws {
    let live = try liveHarness()

    for method in EraseMethod.allCases {
      if method.requiresLongEraseOptIn {
        guard longDestructiveDiskTestsEnabled else {
          continue
        }
      }
      let result = try await live.eraseDisk(method)
      XCTAssertTrue(
        result.combinedOutput.contains("erase started"),
        "Expected erase confirmation for \(method.rawValue), got: \(result.combinedOutput)"
      )
      try await live.waitForReachable(timeout: method.liveRecoveryTimeout)
      try await live.waitForBuiltInDiskPartition(timeout: method.liveRecoveryTimeout)
    }
  }

  func testLiveDiskArchiveSheetRunsWhenExternalDestinationExists() async throws {
    let live = try liveHarness()
    guard try await live.hasExternalArchiveDestination() else {
      throw XCTSkip("No external AirPort disk archive destination is visible in MaSt.")
    }

    let result = try await live.run(
      script: AirportCommand.writeScript,
      arguments: AirportCommand.archiveDisk(
        connection: live.connection,
        archiveName: "AirPort Live Test Archive",
        confirmed: true,
        dryRun: false),
      timeout: 300
    )
    XCTAssertTrue(
      result.combinedOutput.contains("archive started"),
      "Expected archive confirmation, got: \(result.combinedOutput)"
    )
    try await live.waitForReachable(timeout: 600)
  }

  func testLiveFirmwarePaneReinstallsCurrentFirmwareWhenAllowed() async throws {
    let live = try liveHarness()
    try requireFlag("AIRPORT_LIVE_ALLOW_FIRMWARE_FLASH")

    let productID = try await live.readSettingText("syAP")
    let currentVersion = try await live.readSettingText("syVs")
    let (manifestData, _) = try await URLSession.shared.data(from: FirmwareCatalog.manifestURL)
    let images = try FirmwareCatalog.images(forProductID: productID, in: manifestData)
    let currentImage = try XCTUnwrap(images.first { $0.version == currentVersion })
    let cacheRoot = FileManager.default.temporaryDirectory
      .appendingPathComponent("airport-live-firmware-\(UUID().uuidString)", isDirectory: true)
    let liveConnection = live.connection
    defer { try? FileManager.default.removeItem(at: cacheRoot) }

    let model = await MainActor.run {
      let model = AirportAppModel()
      model.connection = liveConnection
      model.applyAuthoritativeBaseStationIdentity(
        readName: "time capsule",
        serialNumber: "",
        version: currentVersion,
        productID: productID)
      model.firmware.images = images
      model.firmware.selectedImageID = currentImage.id
      model.firmware.hasLoadedImages = true
      model.firmwareDownloadService = FirmwareDownloadService(root: cacheRoot)
      model.firmwareInstallVerificationAttempts = 180
      model.installSelectedFirmware()
      return model
    }

    try await waitForFirmwareModelIdle(model, timeout: 900)

    let finalState = await MainActor.run {
      (
        status: model.status,
        baseVersion: model.baseStation.version,
        firmwareVersion: model.firmware.currentVersion
      )
    }
    XCTAssertEqual(finalState.status, "Firmware \(currentVersion) reinstalled.")
    XCTAssertEqual(finalState.baseVersion, currentVersion)
    XCTAssertEqual(finalState.firmwareVersion, currentVersion)
    let verifiedVersion = try await live.readSettingText("syVs")
    XCTAssertEqual(verifiedVersion, currentVersion)
  }

  func testLiveFirmwarePaneInstallsPreviousFirmwareAndRestoresCurrentWhenAllowed() async throws {
    let live = try liveHarness()
    try requireFlag("AIRPORT_LIVE_ALLOW_FIRMWARE_FLASH")
    try requireFlag("AIRPORT_LIVE_ALLOW_FIRMWARE_DOWNGRADE")

    let productID = try await live.readSettingText("syAP")
    let originalVersion = try await live.readSettingText("syVs")
    let (manifestData, _) = try await URLSession.shared.data(from: FirmwareCatalog.manifestURL)
    let images = try FirmwareCatalog.images(forProductID: productID, in: manifestData)
    let currentImage = try XCTUnwrap(images.first { $0.version == originalVersion })
    let currentIndex = try XCTUnwrap(images.firstIndex { $0.version == originalVersion })
    let previousImage = try XCTUnwrap(images.dropFirst(currentIndex + 1).first)
    let cacheRoot = FileManager.default.temporaryDirectory
      .appendingPathComponent("airport-live-firmware-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: cacheRoot) }

    var installedPrevious = false
    do {
      let previousState = try await installFirmwareImage(
        previousImage,
        images: images,
        live: live,
        currentVersion: originalVersion,
        productID: productID,
        cacheRoot: cacheRoot)
      XCTAssertEqual(previousState.status, "Firmware \(previousImage.version) installed.")
      XCTAssertEqual(previousState.baseVersion, previousImage.version)
      XCTAssertEqual(previousState.firmwareVersion, previousImage.version)
      XCTAssertEqual(previousState.verifiedVersion, previousImage.version)
      installedPrevious = true

      let restoredState = try await installFirmwareImage(
        currentImage,
        images: images,
        live: live,
        currentVersion: previousImage.version,
        productID: productID,
        cacheRoot: cacheRoot)
      XCTAssertEqual(restoredState.status, "Firmware \(originalVersion) installed.")
      XCTAssertEqual(restoredState.baseVersion, originalVersion)
      XCTAssertEqual(restoredState.firmwareVersion, originalVersion)
      XCTAssertEqual(restoredState.verifiedVersion, originalVersion)
    } catch {
      if installedPrevious {
        _ = try? await installFirmwareImage(
          currentImage,
          images: images,
          live: live,
          currentVersion: previousImage.version,
          productID: productID,
          cacheRoot: cacheRoot)
      }
      throw error
    }
  }

  private func liveHarness() throws -> LiveAirPortHarness {
    guard environmentValue("AIRPORT_LIVE_TESTS") == "1" else {
      throw XCTSkip("Set AIRPORT_LIVE_TESTS=1 to run live Time Capsule mutation tests.")
    }
    let host = try requireEnvironmentValue("AIRPORT_UTILITY_HOST")
    let password = try requireEnvironmentValue("AIRPORT_UTILITY_PASSWORD")
    let repoPath =
      environmentValue("AIRPORT_UTILITY_REPO") ?? FileManager.default.currentDirectoryPath
    return LiveAirPortHarness(
      connection: AirportConnection(host: host, password: password, repoPath: repoPath))
  }

  @MainActor
  private static func liveBonjourDevice(
    matchingHost host: String,
    timeout: TimeInterval = 30
  ) async throws -> AirportDiscoveredDevice {
    try await liveBonjourDevice(timeout: timeout) { device in
      device.matchesConnectionHost(host) && !device.normalizedStableIdentifiers.isEmpty
    }
  }

  @MainActor
  private static func liveBonjourDevice(
    sharingStableIdentityWith expectedDevice: AirportDiscoveredDevice,
    expectedName: String,
    timeout: TimeInterval = 90
  ) async throws -> AirportDiscoveredDevice {
    let expectedIdentifiers = expectedDevice.normalizedStableIdentifiers
    return try await liveBonjourDevice(timeout: timeout) { device in
      device.sharesStableIdentity(with: expectedIdentifiers)
        && device.displayName.trimmingCharacters(in: .whitespacesAndNewlines) == expectedName
    }
  }

  @MainActor
  private static func liveBonjourDevice(
    timeout: TimeInterval,
    matching predicate: @escaping (AirportDiscoveredDevice) -> Bool
  ) async throws -> AirportDiscoveredDevice {
    let state = LiveBonjourMatchState()
    let browser = AirPortBonjourBrowser { devices in
      guard !state.didFulfill else { return }
      guard let device = devices.first(where: predicate) else { return }
      state.didFulfill = true
      state.matchedDevice = device
    }
    browser.start()
    defer { browser.stop() }

    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
      if let device = state.matchedDevice {
        return device
      }
      try await Task.sleep(nanoseconds: 250_000_000)
    }
    throw LiveAirPortAssertionError(message: "Timed out waiting for matching Bonjour device.")
  }

  private func requireFlag(_ name: String) throws {
    guard environmentValue(name) == "1" else {
      throw XCTSkip("Set \(name)=1 to run this disruptive live Time Capsule test.")
    }
  }

  private func requireEnvironmentValue(_ name: String) throws -> String {
    guard let value = environmentValue(name), !value.trimmingCharacters(in: .whitespaces).isEmpty
    else {
      throw XCTSkip("Set \(name) to run this live Time Capsule test.")
    }
    return value
  }

  private func environmentValue(_ name: String) -> String? {
    ProcessInfo.processInfo.environment[name]
  }

  private func waitForFirmwareModelIdle(
    _ model: AirportAppModel,
    timeout: TimeInterval
  ) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
      let isBusy = await MainActor.run { model.isBusy }
      if !isBusy {
        return
      }
      try await Task.sleep(nanoseconds: 2_000_000_000)
    }
    let status = await MainActor.run { model.status }
    throw LiveAirPortAssertionError(
      message: "Timed out waiting for firmware install model to finish. Status: \(status)")
  }

  private func installFirmwareImage(
    _ image: FirmwareImage,
    images: [FirmwareImage],
    live: LiveAirPortHarness,
    currentVersion: String,
    productID: String,
    cacheRoot: URL
  ) async throws -> (
    status: String, baseVersion: String, firmwareVersion: String, verifiedVersion: String
  ) {
    let liveConnection = live.connection
    let model = await MainActor.run {
      let model = AirportAppModel()
      model.connection = liveConnection
      model.applyAuthoritativeBaseStationIdentity(
        readName: "time capsule",
        serialNumber: "",
        version: currentVersion,
        productID: productID)
      model.firmware.images = images
      model.firmware.selectedImageID = image.id
      model.firmware.hasLoadedImages = true
      model.firmwareDownloadService = FirmwareDownloadService(root: cacheRoot)
      model.firmwareInstallVerificationAttempts = 180
      model.installSelectedFirmware()
      return model
    }

    try await waitForFirmwareModelIdle(model, timeout: 900)

    let finalState = await MainActor.run {
      (
        status: model.status,
        baseVersion: model.baseStation.version,
        firmwareVersion: model.firmware.currentVersion
      )
    }
    let verifiedVersion = try await live.readSettingText("syVs")
    return (
      status: finalState.status,
      baseVersion: finalState.baseVersion,
      firmwareVersion: finalState.firmwareVersion,
      verifiedVersion: verifiedVersion
    )
  }

  private var longDestructiveDiskTestsEnabled: Bool {
    environmentValue("RUN_LONG_DESTRUCTIVE_DISK_TESTS") == "1"
      || environmentValue("AIRPORT_LIVE_ALLOW_LONG_DISK_ERASES") == "1"
  }
}

extension EraseMethod {
  fileprivate var requiresLongEraseOptIn: Bool {
    switch self {
    case .quick, .zero:
      return false
    case .sevenPass, .thirtyFivePass:
      return true
    }
  }

  fileprivate var liveEraseTimeout: TimeInterval {
    switch self {
    case .quick:
      return 300
    case .zero:
      return 3_600
    case .sevenPass:
      return 12 * 3_600
    case .thirtyFivePass:
      return 72 * 3_600
    }
  }

  fileprivate var liveRecoveryTimeout: TimeInterval {
    switch self {
    case .quick:
      return 600
    case .zero:
      return 3_600
    case .sevenPass:
      return 12 * 3_600
    case .thirtyFivePass:
      return 72 * 3_600
    }
  }
}

private struct LiveAirPortAssertionError: Error, CustomStringConvertible {
  var message: String
  var description: String { message }
}

private final class LiveAirPortHarness {
  let connection: AirportConnection
  private let runner = AirportCommandRunner()

  init(connection: AirportConnection) {
    self.connection = connection
  }

  func withRestore(
    restore: () async throws -> Void,
    operation: () async throws -> Void
  ) async throws {
    do {
      try await operation()
    } catch {
      try? await restore()
      throw error
    }
    try await restore()
  }

  func run(
    script: String,
    arguments: [String],
    timeout: TimeInterval = 90
  ) async throws -> CommandResult {
    try await runner.run(
      script: script, arguments: arguments, connection: connection, timeout: timeout)
  }

  func runRetryingTransientAuth(
    script: String,
    arguments: [String],
    timeout: TimeInterval
  ) async throws -> CommandResult {
    var lastError: Error?
    for attempt in 0..<12 {
      do {
        return try await run(script: script, arguments: arguments, timeout: timeout)
      } catch {
        lastError = error
        guard attempt < 11, Self.isTransientACPAuthenticationError(error) else {
          throw error
        }
        try? await waitForReachable(timeout: 60)
        try await Task.sleep(nanoseconds: 5_000_000_000)
      }
    }
    throw lastError ?? LiveAirPortAssertionError(message: "Command failed.")
  }

  func writeRaw(setting: String, value: String, title: String) async throws {
    _ = try await runRetryingTransientAuth(
      script: AirportCommand.writeScript,
      arguments: AirportCommand.rawWrite(
        setting: setting, value: value, connection: connection, dryRun: false),
      timeout: 120
    )
    try await waitForReachable()
  }

  func writeFlags(_ flags: [(String, String?)], title: String) async throws {
    _ = try await runRetryingTransientAuth(
      script: AirportCommand.writeScript,
      arguments: AirportCommand.friendlyWrite(connection: connection, flags: flags, dryRun: false),
      timeout: 120
    )
    try await waitForReachable()
  }

  func supportsFlags(_ flags: [(String, String?)]) async throws -> Bool {
    do {
      _ = try await runRetryingTransientAuth(
        script: AirportCommand.writeScript,
        arguments: AirportCommand.friendlyWrite(connection: connection, flags: flags, dryRun: true),
        timeout: 45
      )
      return true
    } catch {
      if Self.isTransientACPAuthenticationError(error) {
        throw error
      }
      if case AirportCommandError.failed = error {
        return false
      }
      throw error
    }
  }

  func eraseDisk(_ method: EraseMethod) async throws -> CommandResult {
    var lastError: Error?
    for attempt in 0..<3 {
      do {
        return try await run(
          script: AirportCommand.writeScript,
          arguments: AirportCommand.eraseDisk(
            connection: connection, method: method, confirmed: true, dryRun: false),
          timeout: method.liveEraseTimeout
        )
      } catch {
        lastError = error
        guard attempt < 2, Self.isRetryableDiskEraseError(error) else {
          throw error
        }
        try? await waitForReachable(timeout: method.liveRecoveryTimeout)
        try? await waitForBuiltInDiskPartition(timeout: method.liveRecoveryTimeout)
        try await Task.sleep(nanoseconds: 5_000_000_000)
      }
    }
    throw lastError ?? LiveAirPortAssertionError(message: "Disk erase failed.")
  }

  func readSettingText(_ setting: String) async throws -> String {
    let result = try await run(
      script: AirportCommand.readScript,
      arguments: AirportCommand.readSetting(setting, connection: connection),
      timeout: 30
    )
    return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  func readSettingJSON(_ setting: String) async throws -> Any {
    let result = try await run(
      script: AirportCommand.readScript,
      arguments: AirportCommand.readSetting(setting, connection: connection, json: true),
      timeout: 45
    )
    return try Self.decodeJSON(result.stdout)
  }

  func readProfileValue(_ path: String) async throws -> Any {
    let result = try await run(
      script: AirportCommand.readScript,
      arguments: AirportCommand.readProfilePath(path, connection: connection, json: true),
      timeout: 45
    )
    return try Self.decodeJSON(result.stdout)
  }

  func optionalProfileValue(_ path: String) async -> Any? {
    do {
      return try await readProfileValue(path)
    } catch {
      return nil
    }
  }

  func expectSetting(_ setting: String, equals expected: String) async throws {
    try await eventually("Expected \(setting) to equal \(expected)") {
      let actual = try await self.readSettingText(setting)
      return actual == expected
    }
  }

  func expectSettingInt(_ setting: String, equals expected: Int) async throws {
    try await eventually("Expected \(setting) to equal \(expected)") {
      let actual = try await self.readSettingText(setting)
      return Self.intTextValue(actual) == expected
    }
  }

  func expectSettingBool(_ setting: String, equals expected: Bool) async throws {
    try await eventually("Expected \(setting) to equal \(expected)") {
      let actual = try await self.readSettingText(setting)
      return Self.boolTextValue(actual) == expected
    }
  }

  func expectSettingJSONString(_ setting: String, equals expected: String) async throws {
    try await eventually("Expected \(setting) to equal \(expected)") {
      let actual = try await self.readSettingJSON(setting)
      return Self.stringValue(actual) == expected
    }
  }

  func expectSettingJSONInt(_ setting: String, equals expected: Int) async throws {
    try await eventually("Expected \(setting) to equal \(expected)") {
      let actual = try await self.readSettingJSON(setting)
      return Self.intValue(actual) == expected
    }
  }

  func expectSettingJSONBool(_ setting: String, equals expected: Bool) async throws {
    try await eventually("Expected \(setting) to equal \(expected)") {
      let actual = try await self.readSettingJSON(setting)
      return Self.boolValue(actual) == expected
    }
  }

  func expectRadioChannel(equals expected: Int, timeout: TimeInterval = 90) async throws {
    try await eventually("Expected radio channel to equal \(expected)", timeout: timeout) {
      let actual = try await self.readSettingJSON("raCh")
      guard let value = Self.intValue(actual) else { return false }
      if expected == 1000 {
        return value == 1000 || (1...200).contains(value)
      }
      return value == expected
    }
  }

  func expectProfileString(_ path: String, equals expected: String) async throws {
    try await eventually("Expected \(path) to equal \(expected)") {
      let actual = try await self.readProfileValue(path)
      return Self.stringValue(actual) == expected
    }
  }

  func expectProfileInt(_ path: String, equals expected: Int) async throws {
    try await eventually("Expected \(path) to equal \(expected)") {
      let actual = try await self.readProfileValue(path)
      return Self.intValue(actual) == expected
    }
  }

  func expectProfileBool(_ path: String, equals expected: Bool) async throws {
    try await eventually("Expected \(path) to equal \(expected)") {
      let actual = try await self.readProfileValue(path)
      return Self.boolValue(actual) == expected
    }
  }

  func waitForReachable(timeout: TimeInterval = 240) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    var lastError: Error?
    while Date() < deadline {
      do {
        _ = try await readSettingText("syNm")
        return
      } catch {
        lastError = error
        try await Task.sleep(nanoseconds: 2_000_000_000)
      }
    }
    if let lastError { throw lastError }
  }

  func hasExternalArchiveDestination() async throws -> Bool {
    guard let disks = try await readSettingJSON("MaSt") as? [[String: Any]] else { return false }
    return disks.contains { disk in
      let builtIn = Self.boolValue(disk["builtIn"]) ?? Self.boolValue(disk["builtin"]) ?? false
      guard !builtIn else { return false }
      guard let partitions = disk["partitions"] as? [[String: Any]] else { return false }
      return !partitions.isEmpty
    }
  }

  func waitForBuiltInDiskPartition(timeout: TimeInterval = 600) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    var lastError: Error?
    while Date() < deadline {
      do {
        if try await hasBuiltInDiskPartition() {
          return
        }
      } catch {
        lastError = error
      }
      try await Task.sleep(nanoseconds: 2_000_000_000)
    }
    if let lastError {
      throw LiveAirPortAssertionError(
        message: "Expected built-in disk partition to reappear. Last read failed: \(lastError)")
    }
    throw LiveAirPortAssertionError(message: "Expected built-in disk partition to reappear.")
  }

  func hasBuiltInDiskPartition() async throws -> Bool {
    guard let disks = try await readSettingJSON("MaSt") as? [[String: Any]] else { return false }
    return disks.contains { disk in
      let builtIn = Self.boolValue(disk["builtIn"]) ?? Self.boolValue(disk["builtin"]) ?? false
      guard builtIn else { return false }
      guard let partitions = disk["partitions"] as? [[String: Any]] else { return false }
      return !partitions.isEmpty
    }
  }

  func internetRestoreFlags() async throws -> [(String, String?)] {
    var flags: [(String, String?)] = []
    let connectUsing = Self.connectUsingOption(
      Self.intValue(await optionalProfileValue("restoreProfile.waCV")) ?? 0x8300)
    flags.append(("--connect-using", connectUsing))
    if connectUsing == "static" {
      flags.append(("--ipv4-address", try await requiredProfileString("restoreProfile.waIP")))
      flags.append(("--subnet-mask", try await requiredProfileString("restoreProfile.waSM")))
      flags.append(("--router-address", try await requiredProfileString("restoreProfile.waRA")))
    }
    if connectUsing == "pppoe" {
      flags.append(("--pppoe-account", try await requiredProfileString("restoreProfile.peUN")))
      if let password = await optionalProfileString("restoreProfile.pePW"), !password.isEmpty {
        flags.append(("--pppoe-password", password))
      }
      if let service = await optionalProfileString("restoreProfile.peSN") {
        flags.append(("--pppoe-service", service))
      }
    }

    let dns = await profileStrings(["restoreProfile.waD1", "restoreProfile.waD2"])
      .filter { !$0.isEmpty && $0 != "0.0.0.0" }
    if dns.isEmpty {
      flags.append(("--clear-dns", nil))
    } else {
      dns.forEach { flags.append(("--dns-server", $0)) }
    }

    let ipv6DNS = await profileStrings(["restoreProfile.6NS1", "restoreProfile.6NS2"])
      .filter { !$0.isEmpty && $0 != "::" }
    if ipv6DNS.isEmpty {
      flags.append(("--clear-ipv6-dns", nil))
    } else {
      ipv6DNS.forEach { flags.append(("--ipv6-dns-server", $0)) }
    }

    flags.append(("--domain-name", await optionalProfileString("restoreProfile.waDN") ?? ""))
    flags.append(("--configure-ipv6", await configureIPv6Option()))
    if await optionalProfileBool("restoreProfile.wbEn") == true {
      flags.append(("--dynamic-global-hostname", nil))
      flags.append(("--global-hostname", try await requiredProfileString("restoreProfile.wbHN")))
      flags.append(
        ("--global-hostname-user", await optionalProfileString("restoreProfile.wbHU") ?? ""))
      if let password = await optionalProfileString("restoreProfile.wbHP"), !password.isEmpty {
        flags.append(("--global-hostname-password", password))
      }
    } else {
      flags.append(("--no-dynamic-global-hostname", nil))
    }
    return flags
  }

  func wirelessRestoreFlags() async throws -> [(String, String?)] {
    let mode = Self.wirelessModeOption(Int(try await readSettingText("raSt")) ?? 0)
    var flags: [(String, String?)] = [("--wireless-mode", mode)]
    if mode != "off" {
      flags.append(("--wireless-name", try await readSettingText("raNm")))
      let security = Self.wirelessSecurityOption(Int(try await readSettingText("raWM")) ?? 7)
      flags.append(("--wireless-security", security))
      if security != "none" {
        let password = try await wirelessRestorePassword()
        flags.append(("--wireless-password", password))
      }
      if let regionCode = Int(try await readSettingText("syRe")) {
        flags.append(("--region-code", String(regionCode)))
      }
      let hiddenNetwork = Self.boolTextValue(try await readSettingText("raCl")) ?? false
      flags.append((hiddenNetwork ? "--hidden-network" : "--no-hidden-network", nil))
      let radioMode = Self.radioModeOption(Int(try await readSettingText("raMd")) ?? 6)
      flags.append(("--radio-mode", radioMode))
      if let channel = Self.intTextValue((try? await readSettingText("raCh")) ?? "") {
        flags.append(("--radio-channel", channel == 1000 ? "automatic" : String(channel)))
      }
    }
    return flags
  }

  func networkRestoreFlags() async throws -> [(String, String?)] {
    let routerMode = Self.routerModeOption(
      Self.intValue(await optionalProfileValue("restoreProfile.bsRM")) ?? 3)
    var flags: [(String, String?)] = [("--router-mode", routerMode)]
    if routerMode == "dhcp-and-nat" || routerMode == "dhcp-only" {
      flags.append(("--dhcp-range-start", try await requiredProfileString("restoreProfile.dhBg")))
      flags.append(("--dhcp-range-end", try await requiredProfileString("restoreProfile.dhEn")))
      flags.append(
        (
          "--dhcp-lease",
          String(Self.intValue(await optionalProfileValue("restoreProfile.dhLe")) ?? 86_400)
        ))
      flags.append(("--dhcp-lease-unit", "seconds"))
    }
    if routerMode == "dhcp-and-nat" || routerMode == "nat-only" {
      let natPMP = await optionalProfileInt("restoreProfile.naFl") ?? 0
      flags.append((natPMP == 0 ? "--no-nat-pmp" : "--nat-pmp", nil))
      let defaultHost = await optionalProfileString("restoreProfile.nDMZ") ?? "0.0.0.0"
      if defaultHost == "0.0.0.0" {
        flags.append(("--clear-default-host", nil))
      } else {
        flags.append(("--default-host", defaultHost))
      }
    }
    return flags
  }

  func diskRestoreFlags() async throws -> [(String, String?)] {
    var flags: [(String, String?)] = []
    let fileSharing = await optionalProfileInt("restoreProfile.bsFS") ?? 0
    flags.append((fileSharing == 0 ? "--no-file-sharing" : "--file-sharing", nil))
    let security = Self.diskSecurityOption(await optionalProfileInt("restoreProfile.bsFM") ?? 2)
    flags.append(("--disk-security", security))
    if security == "disk-password" {
      let password =
        await optionalProfileString("restoreProfile.fssp")
        ?? ProcessInfo.processInfo.environment["AIRPORT_LIVE_DISK_RESTORE_PASSWORD"]
      guard let password, !password.isEmpty else {
        throw XCTSkip(
          "Current disk security uses a disk password, but restore password is not readable. Set AIRPORT_LIVE_DISK_RESTORE_PASSWORD."
        )
      }
      flags.append(("--disk-password", password))
    }
    return flags
  }

  private func eventually(
    _ description: String,
    timeout: TimeInterval = 90,
    assertion: () async throws -> Bool
  ) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    var lastError: Error?
    while Date() < deadline {
      do {
        if try await assertion() {
          return
        }
      } catch {
        lastError = error
      }
      try await Task.sleep(nanoseconds: 2_000_000_000)
    }
    if let lastError {
      XCTFail("\(description). Last read failed: \(lastError)")
      throw LiveAirPortAssertionError(message: "\(description). Last read failed: \(lastError)")
    } else {
      XCTFail(description)
      throw LiveAirPortAssertionError(message: description)
    }
  }

  private func requiredProfileString(_ path: String) async throws -> String {
    guard let value = await optionalProfileString(path), !value.isEmpty else {
      throw XCTSkip("Required restore value \(path) is missing from the live profile.")
    }
    return value
  }

  private func optionalProfileString(_ path: String) async -> String? {
    guard let value = await optionalProfileValue(path) else { return nil }
    return Self.stringValue(value)
  }

  private func optionalProfileInt(_ path: String) async -> Int? {
    guard let value = await optionalProfileValue(path) else { return nil }
    return Self.intValue(value)
  }

  private func optionalProfileBool(_ path: String) async -> Bool? {
    guard let value = await optionalProfileValue(path) else { return nil }
    return Self.boolValue(value)
  }

  private func profileStrings(_ paths: [String]) async -> [String] {
    var values: [String] = []
    for path in paths {
      if let value = await optionalProfileString(path) {
        values.append(value)
      }
    }
    return values
  }

  private func configureIPv6Option() async -> String {
    if await optionalProfileInt("restoreProfile.6cfg") == 0 {
      return "link-local"
    }
    if await optionalProfileBool("restoreProfile.6aut") == true {
      return "automatic"
    }
    return "manual"
  }

  private func wirelessRestorePassword() async throws -> String {
    if let password = ProcessInfo.processInfo.environment["AIRPORT_LIVE_WIRELESS_RESTORE_PASSWORD"],
      !password.isEmpty
    {
      return password
    }
    throw XCTSkip(
      "Current wireless security uses a password. Set AIRPORT_LIVE_WIRELESS_RESTORE_PASSWORD so the live test can restore it without reading stored credentials."
    )
  }

  private static func decodeJSON(_ text: String) throws -> Any {
    let data = Data(text.utf8)
    return try JSONSerialization.jsonObject(with: data)
  }

  private static func isTransientACPAuthenticationError(_ error: Error) -> Bool {
    guard case AirportCommandError.failed(let result) = error else { return false }
    let output = result.combinedOutput.lowercased()
    return output.contains("srp proof failed") || output.contains("acp status -6754")
  }

  private static func isRetryableDiskEraseError(_ error: Error) -> Bool {
    guard case AirportCommandError.failed(let result) = error else { return false }
    return result.combinedOutput.contains("diskd.eraseDisk returned status 18446744073709544895")
  }

  private static func stringValue(_ value: Any?) -> String? {
    if let string = value as? String {
      return string
    }
    if let number = value as? NSNumber {
      if CFGetTypeID(number) == CFBooleanGetTypeID() {
        return number.boolValue ? "true" : "false"
      }
      return String(number.intValue)
    }
    guard let object = value as? [String: Any] else { return nil }
    if let text = object["text"] as? String {
      return text
    }
    if let value = object["value"] as? String {
      if let hex = object["hex"] as? String, hex.count == 8, let intValue = UInt32(value) {
        return ipv4String(intValue)
      }
      if let hex = object["hex"] as? String, hex.count == 32 {
        return ipv6String(hex) ?? value
      }
      return value
    }
    if let hex = object["hex"] as? String {
      if hex.count == 8, let intValue = UInt32(hex, radix: 16) {
        return ipv4String(intValue)
      }
      if hex.count == 32 {
        return ipv6String(hex)
      }
    }
    return nil
  }

  private static func intValue(_ value: Any?) -> Int? {
    if let number = value as? NSNumber {
      return number.intValue
    }
    if let string = value as? String {
      return Int(string)
    }
    guard let object = value as? [String: Any] else { return nil }
    if let value = object["value"] as? String, let intValue = Int(value) {
      return intValue
    }
    if let text = object["text"] as? String,
      let intValue = Int(text.trimmingCharacters(in: .whitespaces))
    {
      return intValue
    }
    if let hex = object["hex"] as? String, hex.count <= 8, let intValue = Int(hex, radix: 16) {
      return intValue
    }
    return nil
  }

  private static func boolValue(_ value: Any?) -> Bool? {
    if let bool = value as? Bool {
      return bool
    }
    if let number = value as? NSNumber {
      return number.boolValue
    }
    if let string = value as? String {
      switch string.lowercased() {
      case "true", "1": return true
      case "false", "0": return false
      default:
        if let intValue = intTextValue(string) {
          return intValue != 0
        }
        return nil
      }
    }
    guard let object = value as? [String: Any] else { return nil }
    if let text = object["text"] as? String {
      return boolValue(text.trimmingCharacters(in: .whitespaces))
    }
    if let value = object["value"] {
      return boolValue(value)
    }
    return nil
  }

  private static func intTextValue(_ value: String) -> Int? {
    let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if let intValue = Int(text) {
      return intValue
    }
    if let intValue = Int(text, radix: 16) {
      return intValue
    }
    return nil
  }

  private static func boolTextValue(_ value: String) -> Bool? {
    let text = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    switch text {
    case "true", "1", "01":
      return true
    case "false", "0", "00":
      return false
    default:
      if let intValue = intTextValue(text) {
        return intValue != 0
      }
      return nil
    }
  }

  private static func ipv4String(_ value: UInt32) -> String {
    [
      (value >> 24) & 0xff,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ].map(String.init).joined(separator: ".")
  }

  private static func ipv6String(_ hex: String) -> String? {
    guard hex.count == 32 else { return nil }
    var groups: [String] = []
    var index = hex.startIndex
    for _ in 0..<8 {
      let next = hex.index(index, offsetBy: 4)
      let group = String(hex[index..<next])
      groups.append(String(Int(group, radix: 16) ?? 0, radix: 16))
      index = next
    }
    return compressIPv6Groups(groups)
  }

  private static func compressIPv6Groups(_ groups: [String]) -> String {
    var bestStart: Int?
    var bestLength = 0
    var index = 0
    while index < groups.count {
      if groups[index] != "0" {
        index += 1
        continue
      }
      let start = index
      while index < groups.count && groups[index] == "0" {
        index += 1
      }
      let length = index - start
      if length > bestLength {
        bestStart = start
        bestLength = length
      }
    }
    guard let start = bestStart, bestLength > 1 else {
      return groups.joined(separator: ":")
    }
    let before = groups[..<start].joined(separator: ":")
    let after = groups[(start + bestLength)...].joined(separator: ":")
    if before.isEmpty && after.isEmpty { return "::" }
    if before.isEmpty { return "::\(after)" }
    if after.isEmpty { return "\(before)::" }
    return "\(before)::\(after)"
  }

  private static func connectUsingOption(_ value: Int) -> String {
    switch value {
    case 0x8400: return "static"
    case 0x8900: return "pppoe"
    default: return "dhcp"
    }
  }

  private static func wirelessModeOption(_ value: Int) -> String {
    switch value {
    case 3: return "off"
    case 20: return "extend"
    default: return "create"
    }
  }

  private static func wirelessSecurityOption(_ value: Int) -> String {
    switch value {
    case 1: return "none"
    case 5: return "wpa-wpa2-personal"
    default: return "wpa2-personal"
    }
  }

  private static func radioModeOption(_ value: Int) -> String {
    switch value {
    case 3: return "80211g"
    case 7: return "80211n-only-24"
    case 8: return "80211n-only-5"
    default: return "80211n-bg"
    }
  }

  private static func routerModeOption(_ value: Int) -> String {
    switch value {
    case 0: return "dhcp-and-nat"
    case 1: return "dhcp-only"
    case 2: return "nat-only"
    default: return "bridge"
    }
  }

  private static func diskSecurityOption(_ value: Int) -> String {
    switch value {
    case 0: return "accounts"
    case 1: return "disk-password"
    default: return "device-password"
    }
  }
}
