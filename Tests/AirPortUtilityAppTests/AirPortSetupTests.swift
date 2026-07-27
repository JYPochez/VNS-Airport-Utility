import XCTest
@testable import AirPortUtilityCore

@MainActor
final class AirPortSetupTests: XCTestCase {
  func testSetupDetailsRequireNamesAndMatchingEightCharacterPasswords() {
    var setup = AirPortSetupState(
      step: .details, mode: .create, deviceName: "new airport", networkName: "new network",
      password: "password", verifyPassword: "password")
    XCTAssertTrue(setup.canContinueDetails)

    setup.verifyPassword = "different"
    XCTAssertFalse(setup.canContinueDetails)
    setup.verifyPassword = "short"
    setup.password = "short"
    XCTAssertFalse(setup.canContinueDetails)
  }

  func testReplaceSetupRequiresSourceDeviceInsteadOfNetworkName() {
    var setup = AirPortSetupState(
      step: .details, mode: .replace, deviceName: "replacement", networkName: "",
      password: "password", verifyPassword: "password")
    XCTAssertFalse(setup.canContinueDetails)
    setup.sourceDeviceID = "source"
    XCTAssertTrue(setup.canContinueDetails)
  }

  func testBeginSetupUsesSelectedNewDeviceIdentity() {
    let model = AirportAppModel()
    let device = AirportDiscoveredDevice(
      id: "new-express", name: "AirPort Express eb68e8",
      hostName: "airport-express-eb68e8.local.", txtFields: ["syfl": "0x40"],
      modelName: "AirPort Express", productID: "115")

    model.beginSetup(for: device)

    XCTAssertTrue(model.isShowingSetup)
    XCTAssertEqual(model.setup.deviceName, "AirPort Express eb68e8")
    XCTAssertEqual(model.setup.networkName, "AirPort Express eb68e8")
    XCTAssertEqual(model.setup.step, .examining)
  }

  func testFactoryGeneratedBonjourNamesRequireSetupWhenFlagsAreTemporarilyMissing() {
    for name in [
      "AirPort Express eb68e8", "AirPort Extreme ed08ad",
      "AirPort Time Capsule b92ec3", "Base Station 21f58f",
    ] {
      let device = AirportDiscoveredDevice(id: name, name: name, hostName: "base.local.")
      XCTAssertFalse(device.isNewAirPortDevice)
      XCTAssertTrue(device.requiresSetup, name)
      XCTAssertFalse(device.usesDefaultAdminPassword, name)
    }
    let configured = AirportDiscoveredDevice(
      id: "configured", name: "Living Room AirPort", hostName: "living-room.local.")
    XCTAssertFalse(configured.requiresSetup)
  }

  func testOtherWiFiDeviceSetupSelectionUsesPublicAndOpensWizard() {
    let model = AirportAppModel()
    let device = AirportDiscoveredDevice(
      id: "new-express", name: "AirPort Express eb68e8",
      hostName: "airport-express-eb68e8.local.", txtFields: ["syfl": "0x40"],
      modelName: "AirPort Express")
    model.updateDiscoveredDevices([device])

    model.presentOtherWiFiDeviceFromMenu(id: device.id)

    XCTAssertEqual(model.connection.host, "airport-express-eb68e8.local")
    XCTAssertEqual(model.connection.password, "public")
    XCTAssertTrue(model.hasTrustedConnectionPassword)
    XCTAssertTrue(model.isShowingSetup)
    XCTAssertFalse(model.isDevicePopoverPresented)
  }

  func testDefaultNamedProductThreeDoesNotOverwriteKnownAdminPassword() {
    let model = AirportAppModel()
    model.connection.host = "10.0.1.1"
    model.connection.password = "password"
    model.hasTrustedConnectionPassword = true
    let device = AirportDiscoveredDevice(
      id: "spaceship", name: "Base Station 98293a",
      hostName: "Base-Station-98293a.local.", addresses: ["10.0.1.1"],
      txtFields: ["syfl": "0x00000A00"], modelName: "Apple Base Station V5.7",
      productID: "3")
    model.updateDiscoveredDevices([device])

    model.presentOtherWiFiDeviceFromMenu(id: device.id)

    XCTAssertEqual(model.connection.password, "password")
    XCTAssertTrue(model.isShowingSetup)
  }

  func testRestoreConfirmationRequiresAConnectedOrSelectedDevice() {
    let model = AirportAppModel()
    model.connection.host = ""
    model.requestRestoreDefaultSettings()
    XCTAssertFalse(model.isShowingRestoreConfirmation)

    model.connection.host = "192.0.2.1"
    model.requestRestoreDefaultSettings()
    XCTAssertTrue(model.isShowingRestoreConfirmation)

    model.isRestoringDefaults = true
    XCTAssertFalse(model.canRequestRestoreDefaultSettings)
    model.isRestoringDefaults = false
    model.isShowingSetup = true
    XCTAssertFalse(model.canRequestRestoreDefaultSettings)
  }

  func testRestoreUsesCapturedEmptyFactoryResetThenRebootProperties() throws {
    let model = AirportAppModel()
    model.connection.host = "192.0.2.1"
    model.connection.password = "password"

    let commands = model.restoreDefaultCommandSequence(connection: model.connection)

    XCTAssertEqual(commands.map(\.0), ["Restore Factory Defaults", "Restart Base Station"])
    XCTAssertEqual(commands[0].1.first, "legacy-write")
    XCTAssertEqual(value(after: "--setting", in: commands[0].1), "acRF")
    XCTAssertEqual(value(after: "--setting", in: commands[1].1), "acRB")
    XCTAssertEqual(value(after: "--password", in: commands[0].1), "password")
    XCTAssertEqual(value(after: "--password", in: commands[1].1), "public")
    XCTAssertEqual(value(after: "--value-json", in: commands[0].1), #"{"type":"bytes","hex":""}"#)
    XCTAssertEqual(value(after: "--value-json", in: commands[1].1), #"{"type":"bytes","hex":""}"#)
    XCTAssertTrue(commands.allSatisfy { $0.1.contains("--streaming") })
    XCTAssertEqual(commands.map { value(after: "--request-flags", in: $0.1) }, ["0", "0"])
  }

  func testProductThreeRestoreMatchesCapturedFiveStreamingMarkers() {
    let model = AirportAppModel()
    model.baseStation.productID = "3"
    model.connection.host = "192.0.2.1"
    model.connection.password = "password"

    let commands = model.restoreDefaultCommandSequence(connection: model.connection)

    XCTAssertEqual(
      commands.compactMap { value(after: "--setting", in: $0.1) },
      ["lebl", "acRF", "acRB", "lebs", "acRB"])
    XCTAssertEqual(
      commands.compactMap { value(after: "--password", in: $0.1) },
      ["password", "password", "password", "public", "public"])
    XCTAssertTrue(commands.allSatisfy { $0.1.contains("--streaming") })
    XCTAssertTrue(commands.allSatisfy { $0.1.contains("--acp17") })
    XCTAssertEqual(
      commands.compactMap { value(after: "--request-flags", in: $0.1) },
      ["0", "0", "0", "0", "0"])
  }

  func testProductThreeSetupDoesNotExposeOrWriteAirPlay() {
    let model = AirportAppModel()
    model.usesLegacyACP = true
    model.baseStation.productID = "3"
    model.capabilities = DeviceCapabilities.forProductID("3")
    model.connection.host = "192.0.2.1"
    model.connection.password = "public"
    model.setup = AirPortSetupState(
      step: .details, mode: .create, deviceName: "spaceship",
      networkName: "spaceship network", password: "password", verifyPassword: "password",
      airPlaySpeakerName: "spaceship")

    let commands = model.setupCommandSequence(connection: model.connection)
    let arguments = commands.flatMap(\.1)

    XCTAssertFalse(model.showsSetupAirPlayControls)
    XCTAssertFalse(arguments.contains("--airplay-enabled"))
    XCTAssertFalse(arguments.contains("--no-airplay-enabled"))
    XCTAssertFalse(arguments.contains("--airplay-speaker-name"))
    XCTAssertTrue(arguments.contains("--acp17"))
  }

  func testExpressSetupStillExposesAirPlay() {
    let model = AirportAppModel()
    model.capabilities = DeviceCapabilities.forProductID("115")

    XCTAssertTrue(model.showsSetupAirPlayControls)
  }

  func testRestoreSheetRemainsPresentedAndExecutesBothWritesWhileWaitingForRestart() async throws {
    let model = AirportAppModel()
    model.mockMode = true
    model.connection.host = "192.0.2.1"
    model.requestRestoreDefaultSettings()

    model.restoreDefaultSettings()

    XCTAssertTrue(model.isShowingRestoreConfirmation)
    XCTAssertTrue(model.isRestoringDefaults)

    for _ in 0..<50 where model.isBusy {
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    let log = model.logs.joined(separator: "\n")
    XCTAssertTrue(log.contains("acRF"), log)
    XCTAssertTrue(log.contains("acRB"), log)
  }

  func testRestoreQueuesBehindAnActiveBackgroundOperation() {
    let model = AirportAppModel()
    model.mockMode = true
    model.connection.host = "192.0.2.1"
    model.isShowingRestoreConfirmation = true
    model.isBusy = true

    model.restoreDefaultSettings()

    XCTAssertTrue(model.isRestorePending)
    XCTAssertEqual(model.pendingRestoreConnection?.host, "192.0.2.1")
    XCTAssertFalse(model.isRestoringDefaults)
    XCTAssertTrue(model.isShowingRestoreConfirmation)

    model.isBusy = false
    model.connection.host = "other-device.local"
    model.startPendingRestoreIfNeeded()

    XCTAssertFalse(model.isRestorePending)
    XCTAssertTrue(model.isRestoringDefaults)
    XCTAssertTrue(model.isBusy)
  }

  func testFactoryDeviceDoesNotEnterSetupBeforeRestoreCommandsComplete() {
    let model = AirportAppModel()
    model.isRestoringDefaults = true
    model.isWaitingForRestoreRestart = false
    model.updatingBaseStationDeviceIdentifiers = ["wama:00-11-22-33-44-55"]
    let reset = AirportDiscoveredDevice(
      id: "reset", name: "Base Station 4455", hostName: "base-station.local.",
      identifiers: ["wama:00-11-22-33-44-55"], txtFields: ["syfl": "0x40"])

    model.updateDiscoveredDevices([reset])

    XCTAssertTrue(model.isRestoringDefaults)
    XCTAssertFalse(model.isShowingSetup)

    model.isWaitingForRestoreRestart = true
    model.completeRestoreIfResetDeviceAvailable()

    XCTAssertFalse(model.isRestoringDefaults)
    XCTAssertTrue(model.isShowingSetup)
  }

  func testSetupApplyReportsBusyOperationInsteadOfSilentlyDoingNothing() {
    let model = AirportAppModel()
    model.isBusy = true
    model.setup = AirPortSetupState(
      step: .details, mode: .create, deviceName: "extreme", networkName: "network",
      password: "password", verifyPassword: "password", profile: .object([:]))

    model.applySetup()

    XCTAssertEqual(model.setup.step, .details)
    XCTAssertTrue(model.setup.errorText.contains("Wait for the current"))
  }

  func testRestartingSequenceCompletesAfterBonjourChangesConnectionHost() async throws {
    let model = AirportAppModel()
    model.mockMode = true
    let originalConnection = AirportConnection(
      host: "base-station.local", password: "public", repoPath: model.connection.repoPath)
    model.connection = AirportConnection(
      host: "airport-extreme.local", password: "password", repoPath: model.connection.repoPath)
    var completed = false

    model.applySequence(
      title: "Setup",
      commands: [("Setup", ["write", "base-station.local", "--password", "public"])],
      connection: originalConnection, cleanScope: .none,
      allowsConnectionHostChange: true
    ) {
      completed = true
    }

    for _ in 0..<50 where model.isBusy {
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTAssertTrue(completed)
  }

  func testRestoringSelectedDeviceUsesRestoringStatusForYellowIndicator() {
    let model = AirportAppModel()
    let device = AirportDiscoveredDevice(
      id: "capsule", name: "time capsule", hostName: "time-capsule.local.",
      identifiers: ["wama:00-11-22-33-44-55"])
    model.selectTopologyDevice(device)

    XCTAssertEqual(model.deviceStatusText(for: device), "Working normally")
    XCTAssertFalse(model.isTopologyDeviceRestoring(device))

    model.isRestoringDefaults = true

    XCTAssertTrue(model.isTopologyDeviceRestoring(device))
    XCTAssertEqual(model.deviceStatusText(for: device), "Restoring")
  }

  private func value(after flag: String, in arguments: [String]) -> String? {
    guard let index = arguments.firstIndex(of: flag), arguments.indices.contains(index + 1) else {
      return nil
    }
    return arguments[index + 1]
  }

  func testCreateSetupBuildsTraceShapedNetworkAndCompletionFlags() throws {
    let model = AirportAppModel()
    model.connection.host = "192.0.2.1"
    model.connection.password = "public"
    model.setup = AirPortSetupState(
      step: .details, mode: .create, deviceName: "new airport", networkName: "new network",
      password: "password", verifyPassword: "password")

    let commands = model.setupCommandSequence(connection: model.connection)
    let network = try XCTUnwrap(commands.first?.1)

    XCTAssertTrue(network.contains("--wireless-mode"))
    XCTAssertTrue(network.contains("create"))
    XCTAssertTrue(network.contains("--router-mode"))
    XCTAssertTrue(network.contains("dhcp-and-nat"))
    XCTAssertFalse(network.contains("--setup-complete"))
    XCTAssertTrue(commands.last?.1.contains("--setup-complete") == true)
    XCTAssertEqual(value(after: "--wireless-security", in: network), "wpa-wpa2-personal")
    XCTAssertTrue(network.contains("--allow-network-extension"))
    XCTAssertTrue(network.contains("--allow-setup-over-wan"))
    XCTAssertTrue(network.contains("--dhcp-range-start"))
    XCTAssertEqual(commands.last?.0, "Base Station Password")
  }

  func testTimeCapsuleCreateSetupUsesCapturedBridgeMode() throws {
    let model = AirportAppModel()
    model.baseStation.productID = "106"
    model.connection.host = "192.0.2.1"
    model.connection.password = "public"
    model.setup = AirPortSetupState(
      step: .details, mode: .create, deviceName: "time capsule", networkName: "time capsule",
      password: "password", verifyPassword: "password")

    let network = try XCTUnwrap(model.setupCommandSequence(connection: model.connection).first?.1)

    XCTAssertEqual(value(after: "--router-mode", in: network), "bridge")
    XCTAssertEqual(value(after: "--connect-using", in: network), "dhcp")
  }

  func testModernSetupUsesOneAtomicTraceOrderedDictionaryWrite() throws {
    let model = AirportAppModel()
    model.baseStation.productID = "106"
    model.connection.host = "192.0.2.1"
    model.connection.password = "public"
    model.setup = AirPortSetupState(
      step: .details, mode: .create, deviceName: "time capsule", networkName: "time capsule",
      password: "password", verifyPassword: "password",
      profile: .object([
        "restoreProfile": .object([
          "syNm": .string("AirPort Time Capsule b92ec3"),
          "timz": .object(["zoneName": .string("America/New_York")]),
          "WiFi": .object([
            "radios": .array([
              .object(["raMA": .object(["type": .string("bytes"), "hex": .string("0021e9b92ec3")])])
            ])
          ]),
        ]),
        "currentProfile": .number(0),
        "profiles": .array([.object(["syNm": .string("stale profile")])]),
      ]))

    let commands = model.setupCommandSequence(connection: model.connection)
    let command = try XCTUnwrap(commands.first?.1)
    let valuesJSON = try XCTUnwrap(value(after: "--values-json", in: command))

    XCTAssertEqual(commands.count, 1)
    XCTAssertEqual(command.first, "write")
    XCTAssertTrue(command.contains("--no-verify"))
    let expectedOrder = [
      "AUVs", "Prof", "WiFi", "ctim", "lcVr", "lcVs", "raDS", "raNA", "raWB",
      "syNm", "syPW", "timz",
    ]
    var previous = valuesJSON.startIndex
    for key in expectedOrder {
      let range = try XCTUnwrap(valuesJSON.range(of: "\"\(key)\"", range: previous..<valuesJSON.endIndex))
      previous = range.upperBound
    }
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(valuesJSON.utf8)) as? [String: Any])
    XCTAssertEqual(Set(object.keys), Set(expectedOrder))
    let emittedProfile = try XCTUnwrap(object["Prof"] as? [String: Any])
    XCTAssertEqual(Set(emittedProfile.keys), ["restoreProfile"])
  }

  func testFactoryDefaultACPRecordsRetainProfileSchemaTypes() throws {
    let integerTemplate: JSONValue = .object([
      "type": .string("integer"), "decimal": .string("7"), "width": .number(4),
    ])
    let integerRecord: JSONValue = .object(["value": .string("4294967295")])
    XCTAssertEqual(
      AirportAppModel.factoryProfileValue(record: integerRecord, matching: integerTemplate),
      .object([
        "type": .string("integer"), "decimal": .string("4294967295"),
        "width": .number(4),
      ]))

    XCTAssertEqual(
      AirportAppModel.factoryProfileValue(
        record: .object(["hex": .string("01"), "value": .string("01")]),
        matching: .bool(false)),
      .bool(true))
    XCTAssertEqual(
      AirportAppModel.factoryProfileValue(
        record: .object(["value": .string("fe80::1")]), matching: .string("::")),
      .string("fe80::1"))
    XCTAssertEqual(
      AirportAppModel.factoryProfileValue(
        record: .object(["hex": .string("00000000000000000000000000000000")]),
        matching: .string("::")),
      .string("::"))
    XCTAssertEqual(
      AirportAppModel.factoryProfileValue(
        record: .object(["decoded": .object(["entries": .array([])])]),
        matching: .object(["entries": .array([.string("stale")])])),
      .object(["entries": .array([])]))
  }

  func testSetupProfileTemplateUsesNearestTracedModelFamily() throws {
    XCTAssertEqual(SetupProfileTemplates.tracedProductID(for: "102"), "115")
    XCTAssertEqual(SetupProfileTemplates.tracedProductID(for: "109"), "106")
    XCTAssertEqual(SetupProfileTemplates.tracedProductID(for: "117"), "120")
    XCTAssertEqual(
      SetupProfileTemplates.tracedProductID(for: "999", modelName: "AirPort Express"), "115")
    XCTAssertEqual(
      SetupProfileTemplates.tracedProductID(for: "999", modelName: "AirPort Time Capsule"), "106")

    for productID in ["115", "120", "106"] {
      let profile = try SetupProfileTemplates.load(productID: productID)
      guard case .object(let wrapper) = profile else {
        return XCTFail("Template \(productID) is not an object")
      }
      XCTAssertEqual(Set(wrapper.keys), ["restoreProfile"])
    }
  }

  func testLegacySetupIncludesAirPlayAndRestartMarkers() throws {
    let model = AirportAppModel()
    model.usesLegacyACP = true
    model.connection.host = "192.0.2.1"
    model.connection.password = "public"
    let empty: JSONValue = .object(["type": .string("bytes"), "hex": .string("")])
    model.setup = AirPortSetupState(
      step: .details, mode: .create, deviceName: "old express", networkName: "old express",
      password: "password", verifyPassword: "password", airPlaySpeakerName: "old express",
      profile: .object([
        "settings": .object(
          Dictionary(uniqueKeysWithValues: AirportAppModel.legacySetupSnapshotSettings.map { ($0, empty) })
        )
      ]))

    let commands = model.setupCommandSequence(connection: model.connection)
    let command = try XCTUnwrap(commands.first?.1)
    let valuesJSON = try XCTUnwrap(value(after: "--values-json", in: command))
    let values = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(valuesJSON.utf8)) as? [String: Any])

    XCTAssertEqual(commands.count, 1)
    XCTAssertEqual(command.first, "legacy-write")
    XCTAssertEqual(values.count, 116)
    XCTAssertNotNil(values["acFN"])
    XCTAssertNotNil(values["acRB"])
  }

  func testRestoredNewDeviceAutomaticallyEntersSetupAfterDisappearingDuringRestart() async throws {
    let model = AirportAppModel()
    model.mockMode = true
    let configured = AirportDiscoveredDevice(
      id: "configured", name: "old name", hostName: "old.local.",
      identifiers: ["wama:00-11-22-33-44-55"])
    model.selectTopologyDevice(configured)
    model.restoreDefaultSettings()

    model.updateDiscoveredDevices([])

    XCTAssertTrue(model.isRestoringDefaults)
    XCTAssertTrue(model.isShowingRestoreConfirmation)
    XCTAssertNil(model.selectedTopologyDeviceID)
    XCTAssertEqual(model.updatingBaseStationDeviceIdentifiers, ["wama:00-11-22-33-44-55"])

    for _ in 0..<50 where model.isBusy {
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTAssertTrue(model.isWaitingForRestoreRestart)

    let reset = AirportDiscoveredDevice(
      id: "reset", name: "Base Station 4455", hostName: "base-station-4455.local.",
      identifiers: ["wama:00-11-22-33-44-55"], txtFields: ["syfl": "0x40"])

    model.updateDiscoveredDevices([reset])

    XCTAssertFalse(model.isRestoringDefaults)
    XCTAssertFalse(model.isShowingRestoreConfirmation)
    XCTAssertTrue(model.updatingBaseStationDeviceIdentifiers.isEmpty)
    XCTAssertTrue(model.isShowingSetup)
    XCTAssertEqual(model.setup.deviceName, "Base Station 4455")
  }

  func testSetupClosesWhenConfiguredDeviceReturnsWithWarningWithoutDiscoveryGap() {
    let model = AirportAppModel()
    let factoryDevice = AirportDiscoveredDevice(
      id: "factory", name: "AirPort Time Capsule 4455", hostName: "factory.local.",
      identifiers: ["wama:00-11-22-33-44-55"], txtFields: ["syfl": "0x40"])
    model.selectTopologyDevice(factoryDevice)
    model.isShowingSetup = true
    model.setup = AirPortSetupState(step: .applying, deviceName: "time capsule")
    model.updatingBaseStationDeviceIdentifiers = factoryDevice.normalizedStableIdentifiers
    model.setupPreRestartServiceID = factoryDevice.id

    var unchangedFactoryService = factoryDevice
    unchangedFactoryService.txtFields = [:]
    model.setupWriteDidSucceed(password: "password")
    model.updateDiscoveredDevices([unchangedFactoryService])

    XCTAssertEqual(model.setup.step, .applying)
    XCTAssertTrue(model.isWaitingForSetupRestart)

    let configuredDevice = AirportDiscoveredDevice(
      id: factoryDevice.id, name: "time capsule", hostName: "time-capsule.local.",
      identifiers: ["wama:00-11-22-33-44-55"], txtFields: ["prob": "waNI"])
    model.updateDiscoveredDevices([configuredDevice])

    XCTAssertFalse(model.isShowingSetup)
    XCTAssertEqual(model.setup.step, .complete)
    XCTAssertFalse(model.isWaitingForSetupRestart)
    XCTAssertFalse(model.didSetupDeviceDisappear)
    XCTAssertEqual(model.baseStation.problemCodes, ["waNI"])
    XCTAssertNil(model.selectedTopologyDeviceID)
    XCTAssertFalse(model.isDevicePopoverPresented)
  }

  func testSetupClosesWhenConfiguredDeviceReturnsBeforeWriteCallback() {
    let model = AirportAppModel()
    let factoryDevice = AirportDiscoveredDevice(
      id: "factory", name: "AirPort Extreme 4455", hostName: "factory.local.",
      identifiers: ["wama:00-11-22-33-44-55"], txtFields: ["syfl": "0x40"])
    let configuredDevice = AirportDiscoveredDevice(
      id: "configured", name: "airport extreme", hostName: "airport-extreme.local.",
      identifiers: ["wama:00-11-22-33-44-55"])
    model.selectTopologyDevice(factoryDevice)
    model.isShowingSetup = true
    model.setup = AirPortSetupState(step: .applying, deviceName: "airport extreme")
    model.updatingBaseStationDeviceIdentifiers = factoryDevice.normalizedStableIdentifiers
    model.setupPreRestartServiceID = factoryDevice.id

    model.updateDiscoveredDevices([configuredDevice])

    XCTAssertTrue(model.isShowingSetup)
    XCTAssertFalse(model.isWaitingForSetupRestart)

    model.setupWriteDidSucceed(password: "password")

    XCTAssertFalse(model.isShowingSetup)
    XCTAssertFalse(model.isWaitingForSetupRestart)
    XCTAssertNil(model.selectedTopologyDeviceID)
    XCTAssertFalse(model.isDevicePopoverPresented)
  }

  func testSetupWaitsForConfiguredNameDespiteBonjourBootSeedChange() {
    let model = AirportAppModel()
    let identifiers = ["wama:00-11-22-33-44-55"]
    let factoryDevice = AirportDiscoveredDevice(
      id: "same-service", name: "airport extreme", hostName: "airport-extreme.local.",
      identifiers: identifiers, txtFields: ["syfl": "0x40", "bjsd": "12"])
    let restartedDevice = AirportDiscoveredDevice(
      id: "same-service", name: "old airport name", hostName: "airport-extreme.local.",
      identifiers: identifiers, txtFields: ["bjsd": "13"])
    model.isShowingSetup = true
    model.setup = AirPortSetupState(step: .applying, deviceName: "airport extreme")
    model.updatingBaseStationDeviceIdentifiers = identifiers
    model.setupPreRestartServiceID = factoryDevice.id
    model.setupPreRestartBonjourSeed = "12"
    model.discoveredDevices = [restartedDevice]

    model.setupWriteDidSucceed(password: "password")

    XCTAssertTrue(model.isShowingSetup)
    XCTAssertTrue(model.isWaitingForSetupRestart)

    var configuredDevice = restartedDevice
    configuredDevice.name = "airport extreme"
    model.updateDiscoveredDevices([configuredDevice])

    XCTAssertFalse(model.isShowingSetup)
    XCTAssertNil(model.selectedTopologyDeviceID)
    XCTAssertFalse(model.isDevicePopoverPresented)
  }
}
