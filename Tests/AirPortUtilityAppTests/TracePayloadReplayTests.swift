import Foundation
import XCTest
@testable import AirPortUtilityCore

@MainActor
final class TracePayloadReplayTests: XCTestCase {
  private struct Scenario: Decodable {
    let name: String
    let kind: String?
    let legacy: Bool
    let productID: String
    let deviceName: String
    let networkName: String
    let password: String
    let timestamp: Int
    let profile: JSONValue?
    let includeRestore: Bool
    let restoreOnly: Bool
    let host: String?
    let mergeFactoryDefaults: Bool?
    let useLegacyTemplate: Bool?
    let baseValuesJSON: String?
    let modemPhoneNumber: String?
    let modemAlternateNumber: String?
    let modemAccount: String?
    let modemPassword: String?
    let modemIdleSeconds: Int?
    let modemCountryCode: Int?
    let modemProtocol: String?
    let modemPulseDialing: Bool?
    let modemAutomaticallyDial: Bool?
    let modemIgnoreDialTone: Bool?
    let modemUseAOL: Bool?
  }

  private struct Generated: Encodable {
    let name: String
    let commands: [[String]]
  }

  func testGenerateRealSetupPayloadsForTraceReplay() async throws {
    let environment = ProcessInfo.processInfo.environment
    guard let input = environment["AIRPORT_SWIFT_TRACE_REPLAY_INPUT"],
      let output = environment["AIRPORT_SWIFT_TRACE_REPLAY_OUTPUT"]
    else {
      throw XCTSkip("Set trace replay input and output paths to generate Swift payloads.")
    }
    let scenarios = try JSONDecoder().decode(
      [Scenario].self, from: Data(contentsOf: URL(fileURLWithPath: input)))
    var generated: [Generated] = []
    for scenario in scenarios {
      let model = AirportAppModel()
      model.usesLegacyACP = scenario.legacy
      model.baseStation.productID = scenario.productID
      model.connection.host = scenario.host ?? "192.0.2.1"
      model.connection.password = "public"
      model.capabilities = DeviceCapabilities.forProductID(scenario.productID)
      model.capabilities.supportsIPv6 = false
      model.capabilities.supportsDynamicGlobalHostname = false
      if scenario.kind == "legacy-reset" {
        generated.append(
          Generated(
            name: scenario.name,
            commands: model.restoreDefaultCommandSequence(connection: model.connection).map(\.1)))
        continue
      }
      if scenario.kind == "legacy-update" {
        model.legacyACPSettingsValuesJSON = scenario.baseValuesJSON ?? ""
        model.internet.connectUsing = .modem
        model.internet.modemPhoneNumber = scenario.modemPhoneNumber ?? ""
        model.internet.modemAlternateNumber = scenario.modemAlternateNumber ?? ""
        model.internet.modemAccount = scenario.modemAccount ?? ""
        model.internet.modemPassword = scenario.modemPassword ?? ""
        model.internet.modemVerifyPassword = scenario.modemPassword ?? ""
        model.internet.modemIdleSeconds = scenario.modemIdleSeconds ?? 600
        model.internet.modemCountryCode = scenario.modemCountryCode ?? 0
        model.internet.modemProtocol = scenario.modemProtocol ?? "v34"
        model.internet.modemPulseDialing = scenario.modemPulseDialing ?? false
        model.internet.modemAutomaticallyDial = scenario.modemAutomaticallyDial ?? true
        model.internet.modemIgnoreDialTone = scenario.modemIgnoreDialTone ?? false
        model.internet.modemUseAOL = scenario.modemUseAOL ?? false
        let flags = try XCTUnwrap(model.internetFlags(changesOnly: true))
        let command = model.appliedWriteArguments(
          AirportCommand.friendlyWrite(
            connection: model.connection, flags: flags, dryRun: false))
        generated.append(Generated(name: scenario.name, commands: [command]))
        continue
      }
      if scenario.kind == "legacy-snapshot" {
        model.legacyACPSettingsValuesJSON = scenario.baseValuesJSON ?? ""
        let command = model.appliedWriteArguments(
          AirportCommand.friendlyWrite(
            connection: model.connection, flags: [(String, String?)](), dryRun: false))
        generated.append(Generated(name: scenario.name, commands: [command]))
        continue
      }
      model.setup = AirPortSetupState(
        step: .details, mode: .create, deviceName: scenario.deviceName,
        networkName: scenario.networkName, password: scenario.password,
        verifyPassword: scenario.password, airPlaySpeakerName: scenario.deviceName,
        profile: scenario.profile)
      if scenario.useLegacyTemplate == true {
        model.setup.profile = try SetupProfileTemplates.loadLegacyExtreme()
      }
      if scenario.mergeFactoryDefaults == true {
        model.setup.profile = try await model.readSetupProfile(connection: model.connection)
      }
      var commands: [[String]] = []
      if scenario.includeRestore {
        commands += model.restoreDefaultCommandSequence(connection: model.connection).map(\.1)
      }
      if !scenario.restoreOnly {
        let valuesJSON = scenario.legacy
          ? try model.setupLegacyAtomicValuesJSON(timestamp: scenario.timestamp)
          : try model.setupAtomicValuesJSON(timestamp: scenario.timestamp)
        var command = AirportCommand.rawWriteValuesJSON(
          valuesJSON, connection: model.connection, dryRun: false)
        if scenario.legacy {
          command = command.usingAirPortBackendSubcommand("legacy-write")
          command.append("--streaming")
          if scenario.productID == "3" {
            command.append("--acp17")
          }
        } else {
          command.append("--no-verify")
        }
        commands.append(command)
      }
      generated.append(Generated(name: scenario.name, commands: commands))
    }
    let data = try JSONEncoder().encode(generated)
    try data.write(to: URL(fileURLWithPath: output), options: .atomic)
  }
}
