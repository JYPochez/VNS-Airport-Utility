import Foundation

enum DeviceStatusMessage {
  static func text(problemCodes: [String]) -> String {
    let codes = Set(normalizedProblemCodes(problemCodes))
    guard !codes.isEmpty else { return "Working normally" }

    if !codes.isDisjoint(with: ["ArcI"]) {
      return "Archiving disk"
    }
    if !codes.isDisjoint(with: ["EraI"]) {
      return "Erasing disk"
    }
    if !codes.isDisjoint(with: ["fsck", "Ifsc", "SSdF", "mgrt"]) {
      return "Disk needs repair"
    }
    if !codes.isDisjoint(with: ["Ifsl"]) {
      return "Disk space is low"
    }
    if !codes.isDisjoint(with: ["DubN"]) {
      return "Double NAT"
    }
    if !codes.isDisjoint(with: ["nDNS"]) {
      return "No DNS servers configured"
    }
    if !codes.isDisjoint(with: ["pubP"]) {
      return "Default password"
    }
    if !codes.isDisjoint(with: ["opNW"]) {
      return "Open wireless network"
    }
    if !codes.isDisjoint(with: ["waCF"]) {
      return "WAN setup over Ethernet"
    }
    if !codes.isDisjoint(with: ["wdsP", "bsWD"]) {
      return "Wireless extension problem"
    }
    if codes.contains(where: { $0.hasPrefix("vErr") }) {
      return "Configuration problem"
    }
    return "Needs attention: \(codes.sorted().joined(separator: ", "))"
  }

  static func text(reader: ProfileReader) -> String {
    text(problemCodes: problemCodes(reader: reader, allowSetupOverWAN: nil))
  }

  static func detail(problemCodes: [String], routerMode: RouterMode) -> String {
    details(problemCodes: problemCodes, routerMode: routerMode).first ?? ""
  }

  static func details(problemCodes: [String], routerMode: RouterMode) -> [String] {
    let codes = Set(normalizedProblemCodes(problemCodes))
    var details: [String] = []
    if codes.contains("DubN") {
      if routerMode == .bridge {
        details.append("Reports Double NAT despite Bridge Mode.")
      } else {
        details.append("Another router appears to be providing NAT upstream of this base station.")
      }
    }
    if codes.contains("pubP") {
      details.append("The base station is still using the default admin password.")
    }
    if codes.contains("opNW") {
      details.append("The wireless network is open and does not require a Wi-Fi password.")
    }
    if codes.contains("waCF") {
      details.append("Setup over the Ethernet WAN port is enabled.")
    }
    if codes.contains("ctim") {
      details.append("Initial setup has not been marked complete.")
    }
    return details
  }

  static func normalizedProblemCodes(_ problemCodes: [String]) -> [String] {
    problemCodes.map {
      $0.trimmingCharacters(in: .whitespacesAndNewlines)
    }.filter { !$0.isEmpty }
  }

  static func liveAllowSetupOverWAN(reader: ProfileReader) -> Bool? {
    if let allowsRemoteConfiguration =
      reader.bool("settings.raWB") ?? reader.boolFromInt("settings.raWB")
    {
      return allowsRemoteConfiguration
    }
    guard let blocksRemoteConfiguration = reader.boolFromInt("settings.waNM") else {
      return nil
    }
    return !blocksRemoteConfiguration
  }

  static func problemCodes(reader: ProfileReader, allowSetupOverWAN: Bool?) -> [String] {
    let decodedCodes = reader.strings("settings.sySt.decoded.problems")
    let codes = decodedCodes.isEmpty ? reader.strings("settings.sySt.problems") : decodedCodes
    guard allowSetupOverWAN == false else { return codes }
    return codes.filter { $0 != "waCF" }
  }
}
