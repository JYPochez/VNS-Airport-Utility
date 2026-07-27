import Darwin
import Foundation

final class AirPortBonjourBrowser: NSObject {
  private let serviceTypes = ["_airport._tcp."]
  private static let stableIdentifierTXTKeys = ["wama", "rama", "sysn"]
  private static let knownModelNameFragments = ["express", "time capsule", "extreme"]
  private let onChange: @MainActor ([AirportDiscoveredDevice]) -> Void
  private var browsers: [NetServiceBrowser] = []
  private var services: [String: NetService] = [:]

  init(onChange: @escaping @MainActor ([AirportDiscoveredDevice]) -> Void) {
    self.onChange = onChange
    super.init()
  }

  func start() {
    stop()
    for serviceType in serviceTypes {
      let browser = NetServiceBrowser()
      browser.delegate = self
      browser.searchForServices(ofType: serviceType, inDomain: "local.")
      browsers.append(browser)
    }
  }

  func stop() {
    for browser in browsers {
      browser.stop()
      browser.delegate = nil
    }
    browsers.removeAll()
    for service in services.values {
      service.stop()
      service.delegate = nil
    }
    services.removeAll()
    publish()
  }

  private func key(for service: NetService) -> String {
    "\(service.domain)|\(service.type)|\(service.name)"
  }

  private func publish() {
    let devices = services.values
      .map(device)
      .sorted {
        $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
      }
    let onChange = onChange
    Task { @MainActor in
      onChange(devices)
    }
  }

  private func device(from service: NetService) -> AirportDiscoveredDevice {
    let txtRecord = service.txtRecordData().map(NetService.dictionary(fromTXTRecord:)) ?? [:]
    let txtFields = Self.airportTXTFields(from: txtRecord)
    return AirportDiscoveredDevice(
      id: key(for: service),
      name: service.name,
      hostName: service.hostName ?? "",
      addresses: service.addresses?.compactMap(Self.numericHostAddress) ?? [],
      identifiers: Self.stableIdentifiers(fromTXTRecord: txtRecord),
      txtFields: txtFields,
      modelName: Self.modelName(fromTXTFields: txtFields),
      productID: txtFields["syap"] ?? ""
    )
  }

  static func stableIdentifiers(fromTXTRecord txtRecord: [String: Data]) -> [String] {
    let fields = airportTXTFields(from: txtRecord)
    return stableIdentifierTXTKeys.compactMap { key in
      guard let value = fields[key], !value.isEmpty else { return nil }
      return "\(key):\(value.lowercased())"
    }
  }

  static func airportTXTFields(from txtRecord: [String: Data]) -> [String: String] {
    var fields: [String: String] = [:]
    for (key, data) in txtRecord {
      let key = key.trimmingCharacters(in: .whitespacesAndNewlines)
      let value =
        String(data: data, encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
      let rawRecord = value.isEmpty ? key : "\(key)=\(value)"
      for field in rawRecord.split(separator: ",") {
        let field = field.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let separator = field.firstIndex(of: "=") else { continue }
        let fieldKey = field[..<separator]
          .trimmingCharacters(in: .whitespacesAndNewlines)
          .lowercased()
        let fieldValue = field[field.index(after: separator)...]
          .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !fieldKey.isEmpty, !fieldValue.isEmpty else { continue }
        fields[fieldKey] = fieldValue
      }
    }
    return fields
  }

  static func modelName(fromTXTFields fields: [String: String]) -> String {
    let description = fields["syds"]?
      .replacingOccurrences(of: "\\ ", with: " ")
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !description.isEmpty {
      let modelName = description.replacingOccurrences(
        of: #"\s+V\d+(?:\.\d+)*$"#,
        with: "",
        options: .regularExpression)
      let lowercasedModelName = modelName.lowercased()
      if knownModelNameFragments.contains(where: lowercasedModelName.contains) {
        return modelName
      }
    }
    switch fields["syap"]?.trimmingCharacters(in: .whitespacesAndNewlines) {
    case "102", "107", "115":
      return "AirPort Express"
    case "106", "109", "113", "116", "119":
      return "AirPort Time Capsule"
    case "3", "104", "105", "108", "114", "117", "120":
      return "AirPort Extreme"
    default:
      return ""
    }
  }

  private static func numericHostAddress(from data: Data) -> String? {
    data.withUnsafeBytes { rawBuffer -> String? in
      guard rawBuffer.count >= MemoryLayout<sockaddr>.size,
        let sockaddrPointer = rawBuffer.baseAddress?.assumingMemoryBound(to: sockaddr.self)
      else {
        return nil
      }
      let addressLength = Int(sockaddrPointer.pointee.sa_len)
      guard addressLength >= MemoryLayout<sockaddr>.size,
        addressLength <= rawBuffer.count
      else {
        return nil
      }
      var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
      let result = getnameinfo(
        sockaddrPointer,
        socklen_t(addressLength),
        &hostBuffer,
        socklen_t(hostBuffer.count),
        nil,
        0,
        NI_NUMERICHOST
      )
      guard result == 0 else { return nil }
      let terminatorIndex = hostBuffer.firstIndex(of: 0) ?? hostBuffer.count
      return String(
        decoding: hostBuffer[..<terminatorIndex].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
  }
}

extension AirPortBonjourBrowser: NetServiceBrowserDelegate {
  func netServiceBrowser(
    _ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool
  ) {
    services[key(for: service)] = service
    service.delegate = self
    service.resolve(withTimeout: 5)
    if !moreComing {
      publish()
    }
  }

  func netServiceBrowser(
    _ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool
  ) {
    services.removeValue(forKey: key(for: service))
    if !moreComing {
      publish()
    }
  }

  func netServiceBrowserDidStopSearch(_ browser: NetServiceBrowser) {
    publish()
  }
}

extension AirPortBonjourBrowser: NetServiceDelegate {
  func netServiceDidResolveAddress(_ sender: NetService) {
    services[key(for: sender)] = sender
    publish()
  }

  func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
    services[key(for: sender)] = sender
    publish()
  }
}
