import Foundation

struct AirportConfigurationFile: Codable {
  var format: String
  var formatVersion: Int
  var exportedAt: String
  var settings: AirportSettingsSnapshot

  init(settings: AirportSettingsSnapshot, exportedAt: String = AirportAppModel.exportTimestamp()) {
    self.format = "AirPortUtility.Configuration"
    self.formatVersion = 1
    self.exportedAt = exportedAt
    self.settings = settings
  }
}

enum AirportBaseConfigurationFileError: LocalizedError {
  case invalidPropertyList
  case invalidCFB0(String)
  case unsupportedCFB0Value(String)

  var errorDescription: String? {
    switch self {
    case .invalidPropertyList:
      "The configuration file is not an AirPort base station property list."
    case .invalidCFB0(let reason):
      "The AirPort profile data is invalid: \(reason)."
    case .unsupportedCFB0Value(let reason):
      "The AirPort profile contains an unsupported value: \(reason)."
    }
  }
}

enum AirportBaseConfigurationFile {
  private static let airportUtilityVersion = "639.26-MacAU"

  static func data(
    from snapshot: AirportSettingsSnapshot,
    capabilities: DeviceCapabilities = DeviceCapabilities()
  ) throws -> Data {
    let profile = profileDictionary(from: snapshot, capabilities: capabilities)
    let profileEnvelope: JSONValue = .object([
      "currentProfile": .number(0),
      "profiles": .array([.object(profile)]),
    ])
    let profileData = try CFB0ProfileCodec.encode(profileEnvelope)

    guard
      var propertyList = try PropertyListJSONValueConverter.propertyListValue(.object(profile))
        as? [String: Any]
    else {
      throw AirportBaseConfigurationFileError.invalidPropertyList
    }

    // Real AirPort Utility keeps the admin password in Prof, not as a flat
    // top-level key, while other password-bearing settings can be present.
    propertyList.removeValue(forKey: "syPW")
    propertyList["APPLE-CONFIG"] = appleConfigMarker
    propertyList["AUVs"] = airportUtilityVersion
    propertyList["cver"] = 0
    propertyList["ctim"] = Int(Date().timeIntervalSinceReferenceDate)
    propertyList["lcVs"] = airportUtilityVersion
    propertyList["Prof"] = profileData
    propertyList["time"] = Int(Date().timeIntervalSince1970)

    return try PropertyListSerialization.data(
      fromPropertyList: propertyList, format: .xml, options: 0)
  }

  static func profileValue(from data: Data) throws -> JSONValue {
    let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    guard let propertyList = plist as? [String: Any] else {
      throw AirportBaseConfigurationFileError.invalidPropertyList
    }

    var object: [String: JSONValue] = [:]
    for (key, value) in propertyList {
      object[key] = PropertyListJSONValueConverter.jsonValue(from: value)
    }

    if let profileData = propertyList["Prof"] as? Data,
      profileData.starts(with: Data("CFB0".utf8)),
      let decoded = try? CFB0ProfileCodec.decode(profileData)
    {
      object["Prof"] = .object([
        "decoded": decoded,
        "hex": .string(profileData.airportHexString),
        "length": .number(Double(profileData.count)),
        "type": .string("bytes"),
      ])
    }

    return .object(object)
  }

  private static var appleConfigMarker: Data {
    var data = Data("APPLE-CONFIG".utf8)
    if data.count < 32 {
      data.append(Data(repeating: 0, count: 32 - data.count))
    }
    return data
  }

  private static func profileDictionary(
    from snapshot: AirportSettingsSnapshot,
    capabilities: DeviceCapabilities
  )
    -> [String: JSONValue]
  {
    var profile: [String: JSONValue] = [
      "DRes": .object(["dhcpReservations": .array([])]),
      "SMBs": .string(normalized(snapshot.disks.winsServer)),
      "SMBw": .string(normalized(snapshot.disks.windowsWorkgroup)),
      "dhBg": .string(normalized(snapshot.network.dhcpRangeStart)),
      "dhEn": .string(normalized(snapshot.network.dhcpRangeEnd)),
      "dhLe": .number(Double(dhcpLeaseSeconds(snapshot.network))),
      "fssp": .string(normalized(snapshot.disks.diskPassword)),
      "laIP": .string(normalized(snapshot.network.lanIPAddress)),
      "name": .string("Default Settings"),
      "nDMZ": .string(normalized(snapshot.network.defaultHost, default: "0.0.0.0")),
      "naFl": .number(snapshot.network.natPMP ? 1 : 0),
      "peID": .number(0),
      "pePW": .string(normalized(snapshot.internet.pppoePassword)),
      "peSN": .string(normalized(snapshot.internet.pppoeService)),
      "peUN": .string(normalized(snapshot.internet.pppoeAccount)),
      "syNm": .string(normalized(snapshot.baseStation.name)),
      "syRe": .number(Double(Int(normalized(snapshot.wireless.regionCode)) ?? 0)),
      "waCV": .number(Double(connectUsingValue(snapshot.internet.connectUsing))),
      "waD1": .string("0.0.0.0"),
      "waD2": .string("0.0.0.0"),
      "waD3": .string("0.0.0.0"),
      "waDN": .string(normalized(snapshot.internet.domainName)),
      "waIP": .string(normalized(snapshot.internet.ipv4Address)),
      "waRA": .string(normalized(snapshot.internet.routerAddress)),
      "waSM": .string(normalized(snapshot.internet.subnetMask)),
    ]

    if !normalized(snapshot.baseStation.newAdminPassword).isEmpty {
      profile["syPW"] = .string(normalized(snapshot.baseStation.newAdminPassword))
    }
    if !normalized(snapshot.baseStation.serialNumber).isEmpty {
      profile["sySN"] = .string(normalized(snapshot.baseStation.serialNumber))
    }
    if !normalized(snapshot.baseStation.version).isEmpty {
      profile["syVs"] = .string(normalized(snapshot.baseStation.version))
    }
    if !normalized(snapshot.baseStation.productID).isEmpty,
      let productID = Int(normalized(snapshot.baseStation.productID))
    {
      profile["syAP"] = .number(Double(productID))
    }

    let pppoe = pppoeConnectionValues(snapshot.internet.pppoeConnection)
    profile["peAC"] = .bool(pppoe.active)
    profile["peSC"] = .bool(pppoe.stayConnected)

    let dnsServers = splitList(snapshot.internet.dnsServers, fillingWith: "0.0.0.0", count: 2)
    profile["waD1"] = .string(dnsServers[0])
    profile["waD2"] = .string(dnsServers[1])

    if capabilities.supportsIPv6 {
      profile["6Lad"] = .string("::")
      profile["6Lfw"] = .bool(true)
      profile["6Lfx"] = .number(0)
      profile["6PDa"] = .string("::")
      profile["6PDl"] = .number(0)
      profile["6Wad"] = .string(normalized(snapshot.internet.ipv6Address, default: "::"))
      profile["6Wfx"] = .number(0)
      profile["6Wgw"] = .string("::")
      profile["6Wte"] = .string("0.0.0.0")

      let ipv6 = ipv6ConfigurationValues(
        snapshot.internet.configureIPv6, mode: snapshot.internet.ipv6Mode)
      profile["6cfg"] = .number(Double(ipv6.mode))
      profile["6aut"] = .bool(ipv6.automatic)

      let ipv6DNSServers = splitList(snapshot.internet.ipv6DNSServers, fillingWith: "::", count: 2)
      profile["6NS1"] = .string(ipv6DNSServers[0])
      profile["6NS2"] = .string(ipv6DNSServers[1])
    }

    if capabilities.supportsDynamicGlobalHostname {
      profile["wbEn"] = .bool(snapshot.internet.dynamicGlobalHostname)
      profile["wbHN"] = .string(normalized(snapshot.internet.globalHostname))
      profile["wbHP"] = .string(normalized(snapshot.internet.globalHostnamePassword))
      profile["wbHU"] = .string(normalized(snapshot.internet.globalHostnameUser))
    }

    if capabilities.supportsLogging {
      profile["slCl"] = .string(
        normalized(snapshot.advanced.syslogDestinationAddress, default: "0.0.0.0"))
      profile["slvl"] = .number(Double(snapshot.advanced.syslogLevel))
      let allowSNMPOverWAN =
        snapshot.advanced.allowSNMP && snapshot.advanced.allowSNMPOverWAN
      let accessFlags =
        (snapshot.advanced.allowSNMP ? 0 : 0x2)
        | (allowSNMPOverWAN ? 0 : 0x1)
      profile["snAF"] = .number(Double(accessFlags))
    }

    if capabilities.supportsPPPDialIn {
      profile["pdFl"] = .number(snapshot.advanced.pppDialInEnabled ? 1 : 0)
      profile["pdUN"] = .string(normalized(snapshot.advanced.pppDialInAccount))
      profile["pdPW"] = .string(normalized(snapshot.advanced.pppDialInPassword))
      profile["pdAR"] = .number(Double(snapshot.advanced.pppDialInAnswerOnRing))
      profile["pdID"] = .number(Double(snapshot.advanced.pppDialInIdleSeconds))
      profile["pdMC"] = .number(Double(snapshot.advanced.pppDialInMaximumConnectSeconds))
    }

    if capabilities.supportsBaseStationMetadata {
      profile["syCt"] = .string(normalized(snapshot.legacyDeviceOptions.baseStation.contact))
      profile["syLo"] = .string(normalized(snapshot.legacyDeviceOptions.baseStation.location))
    }
    profile["ntSV"] = .string(
      snapshot.legacyDeviceOptions.baseStation.setTimeAutomatically
        ? normalized(snapshot.legacyDeviceOptions.baseStation.timeServer) : "")
    if capabilities.supportsLegacyWirelessOptions {
      profile["raMu"] = .number(
        Double(snapshot.legacyDeviceOptions.wireless.multicastRate))
      profile["raPo"] = .number(
        Double(snapshot.legacyDeviceOptions.wireless.transmitPower))
      profile["raKT"] = .number(
        Double(snapshot.legacyDeviceOptions.wireless.groupKeyTimeoutSeconds))
      profile["raRo"] = .bool(
        snapshot.legacyDeviceOptions.wireless.interferenceRobustness)
    }
    if capabilities.supportsLegacyDHCPOptions {
      profile["dhMg"] = .string(normalized(snapshot.legacyDeviceOptions.dhcp.message))
      profile["dh95"] = .string(normalized(snapshot.legacyDeviceOptions.dhcp.ldapServer))
    }
    if capabilities.supportsAccessControl {
      let access = snapshot.legacyDeviceOptions.accessControl
      profile["acEn"] = .bool(access.mode == "local")
      profile["raFl"] = .number(access.mode == "radius" ? 1 : 0)
      profile["acTa"] = bytesValue(accessControlTableData(access.entries))
      profile["raCi"] = .bool(access.radiusType == "alternate")
      profile["raI1"] = .string(normalized(access.primaryAddress, default: "0.0.0.0"))
      profile["raSe"] = .string(normalized(access.primarySecret))
      profile["raAu"] = .number(Double(access.primaryPort))
      let secondaryEnabled = !normalized(access.secondaryAddress).isEmpty
      profile["raF2"] = .number(secondaryEnabled ? 1 : 0)
      profile["raI2"] = .string(
        normalized(access.secondaryAddress, default: "0.0.0.0"))
      profile["raS2"] = .string(normalized(access.secondarySecret))
      profile["raU2"] = .number(Double(secondaryEnabled ? access.secondaryPort : 0))
    }

    profile["raWB"] = .bool(snapshot.baseStation.allowSetupOverWAN)
    profile["bsRM"] = .number(Double(routerModeValue(snapshot.network.routerMode)))
    profile["bsFS"] = .number(snapshot.disks.fileSharing ? 1 : 0)
    profile["bsRF"] = .number(snapshot.disks.shareOverWAN ? 1 : 0)
    profile["bsFM"] = .number(Double(diskSecurityValue(snapshot.disks.secureSharedDisks)))
    profile["bsGA"] = .number(Double(guestDiskAccessValue(snapshot.disks.guestAccess)))

    profile["auRR"] = .bool(snapshot.airPlay.enabled)
    profile["auNN"] = .string(normalized(snapshot.airPlay.speakerName))
    profile["auNP"] = .string(normalized(snapshot.airPlay.speakerPassword))
    profile["aWan"] = .bool(snapshot.airPlay.overWAN)

    profile["WiFi"] = .object([
      "radios": .array([.object(radioProfile(from: snapshot.wireless))])
    ])

    return profile
  }

  private static func radioProfile(from wireless: WirelessState) -> [String: JSONValue] {
    let mode = wirelessModeValue(wireless.mode)
    let security = wirelessSecurityValue(wireless.security)
    let password = mode == 3 || security == 1 ? "" : normalized(wireless.password)
    return [
      "raCh": .number(Double(radioChannelValue(wireless.radioChannel))),
      "raCl": .bool(wireless.hiddenNetwork),
      "raCr": bytesValue(Data(password.utf8)),
      "raMd": .number(Double(radioModeValue(wireless.radioMode))),
      "raNm": .string(mode == 3 ? "" : normalized(wireless.networkName)),
      "raSt": .number(Double(mode)),
      "raWE": bytesValue(Data()),
      "raWM": .number(Double(security)),
    ]
  }

  private static func bytesValue(_ data: Data) -> JSONValue {
    var object: [String: JSONValue] = [
      "hex": .string(data.airportHexString),
      "length": .number(Double(data.count)),
      "type": .string("bytes"),
    ]
    if let text = data.airportPrintableText {
      object["text"] = .string(text)
    }
    return .object(object)
  }

  private static func accessControlTableData(_ entries: [AccessControlEntry]) -> Data {
    let records = entries.compactMap { entry -> Data? in
      let bytes = entry.macAddress
        .split(separator: ":")
        .compactMap { UInt8($0, radix: 16) }
      guard bytes.count == 6 else { return nil }
      let description = Data(entry.description.utf8.prefix(34))
      var record = Data(bytes)
      record.append(description)
      record.append(Data(repeating: 0, count: 34 - description.count))
      return record
    }
    var data = Data(repeating: 0, count: 8)
    let count = UInt64(records.count)
    for shift in stride(from: 56, through: 0, by: -8) {
      data.append(UInt8((count >> UInt64(shift)) & 0xff))
    }
    records.forEach { data.append($0) }
    return data
  }

  private static func connectUsingValue(_ value: ConnectUsing) -> Int {
    switch value {
    case .dhcp: return 0x8300
    case .static: return 0x8400
    case .pppoe: return 0x8900
    case .modem: return 0x0900
    }
  }

  private static func pppoeConnectionValues(_ value: String) -> (active: Bool, stayConnected: Bool)
  {
    switch normalized(value) {
    case "automatic": return (true, false)
    case "manual": return (false, false)
    default: return (true, true)
    }
  }

  private static func ipv6ConfigurationValues(_ value: String, mode: String) -> (
    mode: Int, automatic: Bool
  ) {
    let configurationMode: Int
    switch normalized(mode) {
    case "host": configurationMode = 1
    case "tunnel": configurationMode = 3
    case "router": configurationMode = 5
    default: configurationMode = 1
    }

    switch normalized(value) {
    case "automatic": return (configurationMode, true)
    case "manual": return (configurationMode, false)
    default: return (0, false)
    }
  }

  private static func wirelessModeValue(_ value: String) -> Int {
    switch normalized(value) {
    case "join": return 1
    case "wds": return 10
    case "extend": return 20
    case "off": return 3
    default: return 0
    }
  }

  private static func wirelessSecurityValue(_ value: String) -> Int {
    switch normalized(value) {
    case "wep-40": return 2
    case "wep-128": return 3
    case "wpa-personal": return 4
    case "wpa-wpa2-personal": return 5
    case "wpa2-personal": return 7
    case "wpa-enterprise": return 9
    case "wpa-wpa2-enterprise": return 10
    case "wpa2-enterprise": return 12
    default: return 1
    }
  }

  private static func radioModeValue(_ value: String) -> Int {
    switch normalized(value) {
    case "80211b": return 1
    case "80211bg": return 2
    case "80211g": return 3
    case "80211a": return 4
    case "80211n-a": return 5
    case "80211n-only-24": return 7
    case "80211n-only-5": return 8
    default: return 6
    }
  }

  private static func radioChannelValue(_ value: String) -> Int {
    let trimmed = normalized(value)
    if trimmed == "automatic" || trimmed.isEmpty { return 1000 }
    return Int(trimmed) ?? 1000
  }

  private static func routerModeValue(_ value: RouterMode) -> Int {
    switch value {
    case .dhcpAndNat: return 0
    case .dhcpOnly: return 1
    case .natOnly: return 2
    case .bridge: return 3
    }
  }

  private static func diskSecurityValue(_ value: String) -> Int {
    switch normalized(value) {
    case "accounts": return 0
    case "disk-password": return 1
    default: return 2
    }
  }

  private static func guestDiskAccessValue(_ value: String) -> Int {
    switch normalized(value) {
    case "read-only": return 1
    case "read-write": return 2
    default: return 0
    }
  }

  private static func dhcpLeaseSeconds(_ network: NetworkState) -> Int {
    let value = Int(normalized(network.dhcpLease)) ?? 1
    let multiplier: Int
    switch normalized(network.dhcpLeaseUnit) {
    case "week", "weeks": multiplier = 604_800
    case "day", "days": multiplier = 86_400
    case "hour", "hours": multiplier = 3_600
    case "minute", "minutes": multiplier = 60
    default: multiplier = 1
    }
    return max(1, value) * multiplier
  }

  private static func splitList(_ text: String, fillingWith fallback: String, count: Int)
    -> [String]
  {
    var values =
      text
      .split(separator: ",")
      .map { normalized(String($0)) }
      .filter { !$0.isEmpty }
    while values.count < count {
      values.append(fallback)
    }
    return Array(values.prefix(count))
  }

  private static func normalized(_ text: String, default defaultValue: String = "") -> String {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? defaultValue : trimmed
  }
}

enum PropertyListJSONValueConverter {
  static func jsonValue(from value: Any) -> JSONValue {
    switch value {
    case let string as String:
      return .string(string)
    case let data as Data:
      return bytesValue(data)
    case let bool as Bool:
      return .bool(bool)
    case let number as NSNumber:
      if CFGetTypeID(number) == CFBooleanGetTypeID() {
        return .bool(number.boolValue)
      }
      return .number(number.doubleValue)
    case let array as [Any]:
      return .array(array.map(jsonValue(from:)))
    case let dictionary as [String: Any]:
      var object: [String: JSONValue] = [:]
      for (key, item) in dictionary {
        object[key] = jsonValue(from: item)
      }
      return .object(object)
    default:
      return .string(String(describing: value))
    }
  }

  static func propertyListValue(_ value: JSONValue) throws -> Any {
    switch value {
    case .string(let string):
      return string
    case .number(let number):
      if number.isFinite, number.rounded() == number,
        number >= Double(Int.min), number <= Double(Int.max)
      {
        return Int(number)
      }
      return number
    case .bool(let bool):
      return bool
    case .array(let array):
      return try array.map(propertyListValue(_:))
    case .object(let object):
      if isBytesObject(object) {
        guard let data = data(fromBytesObject: object) else {
          throw AirportBaseConfigurationFileError.unsupportedCFB0Value("invalid byte object")
        }
        return data
      }
      var dictionary: [String: Any] = [:]
      for key in object.keys.sorted() {
        dictionary[key] = try propertyListValue(object[key] ?? .null)
      }
      return dictionary
    case .null:
      return ""
    }
  }

  static func data(fromBytesObject object: [String: JSONValue]) -> Data? {
    if case .string(let hex)? = object["hex"],
      let data = Data(airportHexString: hex),
      lengthMatches(data, object: object)
    {
      return data
    }
    if case .string(let text)? = object["text"] {
      let data = Data(text.utf8)
      return lengthMatches(data, object: object) ? data : nil
    }
    return nil
  }

  private static func bytesValue(_ data: Data) -> JSONValue {
    var object: [String: JSONValue] = [
      "hex": .string(data.airportHexString),
      "length": .number(Double(data.count)),
      "type": .string("bytes"),
    ]
    if let text = data.airportPrintableText {
      object["text"] = .string(text)
    }
    return .object(object)
  }

  private static func isBytesObject(_ object: [String: JSONValue]) -> Bool {
    if case .string(let type)? = object["type"], type == "bytes" {
      return true
    }
    return false
  }

  private static func lengthMatches(_ data: Data, object: [String: JSONValue]) -> Bool {
    guard case .number(let length)? = object["length"] else { return true }
    return Int(length) == data.count
  }
}

enum CFB0ProfileCodec {
  static func decode(_ data: Data) throws -> JSONValue {
    guard data.starts(with: Data("CFB0".utf8)) else {
      throw AirportBaseConfigurationFileError.invalidCFB0("missing CFB0 magic")
    }
    var reader = Reader(data: data.dropFirst(4))
    let value = try reader.readValue()
    guard try reader.read(count: 4) == Array("END!".utf8) else {
      throw AirportBaseConfigurationFileError.invalidCFB0("missing END trailer")
    }
    guard reader.isAtEnd else {
      throw AirportBaseConfigurationFileError.invalidCFB0("trailing data")
    }
    return value
  }

  static func encode(_ value: JSONValue) throws -> Data {
    var data = Data("CFB0".utf8)
    try appendValue(value, to: &data)
    data.append(Data("END!".utf8))
    return data
  }

  private static func appendValue(_ value: JSONValue, to data: inout Data) throws {
    switch value {
    case .bool(let bool):
      data.append(contentsOf: [bool ? 0x09 : 0x08])
    case .string(let string):
      appendCString(string, marker: 0x70, to: &data)
    case .number(let number):
      guard number.isFinite, number.rounded() == number, number >= 0 else {
        throw AirportBaseConfigurationFileError.unsupportedCFB0Value("non-integer number")
      }
      try appendInteger(UInt64(number), to: &data)
    case .array(let values):
      data.append(contentsOf: [0xA0])
      for value in values {
        try appendValue(value, to: &data)
      }
      data.append(contentsOf: [0x00])
    case .object(let object):
      if isBytesObject(object) {
        guard let bytes = PropertyListJSONValueConverter.data(fromBytesObject: object) else {
          throw AirportBaseConfigurationFileError.unsupportedCFB0Value("invalid byte object")
        }
        try appendBlob(bytes, to: &data)
        return
      }
      data.append(contentsOf: [0xD0])
      for key in object.keys.sorted() {
        appendCString(key, marker: 0x70, to: &data)
        try appendValue(object[key] ?? .null, to: &data)
      }
      data.append(contentsOf: [0x00])
    case .null:
      throw AirportBaseConfigurationFileError.unsupportedCFB0Value("null")
    }
  }

  private static func appendCString(_ string: String, marker: UInt8, to data: inout Data) {
    data.append(contentsOf: [marker])
    data.append(Data(string.utf8))
    data.append(contentsOf: [0x00])
  }

  private static func appendInteger(_ value: UInt64, to data: inout Data) throws {
    if value <= 0xFF {
      data.append(contentsOf: [0x10, UInt8(value)])
    } else if value <= 0xFFFF {
      data.append(contentsOf: [0x11])
      appendBigEndian(value, byteCount: 2, to: &data)
    } else if value <= 0xFFFF_FFFF {
      data.append(contentsOf: [0x12])
      appendBigEndian(value, byteCount: 4, to: &data)
    } else {
      data.append(contentsOf: [0x13])
      appendBigEndian(value, byteCount: 8, to: &data)
    }
  }

  private static func appendBlob(_ bytes: Data, to data: inout Data) throws {
    if bytes.count < 0x0F {
      data.append(contentsOf: [0x40 | UInt8(bytes.count)])
      data.append(bytes)
    } else if bytes.count <= 0xFF {
      data.append(contentsOf: [0x4F, 0x10, UInt8(bytes.count)])
      data.append(bytes)
    } else if bytes.count <= 0xFFFF {
      data.append(contentsOf: [0x4F, 0x11])
      appendBigEndian(UInt64(bytes.count), byteCount: 2, to: &data)
      data.append(bytes)
    } else {
      data.append(contentsOf: [0x4F, 0x12])
      appendBigEndian(UInt64(bytes.count), byteCount: 4, to: &data)
      data.append(bytes)
    }
  }

  private static func appendBigEndian(_ value: UInt64, byteCount: Int, to data: inout Data) {
    for shift in stride(from: (byteCount - 1) * 8, through: 0, by: -8) {
      data.append(contentsOf: [UInt8((value >> UInt64(shift)) & 0xFF)])
    }
  }

  private static func isBytesObject(_ object: [String: JSONValue]) -> Bool {
    if case .string(let type)? = object["type"], type == "bytes" {
      return true
    }
    return false
  }

  private struct Reader {
    private let bytes: [UInt8]
    private var offset = 0

    init(data: Data.SubSequence) {
      self.bytes = Array(data)
    }

    var isAtEnd: Bool { offset == bytes.count }

    mutating func read(count: Int) throws -> [UInt8] {
      guard offset + count <= bytes.count else {
        throw AirportBaseConfigurationFileError.invalidCFB0("truncated data")
      }
      let value = Array(bytes[offset..<offset + count])
      offset += count
      return value
    }

    mutating func readByte() throws -> UInt8 {
      try read(count: 1)[0]
    }

    mutating func readCString() throws -> String {
      guard let end = bytes[offset...].firstIndex(of: 0) else {
        throw AirportBaseConfigurationFileError.invalidCFB0("unterminated string")
      }
      let data = Data(bytes[offset..<end])
      offset = end + 1
      guard let string = String(data: data, encoding: .utf8) else {
        throw AirportBaseConfigurationFileError.invalidCFB0("invalid UTF-8 string")
      }
      return string
    }

    mutating func readValue() throws -> JSONValue {
      let marker = try readByte()
      switch marker {
      case 0x08:
        return .bool(false)
      case 0x09:
        return .bool(true)
      case 0x10:
        return .number(Double(try readUnsignedInteger(byteCount: 1)))
      case 0x11:
        return .number(Double(try readUnsignedInteger(byteCount: 2)))
      case 0x12:
        return .number(Double(try readUnsignedInteger(byteCount: 4)))
      case 0x13:
        let value = try readUnsignedInteger(byteCount: 8)
        if value <= UInt64(Int64.max) {
          return .number(Double(value))
        }
        return .string(String(value))
      case 0x40...0x4E:
        return try readByteBlob(length: Int(marker & 0x0F))
      case 0x4F:
        return try readByteBlob(length: readBlobLength())
      case 0x70:
        return .string(try readCString())
      case 0xA0:
        return try readArray()
      case 0xD0:
        return try readDictionary()
      default:
        throw AirportBaseConfigurationFileError.invalidCFB0(
          String(format: "unsupported marker 0x%02x", marker))
      }
    }

    private mutating func readArray() throws -> JSONValue {
      var values: [JSONValue] = []
      while true {
        guard offset < bytes.count else {
          throw AirportBaseConfigurationFileError.invalidCFB0("unterminated array")
        }
        if bytes[offset] == 0 {
          offset += 1
          return .array(values)
        }
        values.append(try readValue())
      }
    }

    private mutating func readDictionary() throws -> JSONValue {
      var object: [String: JSONValue] = [:]
      while true {
        guard offset < bytes.count else {
          throw AirportBaseConfigurationFileError.invalidCFB0("unterminated dictionary")
        }
        if bytes[offset] == 0 {
          offset += 1
          return .object(object)
        }
        guard try readByte() == 0x70 else {
          throw AirportBaseConfigurationFileError.invalidCFB0("expected dictionary key")
        }
        object[try readCString()] = try readValue()
      }
    }

    private mutating func readBlobLength() throws -> Int {
      let marker = try readByte()
      let byteCount: Int
      switch marker {
      case 0x10: byteCount = 1
      case 0x11: byteCount = 2
      case 0x12: byteCount = 4
      case 0x13: byteCount = 8
      default:
        throw AirportBaseConfigurationFileError.invalidCFB0(
          String(format: "unsupported blob length marker 0x%02x", marker))
      }
      let value = try readUnsignedInteger(byteCount: byteCount)
      guard value <= UInt64(Int.max) else {
        throw AirportBaseConfigurationFileError.invalidCFB0("oversized blob")
      }
      return Int(value)
    }

    private mutating func readByteBlob(length: Int) throws -> JSONValue {
      let data = Data(try read(count: length))
      var object: [String: JSONValue] = [
        "hex": .string(data.airportHexString),
        "length": .number(Double(data.count)),
        "type": .string("bytes"),
      ]
      if let text = data.airportPrintableText {
        object["text"] = .string(text)
      }
      return .object(object)
    }

    private mutating func readUnsignedInteger(byteCount: Int) throws -> UInt64 {
      var value: UInt64 = 0
      for byte in try read(count: byteCount) {
        value = (value << 8) | UInt64(byte)
      }
      return value
    }
  }
}

extension Data {
  fileprivate init?(airportHexString hex: String) {
    let trimmed = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count.isMultiple(of: 2) else { return nil }
    var data = Data()
    var index = trimmed.startIndex
    while index < trimmed.endIndex {
      let next = trimmed.index(index, offsetBy: 2)
      guard let byte = UInt8(trimmed[index..<next], radix: 16) else { return nil }
      data.append(contentsOf: [byte])
      index = next
    }
    self = data
  }

  fileprivate var airportHexString: String {
    map { String(format: "%02x", $0) }.joined()
  }

  fileprivate var airportPrintableText: String? {
    var stripped = self
    while stripped.last == 0 {
      stripped.removeLast()
    }
    guard !stripped.isEmpty, let text = String(data: stripped, encoding: .utf8),
      text.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
    else {
      return nil
    }
    return text
  }
}
