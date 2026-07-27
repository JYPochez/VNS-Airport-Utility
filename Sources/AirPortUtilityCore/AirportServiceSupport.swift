import Foundation

struct LiveInternetSettings {
  var connectUsing: ConnectUsing?
  var dnsServers: [String?]?
  var ipv6DNSServers: [String?]?
  var domainName: String?
  var pppoeAccount: String?
  var pppoePassword: String?
  var pppoeService: String?
  var pppoeConnection: String?
  var configureIPv6: String?
  var ipv6Mode: String?
  var ipv6DefaultRoute: String?
  var ipv6Firewall: Bool?
  var dynamicGlobalHostname: Bool?
  var dynamicGlobalHostnameAutoConfig: Bool?
  var globalHostname: String?
  var globalHostnameUser: String?
  var globalHostnamePassword: String?
  var modemPhoneNumber: String?
  var modemAlternateNumber: String?
  var modemAccount: String?
  var modemPassword: String?
  var modemIdleSeconds: Int?
  var modemCountryCode: Int?
  var modemProtocol: String?
  var modemPulseDialing: Bool?
  var modemAutomaticallyDial: Bool?
  var modemIgnoreDialTone: Bool?
  var modemUseAOL: Bool?
}

struct LiveAirPlaySettings {
  var enabled: Bool?
  var speakerName: String?
  var speakerPassword: String?
  var overWAN: Bool?
}

struct AirportSettingsBatch {
  var rawOutput: String
  var value: JSONValue

  var reader: ProfileReader {
    ProfileReader(value)
  }
}
