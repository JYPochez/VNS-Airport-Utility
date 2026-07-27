import Foundation

struct FirmwareBadgeSnapshot {
  var currentVersion: String
  var productID: String
  var images: [FirmwareImage]
}

struct TopologyDeviceDisplaySnapshot {
  var displayName: String
  var stableIdentifiers: [String]
  var connectionHosts: [String]
  var modelName: String
  var productID: String
  var rootIndex: Int?
  var expiresAt: Date?
}

struct CachedConnectionPassword {
  var password: String
  var rememberPassword: Bool
  var trusted: Bool
}
