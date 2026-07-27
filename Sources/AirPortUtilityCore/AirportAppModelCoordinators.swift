import Foundation

@MainActor
final class ConnectionSession {
  var hasTrustedConnectionPassword = false
  var cachedPasswordsByAccount: [String: CachedConnectionPassword] = [:]
}

@MainActor
final class TopologyStore {
  var selectedDeviceID: String?
  var updatingBaseStationHost: String?
  var updatingBaseStationDeviceID: String?
  var selectedDeviceIdentifiers: [String] = []
  var connectedDeviceIdentifiers: [String] = []
  var connectedDeviceHost = ""
  var updatingDeviceIdentifiers: [String] = []
  var updatingDisplaySnapshot: TopologyDeviceDisplaySnapshot?
  var displaySnapshotsByName: [String: TopologyDeviceDisplaySnapshot] = [:]
  var displaySnapshotsByIdentifier: [String: TopologyDeviceDisplaySnapshot] = [:]
  var displaySnapshotsByHost: [String: TopologyDeviceDisplaySnapshot] = [:]
  var firmwareBadgeSnapshotsByIdentifier: [String: FirmwareBadgeSnapshot] = [:]
  var pendingConnectionHost: String?
}

@MainActor
final class FirmwareCoordinator {
  var downloadService = FirmwareDownloadService()
  var installVerificationAttempts = 72
  var installVerificationDelayNanoseconds: UInt64 = 5_000_000_000
  var catalogRefreshTask: Task<Void, Never>?
  var completionMonitorTask: Task<Void, Never>?
  var uploadProgressBuffer = ""
}

@MainActor
final class ConfigurationSession {
  var cleanSnapshot = AirportSettingsSnapshot()
  var cleanCapabilities = DeviceCapabilities()
  var cleanHasDetectedIPv6Support = false
  var cleanHasDetectedDynamicGlobalHostnameSupport = false
  var cleanHasDetectedClassicWDSSupport = false
  var archiveCompletionMonitorTask: Task<Void, Never>?
}
