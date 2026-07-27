import Foundation

// Normalizes settings for dirty-state comparison without changing the editable model state.
enum AirportSettingsComparable {
  static func snapshot(
    _ snapshot: AirportSettingsSnapshot,
    capabilitiesAreKnown: Bool,
    supportsAirPlay: Bool,
    supportsDisks: Bool,
    supportsLogging: Bool,
    supportsPPPDialIn: Bool,
    supportsBaseStationMetadata: Bool,
    supportsLegacyWirelessOptions: Bool,
    supportsLegacyDHCPOptions: Bool,
    supportsAccessControl: Bool,
    showsIPv6InternetControls: Bool,
    showsDynamicGlobalHostnameControls: Bool
  ) -> AirportSettingsSnapshot {
    var comparable = AirportSettingsSnapshot(
      baseStation: baseStation(snapshot.baseStation),
      internet: internet(snapshot.internet),
      wireless: wireless(snapshot.wireless),
      network: network(snapshot.network),
      airPlay: airPlay(snapshot.airPlay),
      disks: disks(snapshot.disks),
      advanced: advanced(snapshot.advanced),
      legacyDeviceOptions: legacyDeviceOptions(snapshot.legacyDeviceOptions)
    )
    if capabilitiesAreKnown && !supportsAirPlay {
      comparable.airPlay = AirPlayState()
    }
    if capabilitiesAreKnown && !supportsDisks {
      comparable.disks = DisksState()
    }
    if capabilitiesAreKnown && !supportsLogging {
      comparable.advanced.syslogDestinationAddress = ""
      comparable.advanced.syslogLevel = AdvancedState().syslogLevel
      comparable.advanced.allowSNMP = AdvancedState().allowSNMP
      comparable.advanced.allowSNMPOverWAN = AdvancedState().allowSNMPOverWAN
    }
    if capabilitiesAreKnown && !supportsPPPDialIn {
      let defaults = AdvancedState()
      comparable.advanced.pppDialInEnabled = defaults.pppDialInEnabled
      comparable.advanced.pppDialInAccount = defaults.pppDialInAccount
      comparable.advanced.pppDialInPassword = defaults.pppDialInPassword
      comparable.advanced.pppDialInVerifyPassword = defaults.pppDialInVerifyPassword
      comparable.advanced.pppDialInAnswerOnRing = defaults.pppDialInAnswerOnRing
      comparable.advanced.pppDialInIdleSeconds = defaults.pppDialInIdleSeconds
      comparable.advanced.pppDialInMaximumConnectSeconds =
        defaults.pppDialInMaximumConnectSeconds
    }
    if capabilitiesAreKnown && !supportsBaseStationMetadata {
      comparable.legacyDeviceOptions.baseStation.contact = ""
      comparable.legacyDeviceOptions.baseStation.location = ""
    }
    if capabilitiesAreKnown && !supportsLegacyWirelessOptions {
      comparable.legacyDeviceOptions.wireless = LegacyWirelessOptionsState()
    }
    if capabilitiesAreKnown && !supportsLegacyDHCPOptions {
      comparable.legacyDeviceOptions.dhcp = LegacyDHCPOptionsState()
    }
    if capabilitiesAreKnown && !supportsAccessControl {
      comparable.legacyDeviceOptions.accessControl = LegacyAccessControlState()
    }
    if capabilitiesAreKnown && !showsIPv6InternetControls {
      comparable.internet.configureIPv6 = ""
      comparable.internet.ipv6DNSServers = ""
      comparable.internet.ipv6DNSServerPreview = ""
      comparable.internet.ipv6Address = ""
    }
    if capabilitiesAreKnown && !showsDynamicGlobalHostnameControls {
      comparable.internet.dynamicGlobalHostname = false
      comparable.internet.globalHostname = ""
      comparable.internet.globalHostnameUser = ""
      comparable.internet.globalHostnamePassword = ""
    }
    return comparable
  }

  static func baseStation(_ state: BaseStationState) -> BaseStationState {
    var comparable = state
    comparable.name = AirportValueNormalizer.text(comparable.name)
    comparable.serialNumber = ""
    comparable.version = ""
    comparable.productID = ""
    comparable.statusText = ""
    comparable.newAdminPassword = AirportValueNormalizer.text(comparable.newAdminPassword)
    comparable.verifyAdminPassword = comparable.newAdminPassword
    comparable.advancedACPSettingsJSON =
      AirportValueNormalizer.text(comparable.advancedACPSettingsJSON)
    comparable.rememberPassword = true
    return comparable
  }

  static func airPlay(_ state: AirPlayState) -> AirPlayState {
    var comparable = state
    if comparable.enabled {
      comparable.speakerName = AirportValueNormalizer.text(comparable.speakerName)
      comparable.speakerPassword = AirportValueNormalizer.text(comparable.speakerPassword)
      comparable.verifySpeakerPassword = comparable.speakerPassword
    } else {
      comparable.speakerName = ""
      comparable.speakerPassword = ""
      comparable.verifySpeakerPassword = ""
      comparable.overWAN = false
    }
    comparable.rememberPassword = true
    return comparable
  }

  static func internet(_ state: InternetState) -> InternetState {
    var comparable = state
    if comparable.connectUsing == .static {
      comparable.ipv4Address = AirportValueNormalizer.text(comparable.ipv4Address)
      comparable.subnetMask = AirportValueNormalizer.text(comparable.subnetMask)
      comparable.routerAddress = AirportValueNormalizer.text(comparable.routerAddress)
    } else {
      comparable.ipv4Address = ""
      comparable.subnetMask = ""
      comparable.routerAddress = ""
    }
    comparable.dnsServers = AirportValueNormalizer.normalizedList(comparable.dnsServers)
    comparable.ipv6DNSServers = AirportValueNormalizer.normalizedList(
      comparable.ipv6DNSServers,
      normalizer: AirportValueNormalizer.normalizedIPv6Address
    )
    comparable.domainName = AirportValueNormalizer.text(comparable.domainName)
    comparable.ipv6Address = AirportValueNormalizer.normalizedIPv6Address(comparable.ipv6Address)
    if comparable.connectUsing == .pppoe {
      comparable.pppoeAccount = AirportValueNormalizer.text(comparable.pppoeAccount)
      comparable.pppoePassword = AirportValueNormalizer.text(comparable.pppoePassword)
      comparable.pppoeService = AirportValueNormalizer.text(comparable.pppoeService)
      comparable.pppoeConnection = AirportValueNormalizer.text(comparable.pppoeConnection)
    } else {
      comparable.pppoeAccount = ""
      comparable.pppoePassword = ""
      comparable.pppoeService = ""
      comparable.pppoeConnection = ""
    }
    comparable.configureIPv6 = AirportValueNormalizer.text(comparable.configureIPv6)
    if comparable.dynamicGlobalHostname {
      comparable.globalHostname = AirportValueNormalizer.text(comparable.globalHostname)
      comparable.globalHostnameUser = AirportValueNormalizer.text(comparable.globalHostnameUser)
      comparable.globalHostnamePassword = AirportValueNormalizer.text(
        comparable.globalHostnamePassword)
    } else {
      comparable.globalHostname = ""
      comparable.globalHostnameUser = ""
      comparable.globalHostnamePassword = ""
    }
    comparable.dnsServerPreview = ""
    comparable.ipv6DNSServerPreview = ""
    return comparable
  }

  static func wireless(_ state: WirelessState) -> WirelessState {
    var comparable = state
    comparable.mode = AirportValueNormalizer.text(comparable.mode)
    comparable.networkName = AirportValueNormalizer.text(comparable.networkName)
    comparable.security = AirportValueNormalizer.text(comparable.security)
    if comparable.mode == "off" {
      comparable.networkName = ""
      comparable.security = ""
      comparable.password = ""
      comparable.verifyPassword = ""
      comparable.regionCode = ""
      comparable.hiddenNetwork = false
      comparable.radioMode = ""
      comparable.radioChannel = ""
      return comparable
    }
    if comparable.security == "none" {
      comparable.password = ""
    } else {
      comparable.password = AirportValueNormalizer.text(comparable.password)
    }
    comparable.verifyPassword = comparable.password
    comparable.regionCode = AirportValueNormalizer.normalizedIntegerText(comparable.regionCode)
    comparable.radioMode = AirportValueNormalizer.text(comparable.radioMode)
    comparable.radioChannel = AirportValueNormalizer.normalizedRadioChannel(
      comparable.radioChannel)
    return comparable
  }

  static func network(_ state: NetworkState) -> NetworkState {
    var comparable = state
    comparable.lanIPAddress = AirportValueNormalizer.text(comparable.lanIPAddress)
    if comparable.routerMode == .dhcpAndNat || comparable.routerMode == .dhcpOnly {
      comparable.dhcpRangeStart = AirportValueNormalizer.text(comparable.dhcpRangeStart)
      comparable.dhcpRangeEnd = AirportValueNormalizer.text(comparable.dhcpRangeEnd)
      comparable.dhcpLease = AirportValueNormalizer.normalizedDHCPLeaseValue(comparable.dhcpLease)
      comparable.dhcpLeaseUnit = AirportValueNormalizer.normalizedDHCPLeaseUnit(
        comparable.dhcpLeaseUnit)
    } else {
      comparable.dhcpRangeStart = ""
      comparable.dhcpRangeEnd = ""
      comparable.dhcpLease = ""
      comparable.dhcpLeaseUnit = ""
    }
    if comparable.routerMode == .dhcpAndNat || comparable.routerMode == .natOnly {
      comparable.defaultHost = AirportValueNormalizer.text(comparable.defaultHost)
    } else {
      comparable.natPMP = false
      comparable.defaultHost = ""
    }
    return comparable
  }

  static func disks(_ state: DisksState) -> DisksState {
    var comparable = state
    comparable.secureSharedDisks = AirportValueNormalizer.text(comparable.secureSharedDisks)
    comparable.guestAccess = AirportValueNormalizer.text(comparable.guestAccess)
    if comparable.secureSharedDisks == "disk-password" {
      comparable.diskPassword = AirportValueNormalizer.text(comparable.diskPassword)
    } else {
      comparable.diskPassword = ""
    }
    comparable.verifyDiskPassword = comparable.diskPassword
    comparable.windowsWorkgroup = AirportValueNormalizer.text(comparable.windowsWorkgroup)
    comparable.winsServer = AirportValueNormalizer.text(comparable.winsServer)
    comparable.rememberPassword = true
    comparable.inventory = []
    comparable.selectedDiskID = ""
    if comparable.secureSharedDisks == "accounts" {
      comparable.fileSharingAccounts = comparable.fileSharingAccounts.compactMap { account in
        let name = AirportValueNormalizer.text(account.name)
        guard !name.isEmpty else { return nil }
        return DiskAccount(
          id: account.id,
          name: name,
          password: AirportValueNormalizer.text(account.password),
          verifyPassword: AirportValueNormalizer.text(account.password),
          access: AirportValueNormalizer.text(account.access)
        )
      }
    } else {
      comparable.fileSharingAccounts = []
    }
    comparable.selectedFileSharingAccountID = ""
    comparable.rawInventory = ""
    comparable.didLoadInventory = false
    return comparable
  }

  static func advanced(_ state: AdvancedState) -> AdvancedState {
    var comparable = state
    comparable.syslogDestinationAddress =
      AirportValueNormalizer.text(comparable.syslogDestinationAddress)
    if comparable.syslogDestinationAddress == "0.0.0.0" {
      comparable.syslogDestinationAddress = ""
    }
    if !comparable.allowSNMP {
      comparable.allowSNMPOverWAN = false
    }
    comparable.pppDialInAccount = AirportValueNormalizer.text(comparable.pppDialInAccount)
    comparable.pppDialInPassword = AirportValueNormalizer.text(comparable.pppDialInPassword)
    comparable.pppDialInVerifyPassword = comparable.pppDialInPassword
    return comparable
  }

  static func legacyDeviceOptions(_ state: LegacyDeviceOptionsState)
    -> LegacyDeviceOptionsState
  {
    var comparable = state
    comparable.baseStation.contact = AirportValueNormalizer.text(
      comparable.baseStation.contact)
    comparable.baseStation.location = AirportValueNormalizer.text(
      comparable.baseStation.location)
    if comparable.baseStation.setTimeAutomatically {
      comparable.baseStation.timeServer = AirportValueNormalizer.text(
        comparable.baseStation.timeServer)
    } else {
      comparable.baseStation.timeServer = ""
    }
    comparable.dhcp.message = AirportValueNormalizer.text(comparable.dhcp.message)
    comparable.dhcp.ldapServer = AirportValueNormalizer.text(comparable.dhcp.ldapServer)
    comparable.accessControl.mode = AirportValueNormalizer.text(
      comparable.accessControl.mode)
    comparable.accessControl.radiusType = AirportValueNormalizer.text(
      comparable.accessControl.radiusType)
    comparable.accessControl.entries = comparable.accessControl.entries.map { entry in
      AccessControlEntry(
        id: entry.id,
        macAddress: entry.macAddress.trimmingCharacters(in: .whitespacesAndNewlines).uppercased(),
        description: AirportValueNormalizer.text(entry.description))
    }
    if comparable.accessControl.mode != "local" {
      comparable.accessControl.entries = []
    }
    if comparable.accessControl.mode == "radius" {
      comparable.accessControl.primaryAddress = AirportValueNormalizer.text(
        comparable.accessControl.primaryAddress)
      comparable.accessControl.primarySecret = AirportValueNormalizer.text(
        comparable.accessControl.primarySecret)
      comparable.accessControl.primaryVerifySecret = comparable.accessControl.primarySecret
      comparable.accessControl.secondaryAddress = AirportValueNormalizer.text(
        comparable.accessControl.secondaryAddress)
      comparable.accessControl.secondarySecret = AirportValueNormalizer.text(
        comparable.accessControl.secondarySecret)
      comparable.accessControl.secondaryVerifySecret = comparable.accessControl.secondarySecret
    } else {
      let defaults = LegacyAccessControlState()
      comparable.accessControl.radiusType = defaults.radiusType
      comparable.accessControl.primaryAddress = ""
      comparable.accessControl.primarySecret = ""
      comparable.accessControl.primaryVerifySecret = ""
      comparable.accessControl.primaryPort = defaults.primaryPort
      comparable.accessControl.secondaryAddress = ""
      comparable.accessControl.secondarySecret = ""
      comparable.accessControl.secondaryVerifySecret = ""
      comparable.accessControl.secondaryPort = defaults.secondaryPort
    }
    return comparable
  }
}
