import Foundation

private struct WirelessClientResponse: Decodable {
  var clients: [WirelessClient]
}

@MainActor
extension AirportAppModel {
  func devicePopoverPresentationDidChange() {
    if isDevicePopoverPresented {
      if mockMode {
        hasLoadedWirelessClients = true
      } else {
        restartWirelessClientPollingIfPossible()
      }
    } else {
      stopWirelessClientPolling(clearClients: true)
    }
  }

  func selectedDeviceForWirelessClientsDidChange() {
    stopWirelessClientPolling(clearClients: true)
  }

  func restartWirelessClientPollingIfPossible() {
    guard isDevicePopoverPresented else { return }
    guard !mockMode else { return }
    guard hasLoadedSettings, liveCredentialsAvailable, selectedTopologyDevice() != nil else {
      return
    }
    if usesLegacyACP {
      guard advanced.allowSNMP else {
        stopWirelessClientPolling(clearClients: true)
        hasLoadedWirelessClients = true
        return
      }
      guard !legacySNMPCommunity.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      else {
        stopWirelessClientPolling(clearClients: true)
        hasLoadedWirelessClients = true
        return
      }
    }

    stopWirelessClientPolling(clearClients: false)
    hasLoadedWirelessClients = false
    let generation = UUID()
    wirelessClientPollGeneration = generation
    let requestConnection = connection
    let requestHost = AirportConnection.normalizedHost(requestConnection.host)
    let requestDeviceID = selectedTopologyDeviceID
    let requestUsesLegacyACP = usesLegacyACP
    let requestSNMPCommunity = legacySNMPCommunity
    let interval = wirelessClientPollIntervalNanoseconds

    wirelessClientPollTask = Task { [weak self] in
      guard let self else { return }
      while !Task.isCancelled {
        do {
          let clients: [WirelessClient]
          if let fetch = wirelessClientFetchOverride {
            clients = try await fetch(
              requestConnection, requestUsesLegacyACP, requestSNMPCommunity)
          } else {
            clients = try await readWirelessClients(
              connection: requestConnection,
              usesLegacyACP: requestUsesLegacyACP,
              snmpCommunity: requestSNMPCommunity)
          }
          guard wirelessClientPollStillMatches(
            generation: generation,
            host: requestHost,
            deviceID: requestDeviceID)
          else { return }
          wirelessClients = clients.filter { !$0.displayName.isEmpty }
          hasLoadedWirelessClients = true
          lastWirelessClientError = ""
        } catch is CancellationError {
          return
        } catch {
          guard wirelessClientPollStillMatches(
            generation: generation,
            host: requestHost,
            deviceID: requestDeviceID)
          else { return }
          // Wireless clients are optional popover enrichment. Once the first
          // attempt finishes, show the normal device details even if it
          // failed, and let the polling loop retry in the background.
          hasLoadedWirelessClients = true
          let description = Self.userFacingErrorDescription(error.localizedDescription)
          if description != lastWirelessClientError {
            appendLog("Wireless client refresh failed: \(description)")
            lastWirelessClientError = description
          }
        }

        do {
          try await Task.sleep(nanoseconds: interval)
        } catch {
          return
        }
      }
    }
  }

  func stopWirelessClientPolling(clearClients: Bool) {
    wirelessClientPollGeneration = UUID()
    wirelessClientPollTask?.cancel()
    wirelessClientPollTask = nil
    lastWirelessClientError = ""
    if clearClients {
      wirelessClients = []
      hasLoadedWirelessClients = false
    }
  }

  private func wirelessClientPollStillMatches(
    generation: UUID,
    host: String,
    deviceID: String?
  ) -> Bool {
    !Task.isCancelled
      && wirelessClientPollGeneration == generation
      && isDevicePopoverPresented
      && selectedTopologyDeviceID == deviceID
      && AirportConnection.normalizedHost(connection.host) == host
  }

  private func readWirelessClients(
    connection: AirportConnection,
    usesLegacyACP: Bool,
    snmpCommunity: String
  ) async throws -> [WirelessClient] {
    let result = try await runner.run(
      script: AirportCommand.backendScript,
      arguments: AirportCommand.wirelessClients(
        connection: connection,
        usesLegacyACP: usesLegacyACP,
        snmpCommunity: snmpCommunity),
      connection: connection,
      timeout: 15)
    return try JSONDecoder().decode(
      WirelessClientResponse.self, from: Data(result.stdout.utf8)
    ).clients
  }
}
