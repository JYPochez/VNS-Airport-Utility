import Foundation

enum HostInternetReader {
  static func readAsync() async -> HostInternetState {
    await Task.detached {
      read()
    }.value
  }

  static func read() -> HostInternetState {
    hostInternetSettings(
      routeOutput: runLocalCommand("/sbin/route", arguments: ["-n", "get", "default"]),
      dnsOutput: runLocalCommand("/usr/sbin/scutil", arguments: ["--dns"]))
  }

  static func hostInternetSettings(routeOutput: String, dnsOutput: String) -> HostInternetState {
    let route = defaultRouteInfo(from: routeOutput)
    let isConnected = !route.gateway.isEmpty
    let dnsServers =
      isConnected ? hostDNSServers(from: dnsOutput, preferredInterface: route.interface) : ""
    return HostInternetState(
      connectionStatus: isConnected ? "Connected" : "Disconnected",
      routerAddress: route.gateway,
      dnsServers: dnsServers)
  }

  static func hostDNSServers(from output: String, preferredInterface: String?) -> String {
    let resolvers = dnsResolvers(from: output)
    let preferredResolvers: [DNSResolver?] = [
      resolvers.first {
        $0.isScoped && $0.interface == preferredInterface && !$0.nameservers.isEmpty
      },
      resolvers.first {
        $0.interface == preferredInterface && !$0.isSupplemental && !$0.nameservers.isEmpty
      },
      resolvers.first { !$0.isSupplemental && !$0.nameservers.isEmpty },
      resolvers.first { !$0.nameservers.isEmpty },
    ]
    let nameservers = preferredResolvers.compactMap { $0 }.first?.nameservers ?? []
    return uniqueNonEmptyValues(nameservers).joined(separator: ", ")
  }

  private static func defaultRouteInfo(from output: String) -> (
    gateway: String, interface: String?
  ) {
    var gateway = ""
    var interface: String?
    for line in output.split(whereSeparator: \.isNewline) {
      let parts = line.split(separator: ":", maxSplits: 1).map {
        $0.trimmingCharacters(in: .whitespacesAndNewlines)
      }
      guard parts.count == 2 else { continue }
      if parts[0] == "gateway" {
        gateway = parts[1]
      } else if parts[0] == "interface" {
        interface = parts[1]
      }
    }
    return (gateway, interface)
  }

  private struct DNSResolver {
    var isScoped = false
    var isSupplemental = false
    var interface: String?
    var nameservers: [String] = []
  }

  private static func dnsResolvers(from output: String) -> [DNSResolver] {
    var resolvers: [DNSResolver] = []
    var current: DNSResolver?
    var isScopedSection = false

    func finishCurrentResolver() {
      guard let resolver = current else { return }
      resolvers.append(resolver)
      current = nil
    }

    for rawLine in output.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
      let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
      if line == "DNS configuration (for scoped queries)" {
        finishCurrentResolver()
        isScopedSection = true
        continue
      }
      if line.hasPrefix("resolver #") {
        finishCurrentResolver()
        current = DNSResolver(isScoped: isScopedSection)
        continue
      }
      guard current != nil else { continue }
      if line.hasPrefix("nameserver["),
        let value = valueAfterColon(in: line)
      {
        current?.nameservers.append(value)
      } else if line.hasPrefix("if_index"),
        let interface = interfaceName(fromIfIndexLine: line)
      {
        current?.interface = interface
      } else if line.hasPrefix("flags"), line.contains("Supplemental") {
        current?.isSupplemental = true
      }
    }
    finishCurrentResolver()
    return resolvers
  }

  private static func valueAfterColon(in line: String) -> String? {
    guard let colon = line.firstIndex(of: ":") else { return nil }
    let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespacesAndNewlines)
    return value.isEmpty ? nil : value
  }

  private static func interfaceName(fromIfIndexLine line: String) -> String? {
    guard let open = line.lastIndex(of: "("), let close = line.lastIndex(of: ")"), open < close
    else {
      return nil
    }
    let name = line[line.index(after: open)..<close].trimmingCharacters(in: .whitespacesAndNewlines)
    return name.isEmpty ? nil : name
  }

  private static func uniqueNonEmptyValues(_ values: [String]) -> [String] {
    var seen: Set<String> = []
    var unique: [String] = []
    for value in values {
      let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !trimmed.isEmpty, !seen.contains(trimmed) else { continue }
      seen.insert(trimmed)
      unique.append(trimmed)
    }
    return unique
  }

  private static func runLocalCommand(_ executable: String, arguments: [String]) -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let output = Pipe()
    process.standardOutput = output
    process.standardError = Pipe()
    do {
      try process.run()
      let data = output.fileHandleForReading.readDataToEndOfFile()
      process.waitUntilExit()
      return String(data: data, encoding: .utf8) ?? ""
    } catch {
      return ""
    }
  }
}
