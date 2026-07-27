import Darwin
import Foundation

enum AirportValueNormalizer {
  static func text(_ value: String) -> String {
    value.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  static func splitList(_ text: String) -> [String] {
    text
      .split { $0 == "," || $0 == " " || $0 == "\n" || $0 == "\t" }
      .map(String.init)
  }

  static func normalizedList(
    _ text: String,
    normalizer: (String) -> String = { $0 }
  ) -> String {
    splitList(text).map(normalizer).joined(separator: ",")
  }

  static func containsEmptyCommaSeparatedValue(_ text: String) -> Bool {
    guard text.contains(",") else { return false }
    return text
      .split(separator: ",", omittingEmptySubsequences: false)
      .contains { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
  }

  static func isIPv4Address(_ value: String) -> Bool {
    let parts = text(value).split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return false }
    return parts.allSatisfy(isIPv4Octet)
  }

  static func isSubnetMask(_ value: String) -> Bool {
    subnetMaskValidationError(value) == nil
  }

  static func subnetMaskValidationError(_ value: String) -> String? {
    let parts = text(value).split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return "Subnet Mask must contain contiguous one bits." }
    var mask: UInt32 = 0
    for part in parts {
      guard isIPv4Octet(part), let octet = UInt8(part) else {
        return "Subnet Mask must contain contiguous one bits."
      }
      mask = (mask << 8) | UInt32(octet)
    }
    var seenZero = false
    for bitIndex in stride(from: 31, through: 0, by: -1) {
      let bitIsSet = (mask & (UInt32(1) << UInt32(bitIndex))) != 0
      if seenZero && bitIsSet {
        return "Subnet Mask must contain contiguous one bits."
      }
      if !bitIsSet {
        seenZero = true
      }
    }
    guard mask != 0 && mask != UInt32.max else {
      return "Subnet Mask must be between 255.0.0.0 and 255.255.255.254."
    }
    return nil
  }

  static func isIPv6Address(_ value: String) -> Bool {
    var address = in6_addr()
    return text(value).withCString { pointer in
      inet_pton(AF_INET6, pointer, &address) == 1
    }
  }

  static func normalizedIPv6Address(_ value: String) -> String {
    let text = text(value)
    guard !text.isEmpty else { return "" }
    var address = in6_addr()
    guard text.withCString({ inet_pton(AF_INET6, $0, &address) == 1 }) else { return text }
    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    var canonicalAddress = address
    guard inet_ntop(AF_INET6, &canonicalAddress, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil
    else {
      return text
    }
    return buffer.withUnsafeBufferPointer { pointer in
      guard let baseAddress = pointer.baseAddress else { return text }
      return String(validatingCString: baseAddress) ?? text
    }
  }

  static func isPositiveInteger(_ value: String) -> Bool {
    let text = text(value)
    guard !text.isEmpty, text.allSatisfy(\.isNumber), let number = Int(text) else {
      return false
    }
    return number > 0
  }

  static func normalizedDHCPLeaseValue(_ value: String) -> String {
    let text = text(value)
    guard let number = Int(text) else { return text }
    return String(number)
  }

  static func normalizedDHCPLeaseUnit(_ value: String) -> String {
    switch text(value) {
    case "second", "seconds":
      return "seconds"
    case "minute", "minutes":
      return "minutes"
    case "hour", "hours":
      return "hours"
    case "day", "days":
      return "days"
    case "week", "weeks":
      return "weeks"
    default:
      return text(value)
    }
  }

  static func isSupportedDHCPLeaseDuration(value: String, unit: String) -> Bool {
    guard let leaseValue = Int(normalizedDHCPLeaseValue(value)),
      let secondsPerUnit = dhcpLeaseSecondsPerUnit(unit)
    else {
      return false
    }
    let duration = leaseValue.multipliedReportingOverflow(by: secondsPerUnit)
    guard !duration.overflow else { return false }
    return (1...(10 * 365 * 86_400)).contains(duration.partialValue)
  }

  static func normalizedIntegerText(_ value: String) -> String {
    let text = text(value)
    guard let number = Int(text) else { return text }
    return String(number)
  }

  static func normalizedRadioChannel(_ value: String) -> String {
    let text = text(value)
    guard text != "automatic" else { return text }
    return normalizedIntegerText(text)
  }

  private static func dhcpLeaseSecondsPerUnit(_ unit: String) -> Int? {
    switch normalizedDHCPLeaseUnit(unit) {
    case "seconds": return 1
    case "minutes": return 60
    case "hours": return 3_600
    case "days": return 86_400
    case "weeks": return 604_800
    default: return nil
    }
  }

  private static func isIPv4Octet(_ part: Substring) -> Bool {
    !part.isEmpty && part.allSatisfy(\.isNumber) && (part.count == 1 || part.first != "0")
      && UInt8(part) != nil
  }
}
