import Foundation
import Security

protocol AirportPasswordStore {
  func password(for host: String) -> String?
  func savePassword(_ password: String, for host: String)
  func deletePassword(for host: String)
}

struct NoopAirportPasswordStore: AirportPasswordStore {
  func password(for host: String) -> String? {
    nil
  }

  func savePassword(_ password: String, for host: String) {}

  func deletePassword(for host: String) {}
}

final class KeychainAirportPasswordStore: AirportPasswordStore, @unchecked Sendable {
  static let shared = KeychainAirportPasswordStore()

  private let service = "AirPortUtility.BaseStationPassword"
  private let legacyServices = ["NewAirPortUtility.BaseStationPassword"]

  func password(for host: String) -> String? {
    let account = AirportConnection.normalizedHost(host)
    guard !account.isEmpty else { return nil }

    if let password = password(for: account, service: service) {
      return password
    }
    for legacyService in legacyServices {
      if let password = password(for: account, service: legacyService) {
        savePassword(password, for: account)
        return password
      }
    }
    return nil
  }

  private func password(for account: String, service: String) -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
      let data = item as? Data
    else {
      return nil
    }
    return String(data: data, encoding: .utf8)
  }

  func savePassword(_ password: String, for host: String) {
    let account = AirportConnection.normalizedHost(host)
    guard !account.isEmpty, let data = password.data(using: .utf8) else { return }

    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
    let update: [String: Any] = [
      kSecValueData as String: data
    ]
    let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
    guard status == errSecItemNotFound else { return }

    var item = query
    item[kSecValueData as String] = data
    SecItemAdd(item as CFDictionary, nil)
  }

  func deletePassword(for host: String) {
    let account = AirportConnection.normalizedHost(host)
    guard !account.isEmpty else { return }

    for service in [service] + legacyServices {
      let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
      ]
      SecItemDelete(query as CFDictionary)
    }
  }
}
