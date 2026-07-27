import Foundation

enum FirmwareCatalogError: LocalizedError {
  case invalidManifest
  case invalidFirmwareURL(String)

  var errorDescription: String? {
    switch self {
    case .invalidManifest:
      "The Apple firmware manifest did not contain firmware updates."
    case .invalidFirmwareURL(let url):
      "The firmware manifest contained an invalid URL: \(url)"
    }
  }
}

enum FirmwareCatalog {
  static let manifestURL = catalogURL(path: "/version.xml")
  static let supportedProductIDs: Set<String> = [
    "3", "102", "104", "105", "106", "107", "108", "109", "113", "114", "115", "116",
    "117", "119", "120",
  ]

  static func images(forProductID productID: String, in data: Data) throws -> [FirmwareImage] {
    let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    guard let root = plist as? [String: Any],
      let updates = root["firmwareUpdates"] as? [[String: Any]]
    else {
      throw FirmwareCatalogError.invalidManifest
    }

    let productID = productID.trimmingCharacters(in: .whitespacesAndNewlines)
    var images: [FirmwareImage] = []
    for update in updates {
      guard String(describing: update["productID"] ?? "") == productID else { continue }
      guard let locationText = update["location"] as? String,
        let location = URL(string: locationText)
      else {
        throw FirmwareCatalogError.invalidFirmwareURL(String(describing: update["location"] ?? ""))
      }
      let version = String(describing: update["version"] ?? "")
      let sourceVersion = String(describing: update["sourceVersion"] ?? "")
      guard !version.isEmpty, !sourceVersion.isEmpty else { continue }
      let size = update["sizeInBytes"] as? Int ?? 0
      let newest = update["newest"] as? Bool ?? false
      images.append(
        FirmwareImage(
          productID: productID,
          version: version,
          sourceVersion: sourceVersion,
          location: location,
          sizeInBytes: size,
          newest: newest))
    }

    return images.sorted { lhs, rhs in
      if lhs.newest != rhs.newest { return lhs.newest && !rhs.newest }
      return lhs.version.compare(rhs.version, options: .numeric) == .orderedDescending
    }
  }

  static func mockImages(forProductID productID: String) -> [FirmwareImage] {
    [
      FirmwareImage(
        productID: productID,
        version: "7.8.1",
        sourceVersion: "78100.3",
        location: catalogURL(
          scheme: "http", path: "/data/\(productID)/mock-current/7.8.1.basebinary"),
        sizeInBytes: 6_605_988,
        newest: true),
      FirmwareImage(
        productID: productID,
        version: "7.6.9",
        sourceVersion: "76900.11",
        location: catalogURL(
          scheme: "http", path: "/data/\(productID)/mock-previous/7.6.9.basebinary"),
        sizeInBytes: 6_605_840,
        newest: false),
    ]
  }

  private static func catalogURL(scheme: String = "https", path: String) -> URL {
    var components = URLComponents()
    components.scheme = scheme
    components.host = "apsu.apple.com"
    components.path = path
    return components.url ?? URL(fileURLWithPath: "/")
  }
}
