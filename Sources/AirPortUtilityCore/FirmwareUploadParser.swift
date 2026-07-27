import Foundation

struct FirmwareUploadCommandResult: Equatable {
  var method = ""
  var uploadHost = ""
  var progressCurrent: Int?
  var progressTotal: Int?
  var progressRaw = ""
  var progressComplete: Bool?
  var rebootSent: Bool?

  var progressText: String {
    if !progressRaw.isEmpty { return progressRaw }
    if let progressCurrent, let progressTotal {
      return "\(progressCurrent)/\(progressTotal)"
    }
    return "unknown"
  }

  var requiresRebootCommand: Bool {
    method == "property-stream"
  }
}

struct FirmwareUploadProgressEvent: Equatable {
  var phase: String
  var current: Int
  var total: Int
  var raw: String
}

enum FirmwareUploadParser {
  static func progressEvent(from line: String) -> FirmwareUploadProgressEvent? {
    let prefix = "firmware-upload progress:"
    guard let range = line.range(of: prefix) else { return nil }
    let jsonText = line[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
    guard let data = jsonText.data(using: .utf8),
      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else {
      return nil
    }
    return FirmwareUploadProgressEvent(
      phase: object["phase"] as? String ?? "upload",
      current: intValue(object["current"]) ?? 0,
      total: intValue(object["total"]) ?? 0,
      raw: object["raw"] as? String ?? "")
  }

  static func commandResult(from output: String) -> FirmwareUploadCommandResult? {
    guard let data = jsonObjectData(after: "firmware-upload result:", in: output),
      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else {
      return nil
    }

    var result = FirmwareUploadCommandResult()
    result.method = object["method"] as? String ?? ""
    result.uploadHost = object["uploadHost"] as? String ?? ""
    if let progress = object["progress"] as? [String: Any] {
      result.progressCurrent = intValue(progress["current"])
      result.progressTotal = intValue(progress["total"])
      result.progressRaw = progress["raw"] as? String ?? ""
      result.progressComplete = boolValue(progress["complete"])
    }
    if let rebootCommand = object["rebootCommand"] as? [String: Any] {
      result.rebootSent = boolValue(rebootCommand["sent"])
    }
    return result
  }

  static func statusSummary(from result: FirmwareUploadCommandResult) -> String {
    var clauses: [String] = []
    if result.progressComplete == true {
      clauses.append("Upload completed (\(result.progressText))")
    } else if result.progressComplete == false {
      clauses.append("Upload progress \(result.progressText)")
    } else {
      clauses.append("Upload accepted")
    }
    if result.rebootSent == true {
      clauses.append("restart requested")
    }
    return clauses.joined(separator: "; ") + "."
  }

  static func validateResult(_ result: FirmwareUploadCommandResult) throws {
    guard result.requiresRebootCommand else { return }
    if result.progressComplete != true {
      throw FirmwareInstallError.uploadIncomplete(result.progressText)
    }
    if result.rebootSent != true {
      throw FirmwareInstallError.rebootNotSent
    }
  }

  private static func jsonObjectData(after marker: String, in text: String) -> Data? {
    guard let markerRange = text.range(of: marker) else { return nil }
    let remainder = text[markerRange.upperBound...]
    guard let start = remainder.firstIndex(of: "{") else { return nil }

    var depth = 0
    var inString = false
    var isEscaped = false
    for index in text[start...].indices {
      let character = text[index]
      if inString {
        if isEscaped {
          isEscaped = false
        } else if character == "\\" {
          isEscaped = true
        } else if character == "\"" {
          inString = false
        }
        continue
      }

      if character == "\"" {
        inString = true
      } else if character == "{" {
        depth += 1
      } else if character == "}" {
        depth -= 1
        if depth == 0 {
          let end = text.index(after: index)
          return Data(String(text[start..<end]).utf8)
        }
      }
    }
    return nil
  }

  private static func intValue(_ value: Any?) -> Int? {
    if let value = value as? Int { return value }
    if let value = value as? NSNumber { return value.intValue }
    if let value = value as? String { return Int(value) }
    return nil
  }

  private static func boolValue(_ value: Any?) -> Bool? {
    if let value = value as? Bool { return value }
    if let value = value as? NSNumber { return value.boolValue }
    if let value = value as? String {
      switch value.lowercased() {
      case "true", "yes", "1":
        return true
      case "false", "no", "0":
        return false
      default:
        return nil
      }
    }
    return nil
  }
}
