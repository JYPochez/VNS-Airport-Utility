import Foundation

struct BackendFlag: Equatable, Sendable {
  var name: String
  var value: String?

  init(_ name: String, _ value: String? = nil) {
    self.name = name
    self.value = value
  }

  init(_ pair: (String, String?)) {
    self.init(pair.0, pair.1)
  }

  var arguments: [String] {
    if let value {
      return [name, value]
    }
    return [name]
  }
}

extension Sequence where Element == BackendFlag {
  var commandArguments: [String] {
    flatMap(\.arguments)
  }
}
