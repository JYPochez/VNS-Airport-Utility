import AppKit
import SwiftUI

struct BaseStationCheckbox: NSViewRepresentable {
  var title: String
  @Binding var isOn: Bool
  var identifier: String?

  init(_ title: String, isOn: Binding<Bool>, identifier: String? = nil) {
    self.title = title
    self._isOn = isOn
    self.identifier = identifier
  }

  func makeNSView(context: Context) -> NSButton {
    let button = NSButton(
      checkboxWithTitle: title, target: context.coordinator, action: #selector(Coordinator.toggle))
    button.font = .systemFont(ofSize: 13)
    button.setButtonType(.switch)
    button.isBordered = false
    button.allowsMixedState = false
    button.identifier = identifier.map { NSUserInterfaceItemIdentifier($0) }
    button.setAccessibilityIdentifier(identifier)
    return button
  }

  func updateNSView(_ button: NSButton, context: Context) {
    context.coordinator.parent = self
    if button.title != title {
      button.title = title
    }
    button.identifier = identifier.map { NSUserInterfaceItemIdentifier($0) }
    button.setAccessibilityIdentifier(identifier)
    button.state = isOn ? .on : .off
  }

  func makeCoordinator() -> Coordinator {
    Coordinator(parent: self)
  }

  final class Coordinator: NSObject {
    var parent: BaseStationCheckbox

    init(parent: BaseStationCheckbox) {
      self.parent = parent
    }

    @objc @MainActor func toggle(_ sender: NSButton) {
      parent.isOn = sender.state == .on
    }
  }
}
