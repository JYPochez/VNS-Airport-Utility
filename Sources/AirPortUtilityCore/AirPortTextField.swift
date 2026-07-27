import AppKit
import SwiftUI

struct AirPortTextField: View {
  @Binding var text: String
  var placeholder = ""
  var selectOnAppear = false
  var identifier: String?
  @State private var isFocused: Bool

  init(
    text: Binding<String>, placeholder: String = "", selectOnAppear: Bool = false,
    identifier: String? = nil
  ) {
    self._text = text
    self.placeholder = placeholder
    self.selectOnAppear = selectOnAppear
    self.identifier = identifier
    self._isFocused = State(initialValue: selectOnAppear)
  }

  var body: some View {
    AirPortNSTextField(
      text: $text,
      placeholder: placeholder,
      selectOnAppear: selectOnAppear,
      identifier: identifier,
      isFocused: $isFocused
    )
    .airPortField(isFocused: isFocused)
  }
}

struct AirPortSecureField: View {
  @Binding var text: String
  var placeholder = ""
  var identifier: String?
  var onSubmit: (() -> Void)?
  @State private var isFocused = false

  init(
    text: Binding<String>, placeholder: String = "", identifier: String? = nil,
    onSubmit: (() -> Void)? = nil
  ) {
    self._text = text
    self.placeholder = placeholder
    self.identifier = identifier
    self.onSubmit = onSubmit
  }

  var body: some View {
    AirPortNSSecureTextField(
      text: $text,
      placeholder: placeholder,
      identifier: identifier,
      onSubmit: onSubmit,
      isFocused: $isFocused
    )
    .airPortField(isFocused: isFocused)
  }
}

private struct AirPortNSTextField: NSViewRepresentable {
  @Binding var text: String
  var placeholder: String
  var selectOnAppear: Bool
  var identifier: String?
  @Binding var isFocused: Bool

  func makeNSView(context: Context) -> NSTextField {
    let textField = BindingNSTextField(string: text)
    textField.onStringValueChanged = { [weak coordinator = context.coordinator] value in
      Task { @MainActor in
        coordinator?.setTextFromTextField(value)
      }
    }
    setPlaceholder(placeholder, on: textField)
    textField.isBezeled = false
    textField.drawsBackground = false
    textField.focusRingType = .none
    textField.font = .systemFont(ofSize: 13)
    textField.textColor = .labelColor
    textField.delegate = context.coordinator
    textField.lineBreakMode = .byClipping
    textField.cell?.isScrollable = true
    textField.cell?.usesSingleLineMode = true
    configureIdentifier(on: textField)
    return textField
  }

  func updateNSView(_ textField: NSTextField, context: Context) {
    if let textField = textField as? BindingNSTextField {
      textField.onStringValueChanged = { [weak coordinator = context.coordinator] value in
        Task { @MainActor in
          coordinator?.setTextFromTextField(value)
        }
      }
    }
    if textField.stringValue != text {
      textField.stringValue = text
    }
    setPlaceholder(placeholder, on: textField)
    configureIdentifier(on: textField)
    context.coordinator.parent = self
    guard selectOnAppear, !context.coordinator.didSelectOnAppear else { return }
    context.coordinator.didSelectOnAppear = true
    DispatchQueue.main.async {
      textField.window?.makeFirstResponder(textField)
      textField.currentEditor()?.selectAll(nil)
      isFocused = true
    }
  }

  private func configureIdentifier(on textField: NSTextField) {
    textField.identifier = identifier.map { NSUserInterfaceItemIdentifier($0) }
    textField.setAccessibilityIdentifier(identifier)
  }

  func makeCoordinator() -> Coordinator {
    Coordinator(parent: self)
  }

  private func setPlaceholder(_ placeholder: String, on textField: NSTextField) {
    guard !placeholder.isEmpty else {
      textField.placeholderString = ""
      return
    }
    textField.placeholderAttributedString = NSAttributedString(
      string: placeholder,
      attributes: [
        .foregroundColor: NSColor.placeholderTextColor,
        .font: NSFont.systemFont(ofSize: 13),
      ]
    )
  }

  final class Coordinator: NSObject, NSTextFieldDelegate {
    var parent: AirPortNSTextField
    var didSelectOnAppear = false

    init(parent: AirPortNSTextField) {
      self.parent = parent
    }

    func controlTextDidBeginEditing(_ notification: Notification) {
      parent.isFocused = true
    }

    func controlTextDidEndEditing(_ notification: Notification) {
      parent.isFocused = false
    }

    func controlTextDidChange(_ notification: Notification) {
      guard let textField = notification.object as? NSTextField else { return }
      setTextFromTextField(textField.stringValue)
    }

    @MainActor func setTextFromTextField(_ value: String) {
      guard parent.text != value else { return }
      parent.text = value
    }
  }
}

private struct AirPortNSSecureTextField: NSViewRepresentable {
  @Binding var text: String
  var placeholder: String
  var identifier: String?
  var onSubmit: (() -> Void)?
  @Binding var isFocused: Bool

  func makeNSView(context: Context) -> NSSecureTextField {
    let textField = BindingNSSecureTextField(frame: .zero)
    textField.stringValue = text
    textField.onStringValueChanged = { [weak coordinator = context.coordinator] value in
      Task { @MainActor in
        coordinator?.setTextFromTextField(value)
      }
    }
    setPlaceholder(placeholder, on: textField)
    textField.isBezeled = false
    textField.drawsBackground = false
    textField.focusRingType = .none
    textField.font = .systemFont(ofSize: 13)
    textField.textColor = .labelColor
    textField.delegate = context.coordinator
    textField.lineBreakMode = .byClipping
    textField.cell?.isScrollable = true
    textField.cell?.usesSingleLineMode = true
    configureIdentifier(on: textField)
    return textField
  }

  func updateNSView(_ textField: NSSecureTextField, context: Context) {
    if let textField = textField as? BindingNSSecureTextField {
      textField.onStringValueChanged = { [weak coordinator = context.coordinator] value in
        Task { @MainActor in
          coordinator?.setTextFromTextField(value)
        }
      }
    }
    if textField.stringValue != text {
      textField.stringValue = text
    }
    setPlaceholder(placeholder, on: textField)
    configureIdentifier(on: textField)
    context.coordinator.parent = self
  }

  private func configureIdentifier(on textField: NSSecureTextField) {
    textField.identifier = identifier.map { NSUserInterfaceItemIdentifier($0) }
    textField.setAccessibilityIdentifier(identifier)
  }

  func makeCoordinator() -> Coordinator {
    Coordinator(parent: self)
  }

  private func setPlaceholder(_ placeholder: String, on textField: NSSecureTextField) {
    guard !placeholder.isEmpty else {
      textField.placeholderString = ""
      return
    }
    textField.placeholderAttributedString = NSAttributedString(
      string: placeholder,
      attributes: [
        .foregroundColor: NSColor.placeholderTextColor,
        .font: NSFont.systemFont(ofSize: 13),
      ]
    )
  }

  final class Coordinator: NSObject, NSTextFieldDelegate {
    var parent: AirPortNSSecureTextField

    init(parent: AirPortNSSecureTextField) {
      self.parent = parent
    }

    func controlTextDidBeginEditing(_ notification: Notification) {
      parent.isFocused = true
    }

    func controlTextDidEndEditing(_ notification: Notification) {
      parent.isFocused = false
    }

    func controlTextDidChange(_ notification: Notification) {
      guard let textField = notification.object as? NSTextField else { return }
      setTextFromTextField(textField.stringValue)
    }

    func control(
      _ control: NSControl,
      textView: NSTextView,
      doCommandBy commandSelector: Selector
    ) -> Bool {
      guard commandSelector == #selector(NSResponder.insertNewline(_:)) else { return false }
      if let textField = control as? NSTextField {
        setTextFromTextField(textField.stringValue)
      }
      Task { @MainActor in
        self.parent.onSubmit?()
      }
      return true
    }

    @MainActor func setTextFromTextField(_ value: String) {
      guard parent.text != value else { return }
      parent.text = value
    }
  }
}

private final class BindingNSTextField: NSTextField {
  var onStringValueChanged: ((String) -> Void)?

  override var stringValue: String {
    didSet {
      guard stringValue != oldValue else { return }
      onStringValueChanged?(stringValue)
    }
  }

  override func setAccessibilityValue(_ accessibilityValue: Any?) {
    guard let value = accessibilityValue as? String else { return }
    if stringValue != value {
      stringValue = value
    }
    onStringValueChanged?(value)
  }
}

private final class BindingNSSecureTextField: NSSecureTextField {
  var onStringValueChanged: ((String) -> Void)?

  override var stringValue: String {
    didSet {
      guard stringValue != oldValue else { return }
      onStringValueChanged?(stringValue)
    }
  }

  override func setAccessibilityValue(_ accessibilityValue: Any?) {
    guard let value = accessibilityValue as? String else { return }
    if stringValue != value {
      stringValue = value
    }
    onStringValueChanged?(value)
  }
}
