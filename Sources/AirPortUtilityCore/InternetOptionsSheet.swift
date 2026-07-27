import AppKit
import SwiftUI

struct InternetOptionsSheet: View {
  @EnvironmentObject private var model: AirportAppModel
  @Environment(\.dismiss) private var dismiss
  @State private var draft = InternetState()
  @State private var loaded = false

  var body: some View {
    ZStack(alignment: .topLeading) {
      Text("Internet Options")
        .font(.system(size: 13, weight: .semibold))
        .frame(width: 150, alignment: .leading)
        .offset(x: 18, y: 11)
      Divider()
        .frame(width: 480)
        .offset(x: 20, y: 36)

      if model.showsIPv6InternetControls {
        optionLabel("Configure IPv6:", width: 159)
          .offset(x: 61, y: 50)
        Picker("Configure IPv6", selection: $draft.configureIPv6) {
          Text("Link-local only").tag("link-local")
          Text("Automatically").tag("automatic")
          Text("Manually").tag("manual")
        }
        .labelsHidden()
        .pickerStyle(.menu)
        .accessibilityIdentifier("internet.options.configure.ipv6")
        .frame(width: 276, height: 23)
        .offset(x: 224, y: 45)

        optionLabel("IPv6 Mode:", width: 159)
          .offset(x: 61, y: 78)
        Picker("IPv6 Mode", selection: $draft.ipv6Mode) {
          Text("Default").tag("")
          Text("Host").tag("host")
          Text("Tunnel").tag("tunnel")
          Text("Router").tag("router")
        }
        .labelsHidden()
        .pickerStyle(.menu)
        .accessibilityIdentifier("internet.options.ipv6.mode")
        .frame(width: 276, height: 23)
        .offset(x: 224, y: 73)

        optionLabel("Default Route:", width: 159)
          .offset(x: 61, y: 106)
        AirPortTextField(
          text: $draft.ipv6DefaultRoute,
          identifier: "internet.options.ipv6.default.route")
          .frame(width: 277, height: 24)
          .offset(x: 224, y: 104)

        InternetOptionsCheckbox(
          "Block incoming IPv6 connections",
          isOn: $draft.ipv6Firewall,
          identifier: "internet.options.ipv6.firewall")
          .frame(width: 279, height: 18, alignment: .leading)
          .offset(x: 224, y: 136)
      }

      if model.showsDynamicGlobalHostnameControls {
        InternetOptionsCheckbox(
          "Use dynamic global hostname",
          isOn: $draft.dynamicGlobalHostname,
          identifier: "internet.options.dynamic.global.hostname")
          .frame(width: 279, height: 18, alignment: .leading)
          .offset(x: 224, y: dynamicHostnameOffset)

        Group {
          optionLabel("Hostname:", width: 133, enabled: draft.dynamicGlobalHostname)
            .offset(x: 86, y: dynamicHostnameOffset + 31)
          AirPortTextField(
            text: $draft.globalHostname,
            identifier: "internet.options.global.hostname")
            .frame(width: 277, height: 24)
            .disabled(!draft.dynamicGlobalHostname)
            .internetOptionsDisabledField(!draft.dynamicGlobalHostname)
            .offset(x: 224, y: dynamicHostnameOffset + 29)
          optionLabel("User:", width: 133, enabled: draft.dynamicGlobalHostname)
            .offset(x: 86, y: dynamicHostnameOffset + 58)
          AirPortTextField(
            text: $draft.globalHostnameUser,
            identifier: "internet.options.global.hostname.user")
            .frame(width: 277, height: 24)
            .disabled(!draft.dynamicGlobalHostname)
            .internetOptionsDisabledField(!draft.dynamicGlobalHostname)
            .offset(x: 224, y: dynamicHostnameOffset + 56)
          optionLabel("Password:", width: 133, enabled: draft.dynamicGlobalHostname)
            .offset(x: 86, y: dynamicHostnameOffset + 85)
          AirPortSecureField(
            text: $draft.globalHostnamePassword,
            identifier: "internet.options.global.hostname.password")
            .frame(width: 277)
            .disabled(!draft.dynamicGlobalHostname)
            .internetOptionsDisabledField(!draft.dynamicGlobalHostname)
            .offset(x: 224, y: dynamicHostnameOffset + 83)
          InternetOptionsCheckbox(
            "Configure automatically",
            isOn: $draft.dynamicGlobalHostnameAutoConfig,
            identifier: "internet.options.dynamic.global.hostname.auto.config")
            .frame(width: 279, height: 18, alignment: .leading)
            .disabled(!draft.dynamicGlobalHostname)
            .internetOptionsDisabledField(!draft.dynamicGlobalHostname)
            .offset(x: 224, y: dynamicHostnameOffset + 115)
        }
      }

      InternetOptionsButton("Cancel", identifier: "internet.options.cancel") { dismiss() }
        .offset(x: 348, y: 283)
      InternetOptionsButton("Save", isDefault: true, identifier: "internet.options.save") {
        model.internet = draft
        dismiss()
      }
      .offset(x: 430, y: 283)
    }
    .onAppear {
      if !loaded {
        draft = model.internet
        loaded = true
      }
    }
    .frame(width: 520, height: 323, alignment: .topLeading)
    .background(AirPortSheetBackground())
  }

  private var dynamicHostnameOffset: CGFloat {
    model.showsIPv6InternetControls ? 168 : 50
  }

  private func optionLabel(_ title: String, width: CGFloat, enabled: Bool = true) -> some View {
    Text(title)
      .font(.system(size: 13))
      .foregroundStyle(Color.primary.opacity(enabled ? 1 : 0.45))
      .frame(width: width, height: 20, alignment: .trailing)
  }
}

private struct InternetOptionsButton: NSViewRepresentable {
  var title: String
  var isDefault: Bool
  var isEnabled: Bool
  var identifier: String?
  var action: () -> Void

  init(
    _ title: String,
    isDefault: Bool = false,
    isEnabled: Bool = true,
    identifier: String? = nil,
    action: @escaping () -> Void
  ) {
    self.title = title
    self.isDefault = isDefault
    self.isEnabled = isEnabled
    self.identifier = identifier
    self.action = action
  }

  func makeNSView(context: Context) -> NSButton {
    let button = InternetOptionsNSButton(
      title: title, target: context.coordinator, action: #selector(Coordinator.press))
    button.bezelStyle = .rounded
    button.controlSize = .regular
    button.font = .systemFont(ofSize: 13)
    button.setButtonType(.momentaryPushIn)
    button.alignment = .center
    button.translatesAutoresizingMaskIntoConstraints = false
    button.widthAnchor.constraint(equalToConstant: 70).isActive = true
    button.heightAnchor.constraint(equalToConstant: 22).isActive = true
    configure(button)
    return button
  }

  func updateNSView(_ button: NSButton, context: Context) {
    context.coordinator.parent = self
    configure(button)
  }

  private func configure(_ button: NSButton) {
    if button.title != title {
      button.title = title
    }
    button.isEnabled = isEnabled
    button.keyEquivalent = isDefault ? "\r" : ""
    button.setAccessibilityTitle(title)
    button.identifier = identifier.map { NSUserInterfaceItemIdentifier($0) }
    button.setAccessibilityIdentifier(identifier)
  }

  func makeCoordinator() -> Coordinator {
    Coordinator(parent: self)
  }

  final class Coordinator: NSObject {
    var parent: InternetOptionsButton

    init(parent: InternetOptionsButton) {
      self.parent = parent
    }

    @objc @MainActor func press(_ sender: NSButton) {
      parent.action()
    }
  }
}

private final class InternetOptionsNSButton: NSButton {
  override func accessibilityTitle() -> String? {
    title
  }
}

struct InternetOptionsCheckbox: NSViewRepresentable {
  var title: String
  @Binding var isOn: Bool
  var identifier: String?

  init(_ title: String, isOn: Binding<Bool>, identifier: String? = nil) {
    self.title = title
    self._isOn = isOn
    self.identifier = identifier
  }

  func makeNSView(context: Context) -> NSButton {
    let button = InternetOptionsNSCheckbox(
      title: title, target: context.coordinator, action: #selector(Coordinator.toggle))
    button.font = .systemFont(ofSize: 13)
    button.setButtonType(.switch)
    button.isBordered = false
    button.allowsMixedState = false
    button.translatesAutoresizingMaskIntoConstraints = false
    button.widthAnchor.constraint(equalToConstant: 279).isActive = true
    button.heightAnchor.constraint(equalToConstant: 18).isActive = true
    button.setAccessibilityTitle(title)
    button.identifier = identifier.map { NSUserInterfaceItemIdentifier($0) }
    button.setAccessibilityIdentifier(identifier)
    return button
  }

  func updateNSView(_ button: NSButton, context: Context) {
    context.coordinator.parent = self
    if button.title != title {
      button.title = title
    }
    button.setAccessibilityTitle(title)
    button.identifier = identifier.map { NSUserInterfaceItemIdentifier($0) }
    button.setAccessibilityIdentifier(identifier)
    button.state = isOn ? .on : .off
  }

  func makeCoordinator() -> Coordinator {
    Coordinator(parent: self)
  }

  final class Coordinator: NSObject {
    var parent: InternetOptionsCheckbox

    init(parent: InternetOptionsCheckbox) {
      self.parent = parent
    }

    @objc @MainActor func toggle(_ sender: NSButton) {
      parent.isOn = sender.state == .on
    }
  }
}

private final class InternetOptionsNSCheckbox: NSButton {
  override func accessibilityTitle() -> String? {
    title
  }
}

extension View {
  fileprivate func internetOptionsDisabledField(_ disabled: Bool) -> some View {
    self
      .opacity(disabled ? 0.32 : 1)
  }
}
