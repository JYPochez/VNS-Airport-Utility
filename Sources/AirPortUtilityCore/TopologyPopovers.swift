import AppKit
import SwiftUI

struct DevicePopover: View {
  @EnvironmentObject private var model: AirportAppModel

  var body: some View {
    if model.shouldShowDeviceLoading {
      DeviceLoadingPopover()
    } else if model.shouldShowDeviceConnectionPrompt {
      ConnectionPopover(mode: DevicePopoverPresentationPolicy.connectionPromptMode)
    } else {
      deviceDetails
    }
  }

  private var deviceDetails: some View {
    VStack(alignment: .leading, spacing: 0) {
      PopoverTitleLabel(
        text: model.baseStation.name.isEmpty ? "time capsule" : model.baseStation.name
      )
      .frame(width: 283, height: 19)
      .padding(.bottom, 6)
      PopoverDetailsRows(
        rows: deviceDetailRows)
        .frame(width: 274, height: deviceDetailsHeight)
      HStack {
        Spacer()
        PopoverEditButton {
          if model.selectedDeviceFirmwareUpdateBadgeCount > 0 {
            model.beginEditingFirmware()
          } else {
            model.beginEditing()
          }
        }
        .frame(width: 47, height: 18)
      }
      .padding(.top, 7)
    }
    .padding(13)
    .frame(width: 300, height: devicePopoverHeight, alignment: .leading)
  }

  private var deviceDetailRows: [(String, String)] {
    var rows = [
      ("status", model.selectedDeviceStatusText()),
      ("network", model.wireless.networkName),
      ("IP address", model.internet.ipv4Address),
      ("LAN IP address", model.network.lanIPAddress),
      ("serial number", model.baseStation.serialNumber),
      ("version", model.baseStation.version),
    ]
    let firmwareUpdate = model.selectedDeviceFirmwareUpdateDetail
      .trimmingCharacters(in: .whitespacesAndNewlines)
    if !firmwareUpdate.isEmpty {
      rows.insert(("firmware update", firmwareUpdate), at: 1)
    }
    let statusDetails = model.selectedDeviceStatusDetails()
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
    for detail in statusDetails.reversed() {
      rows.insert(("detail", detail), at: firmwareUpdate.isEmpty ? 1 : 2)
    }
    return rows
  }

  private var deviceDetailsHeight: CGFloat {
    CGFloat(deviceDetailRows.count) * 17 + 5
  }

  private var devicePopoverHeight: CGFloat {
    deviceDetailsHeight + 69
  }
}

struct DeviceLoadingPopover: View {
  var body: some View {
    SettingsLoadingPopover(title: "Connecting to Base Station")
  }
}

private struct InternetLoadingPopover: View {
  var body: some View {
    SettingsLoadingPopover(title: "Loading Internet Settings")
  }
}

private struct SettingsLoadingPopover: View {
  @EnvironmentObject private var model: AirportAppModel
  let title: String

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(title)
        .font(.system(size: 13, weight: .semibold))
      HStack(spacing: 10) {
        ProgressView()
          .controlSize(.small)
        Text(model.status)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(2)
      }
    }
    .padding(14)
    .frame(width: 277, alignment: .leading)
  }
}

struct InternetPopover: View {
  @EnvironmentObject private var model: AirportAppModel

  var body: some View {
    if model.shouldShowInternetLoading {
      InternetLoadingPopover()
    } else {
      internetDetails
    }
  }

  private var internetDetails: some View {
    VStack(alignment: .leading, spacing: 0) {
      PopoverTitleLabel(text: "Internet")
        .frame(width: 283, height: 19)
        .padding(.bottom, 6)
      PopoverDetailsRows(
        rows: [
          ("connection", model.internetPopoverConnectionStatus),
          ("router address", model.hostInternet.routerAddress),
          ("DNS servers", model.hostInternet.dnsServers),
        ])
        .frame(width: 274, height: 54)
    }
    .padding(13)
    .frame(width: 300, height: 92, alignment: .leading)
  }
}

private struct PopoverTitleLabel: NSViewRepresentable {
  var text: String

  func makeNSView(context: Context) -> NSTextField {
    let field = NSTextField(labelWithString: text)
    field.frame = NSRect(x: 0, y: 0, width: 283, height: 19)
    field.alignment = .center
    field.font = .systemFont(ofSize: 16, weight: .semibold)
    field.textColor = .labelColor
    field.lineBreakMode = .byTruncatingTail
    field.drawsBackground = false
    field.isBezeled = false
    field.isEditable = false
    field.isSelectable = false
    return field
  }

  func updateNSView(_ field: NSTextField, context: Context) {
    field.stringValue = text
  }
}

private struct PopoverDetailsRows: NSViewRepresentable {
  var rows: [(String, String)]

  func makeNSView(context: Context) -> NSScrollView {
    let scrollView = NSScrollView(frame: NSRect(x: 0, y: 0, width: 274, height: 107))
    scrollView.drawsBackground = false
    scrollView.borderType = .noBorder
    scrollView.hasVerticalScroller = false
    scrollView.hasHorizontalScroller = false
    scrollView.autohidesScrollers = true
    scrollView.documentView = PopoverDetailsDocumentView()
    return scrollView
  }

  func updateNSView(_ scrollView: NSScrollView, context: Context) {
    let documentView =
      (scrollView.documentView as? PopoverDetailsDocumentView) ?? PopoverDetailsDocumentView()
    documentView.configure(rows: rows)
    scrollView.documentView = documentView
  }
}

private final class PopoverDetailsDocumentView: NSView {
  override var isFlipped: Bool {
    true
  }

  override init(frame frameRect: NSRect) {
    super.init(frame: frameRect)
    self.frame = NSRect(x: 0, y: 0, width: 274, height: 107)
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    nil
  }

  func configure(rows: [(String, String)]) {
    subviews.forEach { $0.removeFromSuperview() }
    frame.size.height = max(107, CGFloat(rows.count) * 17.5 + 2)

    for (index, row) in rows.enumerated() {
      let y = CGFloat(index) * 17.5
      addSubview(textField(row.0, frame: NSRect(x: 0, y: y, width: 108, height: 19), label: true))
      addSubview(
        textField(
          row.1.isEmpty ? "--" : row.1,
          frame: NSRect(x: 122, y: y, width: 152, height: 19),
          label: false))
    }
  }

  private func textField(_ text: String, frame: NSRect, label: Bool) -> NSTextField {
    let field = NSTextField(labelWithString: text)
    field.frame = frame
    field.toolTip = text
    field.alignment = label ? .right : .left
    field.font = .systemFont(ofSize: 13, weight: .semibold)
    field.textColor = label ? .secondaryLabelColor : .labelColor
    field.lineBreakMode = .byTruncatingTail
    field.drawsBackground = false
    field.isBezeled = false
    field.isEditable = false
    field.isSelectable = false
    return field
  }
}

private struct PopoverEditButton: NSViewRepresentable {
  var action: () -> Void

  func makeCoordinator() -> Coordinator {
    Coordinator(action: action)
  }

  func makeNSView(context: Context) -> NSButton {
    let button = PopoverEditNSButton(
      title: "Edit", target: context.coordinator, action: #selector(Coordinator.press))
    button.bezelStyle = .rounded
    button.controlSize = .small
    button.font = .systemFont(ofSize: 13)
    button.setButtonType(.momentaryPushIn)
    button.identifier = NSUserInterfaceItemIdentifier("topology.device.popover.edit")
    button.setAccessibilityIdentifier("topology.device.popover.edit")
    return button
  }

  func updateNSView(_ nsView: NSButton, context: Context) {
    context.coordinator.action = action
    nsView.target = context.coordinator
    nsView.action = #selector(Coordinator.press)
    nsView.identifier = NSUserInterfaceItemIdentifier("topology.device.popover.edit")
    nsView.setAccessibilityIdentifier("topology.device.popover.edit")
  }

  final class Coordinator: NSObject {
    var action: () -> Void

    init(action: @escaping () -> Void) {
      self.action = action
    }

    @MainActor @objc func press() {
      action()
    }
  }
}

private final class PopoverEditNSButton: NSButton {
  override var intrinsicContentSize: NSSize {
    NSSize(width: 47, height: 18)
  }
}

struct ConnectionPopover: View {
  enum Mode {
    case full
    case passwordOnly
  }

  @EnvironmentObject private var model: AirportAppModel
  var mode: Mode = .full

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      Text("Connect to Base Station")
        .font(.system(size: 13, weight: .semibold))
      if mode == .full {
        AirPortTextField(
          text: $model.connection.host,
          placeholder: "Host",
          identifier: "connection.popover.host")
          .frame(width: 220, height: 24)
      }
      AirPortSecureField(
        text: $model.connection.password,
        placeholder: "Password",
        identifier: "connection.popover.password",
        onSubmit: submitConnection)
        .frame(width: 220, height: 24)
      if mode == .passwordOnly {
        Toggle(
          "Remember this password in my keychain",
          isOn: Binding(
            get: { model.rememberConnectionPassword },
            set: { model.updateRememberConnectionPassword($0) }))
          .toggleStyle(.checkbox)
          .font(.system(size: 12))
          .accessibilityIdentifier("connection.popover.remember.password")
      }
      if mode == .full && !model.mockMode {
        AirPortTextField(
          text: $model.connection.repoPath,
          placeholder: "Repo",
          identifier: "connection.popover.repository")
          .frame(width: 220, height: 24)
      }
      HStack {
        Spacer()
        Button(model.isBusy ? "Working" : "Connect") {
          submitConnection()
        }
        .accessibilityLabel("Connect")
        .accessibilityIdentifier("connection.popover.connect")
        .keyboardShortcut(.defaultAction)
        .disabled(!model.canAttemptConnection)
      }
      if !model.status.hasPrefix("Connected") {
        Text(model.status)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
    }
    .padding(14)
    .onAppear {
      model.prefillConnectionPasswordFromEnvironmentIfNeeded()
    }
  }

  private func submitConnection() {
    guard model.canAttemptConnection else { return }
    model.refresh()
  }
}
