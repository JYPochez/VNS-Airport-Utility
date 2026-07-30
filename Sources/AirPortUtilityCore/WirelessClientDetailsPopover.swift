import AppKit

@MainActor
enum WirelessClientDetailsLayout {
  static let minimumPanelSize = NSSize(width: 253, height: 118)
  static let rowHeight: CGFloat = 16
  static let rowPitch: CGFloat = DevicePopoverLayout.rowHeight
  static let topInset: CGFloat = 19
  static let bottomInset: CGFloat = 19
  static let labelX: CGFloat = 19
  static let minimumLabelWidth: CGFloat = 110
  static let columnSpacing: CGFloat = 6
  static let minimumValueWidth: CGFloat = 99
  static let trailingInset: CGFloat = 19
  static let textPadding: CGFloat = 4
  static let maximumPanelWidth: CGFloat = 420
  static let screenEdgeInset: CGFloat = 12
  static let textFont = NSFont.systemFont(ofSize: 13, weight: .semibold)

  struct Metrics {
    let panelSize: NSSize
    let labelWidth: CGFloat
    let valueX: CGFloat
    let valueWidth: CGFloat
  }

  static func metrics(
    for rows: [WirelessClientDetailRow],
    maximumWidth: CGFloat = maximumPanelWidth
  ) -> Metrics {
    let widestLabel = rows.reduce(CGFloat.zero) { width, row in
      max(width, measuredWidth(of: row.label))
    }
    let widestValue = rows.reduce(CGFloat.zero) { width, row in
      max(width, measuredWidth(of: row.value))
    }
    let labelWidth = max(minimumLabelWidth, widestLabel)
    let valueX = labelX + labelWidth + columnSpacing
    let availableValueWidth = max(
      1,
      maximumWidth - valueX - trailingInset)
    let valueWidth = min(
      max(minimumValueWidth, widestValue),
      availableValueWidth)
    let contentHeight =
      topInset
      + CGFloat(max(rows.count - 1, 0)) * rowPitch
      + rowHeight
      + bottomInset
    let panelSize = NSSize(
      width: valueX + valueWidth + trailingInset,
      height: max(minimumPanelSize.height, contentHeight))
    return Metrics(
      panelSize: panelSize,
      labelWidth: labelWidth,
      valueX: valueX,
      valueWidth: valueWidth)
  }

  static func panelOrigin(
    panelSize: NSSize,
    visibleFrame: NSRect,
    pointerLocation: NSPoint,
    sourceRect: NSRect?
  ) -> NSPoint {
    var origin: NSPoint
    if let sourceRect {
      origin = NSPoint(
        x: sourceRect.maxX + screenEdgeInset,
        y: sourceRect.midY - panelSize.height / 2)
      if origin.x + panelSize.width > visibleFrame.maxX {
        origin.x =
          sourceRect.minX - panelSize.width - screenEdgeInset
      }
    } else {
      origin = NSPoint(
        x: pointerLocation.x + screenEdgeInset,
        y: pointerLocation.y - panelSize.height - 18)
      if origin.x + panelSize.width > visibleFrame.maxX {
        origin.x =
          pointerLocation.x - panelSize.width - screenEdgeInset
      }
      if origin.y < visibleFrame.minY {
        origin.y = pointerLocation.y + 18
      }
    }
    origin.x = clampedCoordinate(
      origin.x,
      minimum: visibleFrame.minX,
      maximum: visibleFrame.maxX - panelSize.width)
    origin.y = clampedCoordinate(
      origin.y,
      minimum: visibleFrame.minY,
      maximum: visibleFrame.maxY - panelSize.height)
    return origin
  }

  private static func clampedCoordinate(
    _ coordinate: CGFloat,
    minimum: CGFloat,
    maximum: CGFloat
  ) -> CGFloat {
    min(max(coordinate, minimum), max(minimum, maximum))
  }

  private static func measuredWidth(of text: String) -> CGFloat {
    ceil(
      (text as NSString).size(
        withAttributes: [.font: textFont]
      ).width) + textPadding
  }
}

@MainActor
final class WirelessClientDetailsContentView: NSVisualEffectView {
  private(set) var client: WirelessClient?
  private var configuredMaximumWidth: CGFloat?
  var pointerPresenceChanged: ((Bool) -> Void)?

  override var isFlipped: Bool {
    true
  }

  init() {
    super.init(
      frame: NSRect(
        origin: .zero,
        size: WirelessClientDetailsLayout.minimumPanelSize))
    material = .popover
    blendingMode = .behindWindow
    state = .active
    wantsLayer = true
    layer?.cornerRadius = 7
    layer?.masksToBounds = true
    addTrackingArea(
      NSTrackingArea(
        rect: .zero,
        options: [.mouseEnteredAndExited, .activeInActiveApp, .inVisibleRect],
        owner: self,
        userInfo: nil))
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    nil
  }

  func configure(
    client: WirelessClient,
    maximumWidth: CGFloat = WirelessClientDetailsLayout.maximumPanelWidth
  ) {
    guard self.client != client || configuredMaximumWidth != maximumWidth else {
      return
    }
    self.client = client
    configuredMaximumWidth = maximumWidth
    subviews.forEach { $0.removeFromSuperview() }
    let metrics = WirelessClientDetailsLayout.metrics(
      for: client.detailRows,
      maximumWidth: maximumWidth)
    frame.size = metrics.panelSize

    for (index, row) in client.detailRows.enumerated() {
      let y =
        WirelessClientDetailsLayout.topInset
        + CGFloat(index) * WirelessClientDetailsLayout.rowPitch
      let identifier = row.label
        .lowercased()
        .replacingOccurrences(of: " ", with: "-")
      addSubview(
        textField(
          row.label,
          frame: NSRect(
            x: WirelessClientDetailsLayout.labelX,
            y: y,
            width: metrics.labelWidth,
            height: WirelessClientDetailsLayout.rowHeight),
          label: true,
          identifier: "popover.wirelessClients.details.label.\(identifier)"))
      addSubview(
        textField(
          row.value,
          frame: NSRect(
            x: metrics.valueX,
            y: y,
            width: metrics.valueWidth,
            height: WirelessClientDetailsLayout.rowHeight),
          label: false,
          identifier: "popover.wirelessClients.details.value.\(identifier)"))
    }
  }

  private func textField(
    _ text: String,
    frame: NSRect,
    label: Bool,
    identifier: String
  ) -> NSTextField {
    let field = NSTextField(labelWithString: text)
    field.frame = frame
    field.alignment = .left
    field.font = WirelessClientDetailsLayout.textFont
    field.textColor = label ? .secondaryLabelColor : .labelColor
    field.lineBreakMode = .byTruncatingTail
    field.toolTip = text
    field.drawsBackground = false
    field.isBezeled = false
    field.isEditable = false
    field.isSelectable = false
    field.identifier = NSUserInterfaceItemIdentifier(identifier)
    field.setAccessibilityIdentifier(identifier)
    return field
  }

  override func mouseEntered(with event: NSEvent) {
    super.mouseEntered(with: event)
    pointerPresenceChanged?(true)
  }

  override func mouseExited(with event: NSEvent) {
    super.mouseExited(with: event)
    pointerPresenceChanged?(false)
  }
}

@MainActor
final class WirelessClientDetailsPanelController: NSObject {
  private enum PresentationAnchor: Equatable {
    case pointer
    case sourceView
  }

  private let panel: NSPanel
  let contentView: WirelessClientDetailsContentView
  var hoverDelay: TimeInterval = 0.7
  var dismissalDelay: TimeInterval = 0.15
  var presentationDidEnd: ((String) -> Void)?
  private(set) var presentedClientID: String?

  private var pendingClient: WirelessClient?
  private weak var pendingSourceView: NSView?
  private var pendingPresentationAnchor = PresentationAnchor.pointer

  override init() {
    contentView = WirelessClientDetailsContentView()
    panel = NSPanel(
      contentRect: NSRect(
        origin: .zero,
        size: WirelessClientDetailsLayout.minimumPanelSize),
      styleMask: [.borderless, .nonactivatingPanel],
      backing: .buffered,
      defer: false)
    super.init()

    panel.contentView = contentView
    panel.backgroundColor = .clear
    panel.isOpaque = false
    panel.hasShadow = true
    panel.ignoresMouseEvents = false
    panel.isReleasedWhenClosed = false
    panel.becomesKeyOnlyIfNeeded = true
    panel.level = .popUpMenu
    panel.collectionBehavior = [.transient, .ignoresCycle]
    panel.setAccessibilityTitle("")
    contentView.pointerPresenceChanged = { [weak self] isInside in
      if isInside {
        self?.cancelPendingDismissal()
      } else {
        self?.dismissAfterGracePeriod()
      }
    }
  }

  var isVisible: Bool {
    panel.isVisible
  }

  func schedule(client: WirelessClient, from sourceView: NSView) {
    cancelPendingDismissal()
    if presentedClientID == client.id, panel.isVisible {
      configurePanel(
        client: client,
        maximumWidth: maximumPanelWidth(for: sourceView.window?.screen))
      return
    }
    cancelPendingPresentation()
    endSupersededPendingPresentation(replacingWith: client.id)
    pendingClient = client
    pendingSourceView = sourceView
    pendingPresentationAnchor = .pointer
    if hoverDelay <= 0 {
      showPendingClient()
    } else {
      perform(
        #selector(showPendingClient),
        with: nil,
        afterDelay: hoverDelay,
        inModes: [.common])
    }
  }

  func presentImmediately(client: WirelessClient, from sourceView: NSView) {
    cancelPendingDismissal()
    cancelPendingPresentation()
    endSupersededPendingPresentation(replacingWith: client.id)
    pendingClient = client
    pendingSourceView = sourceView
    pendingPresentationAnchor = .sourceView
    showPendingClient()
  }

  func update(client: WirelessClient) {
    if pendingClient?.id == client.id {
      pendingClient = client
    }
    if presentedClientID == client.id {
      configurePanel(
        client: client,
        maximumWidth: maximumPanelWidth(for: panel.screen))
    }
  }

  func dismissAfterGracePeriod() {
    cancelPendingPresentation()
    cancelPendingDismissal()
    perform(
      #selector(hideAfterGracePeriod),
      with: nil,
      afterDelay: dismissalDelay,
      inModes: [.common])
  }

  func hide() {
    cancelPendingPresentation()
    cancelPendingDismissal()
    let endedClientIDs = Set(
      [pendingClient?.id, presentedClientID].compactMap { $0 })
    pendingClient = nil
    pendingSourceView = nil
    pendingPresentationAnchor = .pointer
    presentedClientID = nil
    if let parent = panel.parent {
      parent.removeChildWindow(panel)
    }
    panel.orderOut(nil)
    for clientID in endedClientIDs {
      presentationDidEnd?(clientID)
    }
  }

  private func cancelPendingPresentation() {
    NSObject.cancelPreviousPerformRequests(
      withTarget: self,
      selector: #selector(showPendingClient),
      object: nil)
  }

  private func cancelPendingDismissal() {
    NSObject.cancelPreviousPerformRequests(
      withTarget: self,
      selector: #selector(hideAfterGracePeriod),
      object: nil)
  }

  @objc private func hideAfterGracePeriod() {
    hide()
  }

  @objc private func showPendingClient() {
    guard let client = pendingClient, let sourceView = pendingSourceView else {
      return
    }
    let presentationAnchor = pendingPresentationAnchor
    pendingClient = nil
    pendingSourceView = nil
    pendingPresentationAnchor = .pointer

    let mouseLocation = NSEvent.mouseLocation
    let screen =
      sourceView.window?.screen
      ?? NSScreen.screens.first(where: { $0.frame.contains(mouseLocation) })
      ?? NSScreen.main
    let visibleFrame = screen?.visibleFrame ?? .zero
    configurePanel(
      client: client,
      maximumWidth: maximumPanelWidth(for: screen))
    if let previousClientID = presentedClientID,
      previousClientID != client.id
    {
      presentationDidEnd?(previousClientID)
    }
    presentedClientID = client.id
    let panelSize = panel.frame.size
    let sourceRect =
      presentationAnchor == .sourceView
      ? sourceRectOnScreen(for: sourceView)
      : nil
    let origin = WirelessClientDetailsLayout.panelOrigin(
      panelSize: panelSize,
      visibleFrame: visibleFrame,
      pointerLocation: mouseLocation,
      sourceRect: sourceRect)
    panel.setFrameOrigin(origin)

    if let sourceWindow = sourceView.window {
      if let parent = panel.parent, parent !== sourceWindow {
        parent.removeChildWindow(panel)
      }
      if panel.parent == nil {
        sourceWindow.addChildWindow(panel, ordered: .above)
      }
    }
    panel.orderFront(nil)
  }

  private func configurePanel(
    client: WirelessClient,
    maximumWidth: CGFloat
  ) {
    contentView.configure(client: client, maximumWidth: maximumWidth)
    let size = contentView.frame.size
    guard panel.frame.size != size else { return }
    panel.setContentSize(size)

    guard panel.isVisible, let screen = panel.screen else { return }
    var origin = panel.frame.origin
    origin.x = clampedCoordinate(
      origin.x,
      minimum: screen.visibleFrame.minX,
      maximum: screen.visibleFrame.maxX - size.width)
    origin.y = clampedCoordinate(
      origin.y,
      minimum: screen.visibleFrame.minY,
      maximum: screen.visibleFrame.maxY - size.height)
    panel.setFrameOrigin(origin)
  }

  private func maximumPanelWidth(for screen: NSScreen?) -> CGFloat {
    guard let screen else {
      return WirelessClientDetailsLayout.maximumPanelWidth
    }
    return min(
      WirelessClientDetailsLayout.maximumPanelWidth,
      max(
        1,
        screen.visibleFrame.width
          - WirelessClientDetailsLayout.screenEdgeInset * 2))
  }

  private func endSupersededPendingPresentation(
    replacingWith clientID: String
  ) {
    guard let pendingClientID = pendingClient?.id,
      pendingClientID != clientID
    else {
      return
    }
    presentationDidEnd?(pendingClientID)
  }

  private func sourceRectOnScreen(for sourceView: NSView) -> NSRect? {
    guard let window = sourceView.window else {
      return nil
    }
    let sourceRectInWindow = sourceView.convert(sourceView.bounds, to: nil)
    return window.convertToScreen(sourceRectInWindow)
  }

  private func clampedCoordinate(
    _ coordinate: CGFloat,
    minimum: CGFloat,
    maximum: CGFloat
  ) -> CGFloat {
    min(max(coordinate, minimum), max(minimum, maximum))
  }
}

@MainActor
final class WirelessClientHoverField: NSTextField {
  var client: WirelessClient {
    didSet {
      updatePresentedContent()
    }
  }
  var presentationChanged:
    ((WirelessClientHoverField, Bool, Bool) -> Void)?

  private var isPointerInside = false
  private var isKeyboardActive = false
  private var isDetailsPresented = false

  init(client: WirelessClient, frame: NSRect) {
    self.client = client
    super.init(frame: frame)
    updatePresentedContent()
    alignment = .left
    font = .systemFont(ofSize: 13, weight: .semibold)
    textColor = .labelColor
    lineBreakMode = .byTruncatingTail
    drawsBackground = false
    isBezeled = false
    isEditable = false
    isSelectable = false
    focusRingType = .exterior
    addTrackingArea(
      NSTrackingArea(
        rect: .zero,
        options: [.mouseEnteredAndExited, .activeInActiveApp, .inVisibleRect],
        owner: self,
        userInfo: nil))
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    nil
  }

  override var acceptsFirstResponder: Bool {
    true
  }

  override func isAccessibilityElement() -> Bool {
    true
  }

  override func accessibilityRole() -> NSAccessibility.Role? {
    .button
  }

  override func accessibilityTitle() -> String? {
    client.displayName
  }

  override func accessibilityHelp() -> String? {
    accessibilityDetails
  }

  override func accessibilityActionNames() -> [NSAccessibility.Action] {
    [.press]
  }

  override func accessibilityPerformPress() -> Bool {
    if isDetailsPresented {
      dismissPresentation(immediately: true)
      if window?.firstResponder === self {
        _ = window?.makeFirstResponder(nil)
      }
    } else {
      _ = window?.makeFirstResponder(self)
      if !isDetailsPresented {
        requestPresentation(immediately: true)
      }
    }
    return true
  }

  override func setAccessibilityFocused(_ accessibilityFocused: Bool) {
    super.setAccessibilityFocused(accessibilityFocused)
    if accessibilityFocused {
      _ = window?.makeFirstResponder(self)
    } else if !isPointerInside {
      dismissPresentation(immediately: true)
      if window?.firstResponder === self {
        _ = window?.makeFirstResponder(nil)
      }
    }
  }

  func detailsPresentationDidEnd() {
    isDetailsPresented = false
  }

  override func mouseEntered(with event: NSEvent) {
    super.mouseEntered(with: event)
    isPointerInside = true
    requestPresentation(immediately: false)
  }

  override func mouseExited(with event: NSEvent) {
    super.mouseExited(with: event)
    isPointerInside = false
    if !isKeyboardActive {
      dismissPresentation(immediately: false)
    }
  }

  override func mouseDown(with event: NSEvent) {
    _ = window?.makeFirstResponder(self)
    requestPresentation(immediately: true)
  }

  override func keyDown(with event: NSEvent) {
    switch event.charactersIgnoringModifiers {
    case " ", "\r", "\u{3}":
      requestPresentation(immediately: true)
    case "\u{1b}":
      dismissPresentation(immediately: true)
      _ = window?.makeFirstResponder(nil)
    default:
      super.keyDown(with: event)
    }
  }

  override func becomeFirstResponder() -> Bool {
    let becameFirstResponder = super.becomeFirstResponder()
    if becameFirstResponder {
      isKeyboardActive = true
      requestPresentation(immediately: true)
    }
    return becameFirstResponder
  }

  override func resignFirstResponder() -> Bool {
    let resignedFirstResponder = super.resignFirstResponder()
    if resignedFirstResponder {
      isKeyboardActive = false
      if !isPointerInside {
        dismissPresentation(immediately: true)
      }
    }
    return resignedFirstResponder
  }

  override func viewWillMove(toWindow newWindow: NSWindow?) {
    if newWindow == nil {
      isPointerInside = false
      isKeyboardActive = false
      dismissPresentation(immediately: true)
    }
    super.viewWillMove(toWindow: newWindow)
  }

  private var accessibilityDetails: String {
    client.detailRows
      .map { "\($0.label): \($0.value)" }
      .joined(separator: ", ")
  }

  private func updatePresentedContent() {
    stringValue = client.displayName
    toolTip = client.displayName
  }

  private func requestPresentation(immediately: Bool) {
    isDetailsPresented = true
    presentationChanged?(self, true, immediately)
  }

  private func dismissPresentation(immediately: Bool) {
    guard isDetailsPresented else { return }
    isDetailsPresented = false
    presentationChanged?(self, false, immediately)
  }
}
