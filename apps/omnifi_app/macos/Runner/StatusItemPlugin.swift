import AppKit
import FlutterMacOS
import Foundation

/// The menu-bar agent: an `NSStatusItem`, the menu hanging off it, and the
/// two-way bridge that keeps both in step with the engine.
///
/// OmniFi is a background utility. A windowed app with a dock icon gets quit
/// by accident by anyone tidying their dock, and clipboard sync then stops
/// with nothing on screen to say so. `LSUIElement` in `Info.plist` takes away
/// the dock icon and the app-switcher entry; this is what replaces them.
///
/// **The menu is AppKit, not Flutter.** It is a status readout, a checkbox and
/// two commands. `NSMenu` draws that instantly and correctly — keyboard
/// traversal, menu-bar appearance, the lot — where an embedded Flutter popover
/// would have to be told about all of it. The Flutter UI stays as an ordinary
/// window, opened on demand from here.
class StatusItemPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  /// **Strong, and it has to be.** An `NSStatusItem` that nothing retains
  /// disappears from the menu bar when it is deallocated: no error, no log
  /// line, no item. The plugin itself is retained by the registrar's
  /// method-call delegate list, so this property is the whole ownership chain
  /// between the app and the icon.
  private var statusItem: NSStatusItem?

  private var sink: FlutterEventSink?

  /// The first line of the menu — what the engine currently reports.
  /// Deliberately actionless, so AppKit greys it out: it is a readout, not a
  /// command.
  private let statusLine = NSMenuItem(
    title: "Starting…", action: nil, keyEquivalent: "")

  private let pauseItem = NSMenuItem(
    title: "Pause syncing", action: nil, keyEquivalent: "")

  /// How one connection state is presented. Grouped so that adding a state
  /// means answering every question about it at once, exactly as
  /// `StatusIndicator` does on the Dart side.
  private struct Presentation {
    let label: String

    /// **Four genuinely different silhouettes**, not four colours: a bolt, a
    /// cloud, a ring of arrows, a struck-through bolt. A menu-bar icon is
    /// rendered monochrome to match the bar, so colour carries no information
    /// there at all — and even where it would, it excludes anyone who cannot
    /// separate the hues.
    let symbol: String

    /// Used where SF Symbols are not available. The deployment target is
    /// 10.15 and `NSImage(systemSymbolName:)` arrived in 11; without a title
    /// to fall back on, such a build would put a zero-width button in the
    /// menu bar, which is the invisible-agent failure this whole task exists
    /// to prevent.
    let glyph: String
  }

  /// Nil for anything not in the contract with `status_item.dart`. Answered as
  /// an error rather than defaulted, because every default here is a lie about
  /// the connection: the Dart side maps an exhaustive switch onto these four
  /// strings, so a fifth arriving means the two ends have drifted apart and
  /// that should be loud.
  private static func presentation(for status: String) -> Presentation? {
    switch status {
    case "connectedDirect":
      return Presentation(
        label: "Connected (direct)", symbol: "bolt.fill", glyph: "⚡")
    case "connectedRelay":
      return Presentation(
        label: "Connected (relay)", symbol: "cloud.fill", glyph: "☁")
    case "reconnecting":
      return Presentation(
        label: "Reconnecting…", symbol: "arrow.triangle.2.circlepath",
        glyph: "↻")
    case "offline":
      return Presentation(
        label: "Offline", symbol: "bolt.slash.fill", glyph: "⊘")
    default:
      return nil
    }
  }

  static func register(with registrar: FlutterPluginRegistrar) {
    let instance = StatusItemPlugin()
    let methods = FlutterMethodChannel(
      name: "com.omnifi/status_item", binaryMessenger: registrar.messenger)
    registrar.addMethodCallDelegate(instance, channel: methods)
    let events = FlutterEventChannel(
      name: "com.omnifi/status_item/commands",
      binaryMessenger: registrar.messenger)
    events.setStreamHandler(instance)
    instance.install()
  }

  /// Builds the item and its menu.
  ///
  /// Called from `applicationDidFinishLaunching`, which is the main thread —
  /// asserted rather than assumed, because `NSStatusBar` is not thread-safe
  /// and the symptom of getting it wrong is an item that intermittently is
  /// not there.
  private func install() {
    assert(Thread.isMainThread, "the status item must be built on the main thread")

    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()

    statusLine.isEnabled = false
    menu.addItem(statusLine)
    menu.addItem(NSMenuItem.separator())

    pauseItem.target = self
    pauseItem.action = #selector(pauseClicked)
    menu.addItem(pauseItem)
    menu.addItem(NSMenuItem.separator())

    let open = NSMenuItem(
      title: "Open OmniFi", action: #selector(openClicked), keyEquivalent: "")
    open.target = self
    menu.addItem(open)

    // No ⌘Q here: the application menu already owns that key, and it is
    // retargeted below so both doors lead to the same teardown.
    let quit = NSMenuItem(
      title: "Quit OmniFi", action: #selector(quitClicked), keyEquivalent: "")
    quit.target = self
    menu.addItem(quit)

    item.menu = menu
    statusItem = item
    adoptApplicationQuitItem()
    // Something has to be in the bar before Dart's first `setStatus` arrives,
    // and "offline" is the honest thing to show: nothing has connected yet.
    apply(status: "offline")
  }

  /// Points the application menu's Quit item at the same command the status
  /// menu uses.
  ///
  /// ⌘Q is still reachable whenever the Flutter window has focus, and the
  /// nib wires it straight to `NSApplication.terminate(_:)` — which is the
  /// abrupt exit this plugin exists to avoid, leaving the last peer on a
  /// socket that looks alive to it until its liveness timeout expires. Two
  /// ways to quit should not mean two shutdown paths.
  ///
  /// Best-effort by construction: if the item cannot be found the menu keeps
  /// the behaviour it has today rather than losing its Quit.
  private func adoptApplicationQuitItem() {
    let terminate = #selector(NSApplication.terminate(_:))
    for menu in [NSApp.mainMenu?.items.first?.submenu, NSApp.mainMenu] {
      guard let item = menu?.items.first(where: { $0.action == terminate })
      else { continue }
      item.target = self
      item.action = #selector(quitClicked)
      return
    }
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "setStatus":
      guard let args = call.arguments as? [String: Any],
            let status = args["status"] as? String else {
        result(FlutterError(code: "bad_args",
                            message: "status required", details: nil))
        return
      }
      guard apply(status: status) else {
        result(FlutterError(code: "unknown_status",
                            message: "no presentation for '\(status)'",
                            details: nil))
        return
      }
      result(nil)
    case "setPaused":
      guard let args = call.arguments as? [String: Any],
            let paused = args["paused"] as? Bool else {
        result(FlutterError(code: "bad_args",
                            message: "paused required", details: nil))
        return
      }
      // Driven from `ClipboardSync.isPaused`, never from the click that
      // preceded it: the engine also pauses itself when the screen locks, and
      // a checkmark that tracked only the user's clicks would read "syncing"
      // through a locked screen.
      pauseItem.state = paused ? .on : .off
      result(nil)
    case "show":
      showWindow()
      result(nil)
    case "hide":
      flutterWindow?.orderOut(nil)
      result(nil)
    case "terminate":
      // Replied to first. `NSApp.terminate` never returns, and tearing the
      // process down inside the call would leave Dart's `await` on a reply
      // that can no longer come.
      result(nil)
      DispatchQueue.main.async { NSApp.terminate(nil) }
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  /// Returns false for a status string that is not in the contract, leaving
  /// whatever was showing in place rather than replacing it with a guess.
  @discardableResult
  private func apply(status: String) -> Bool {
    guard let presentation = StatusItemPlugin.presentation(for: status),
          let button = statusItem?.button else {
      return false
    }
    statusLine.title = presentation.label
    button.toolTip = "OmniFi — \(presentation.label)"

    if #available(macOS 11.0, *) {
      let image = NSImage(systemSymbolName: presentation.symbol,
                          accessibilityDescription: presentation.label)
      // Template, so AppKit recolours it for a light or dark menu bar and for
      // the inverted look while the menu is open. A non-template image stays
      // one fixed colour and is invisible against half of them.
      image?.isTemplate = true
      button.image = image
      button.title = image == nil ? presentation.glyph : ""
    } else {
      button.title = presentation.glyph
    }
    button.setAccessibilityLabel("OmniFi: \(presentation.label)")
    return true
  }

  /// The Flutter window, found by type rather than by `NSApp.mainWindow`.
  ///
  /// Under `LSUIElement` the window spends most of its life ordered out, and
  /// a window that is not on screen is not the main window — asking AppKit for
  /// the main window is precisely wrong at the one moment this is needed.
  private var flutterWindow: NSWindow? {
    NSApp.windows.first { $0 is MainFlutterWindow }
  }

  private func showWindow() {
    guard let window = flutterWindow else { return }
    // `activate` first, and it is not optional. `LSUIElement` makes this an
    // accessory app, and an accessory app that orders a window front without
    // activating puts it *behind* whatever the user was working in — which
    // looks exactly like the menu item having done nothing.
    NSApp.activate(ignoringOtherApps: true)
    window.makeKeyAndOrderFront(nil)
  }

  @objc private func openClicked() { emit("openWindow") }

  @objc private func pauseClicked() {
    // No optimistic toggle of `pauseItem.state` here. The engine decides what
    // paused means — see `setPaused` — and this comes back down as soon as it
    // has.
    emit("togglePause")
  }

  @objc private func quitClicked() {
    guard let sink = sink else {
      // Nothing is listening: Dart never subscribed, or has already gone. The
      // clean shutdown is not available, but a Quit item that does nothing at
      // all is worse than an abrupt exit, so take the abrupt one.
      NSApp.terminate(nil)
      return
    }
    // The engine is stopped on the Dart side, which then calls `terminate`
    // back down. Doing it here instead would leave the last peer holding a
    // socket that still looks alive to it until its liveness timeout expires.
    sink("quit")
  }

  private func emit(_ command: String) { sink?(command) }

  func onListen(withArguments arguments: Any?,
                eventSink events: @escaping FlutterEventSink)
      -> FlutterError? {
    sink = events
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    sink = nil
    return nil
  }
}
