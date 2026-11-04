import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  /// False, because OmniFi is an agent and not a window.
  ///
  /// With `LSUIElement` set there is no dock icon to reopen from, so quitting
  /// on the last window close would make the close button a Quit button — the
  /// clipboard stops syncing and the only thing that said so has just gone.
  /// Closing the window now hides it; the menu bar is what the app *is*.
  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return false
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }

  /// Registers OmniFi's own plugins.
  ///
  /// This runs on the main thread before the run loop starts spinning, and
  /// platform-channel messages from Dart are delivered on that same thread, so
  /// no `read`/`start` from `main()` can arrive before registration finishes.
  /// (Pub plugins are registered separately, by `RegisterGeneratedPlugins` in
  /// `MainFlutterWindow.awakeFromNib`.)
  override func applicationDidFinishLaunching(_ notification: Notification) {
    // Deliberately fatal rather than guarded-and-skipped. Without these
    // registrations every channel answers `MissingPluginException`, the
    // identity is unreadable and unwritable, and the clipboard is never
    // polled — an app that launches, looks healthy and does nothing at all.
    // If this window shape ever changes, it should stop the app, not the sync.
    guard let controller =
      mainFlutterWindow?.contentViewController as? FlutterViewController
    else {
      fatalError(
        "mainFlutterWindow has no FlutterViewController; OmniFi's platform "
        + "channels cannot be registered.")
    }

    SecureStorePlugin.register(
      with: controller.registrar(forPlugin: "SecureStorePlugin"))
    ClipboardPlugin.register(
      with: controller.registrar(forPlugin: "ClipboardPlugin"))
    PowerPlugin.register(
      with: controller.registrar(forPlugin: "PowerPlugin"))
    // Builds the menu-bar item as a side effect of registering, so the item is
    // in the bar before Dart has finished booting the engine. An agent whose
    // icon appears a second or two after login looks like one that failed to
    // start.
    StatusItemPlugin.register(
      with: controller.registrar(forPlugin: "StatusItemPlugin"))

    super.applicationDidFinishLaunching(notification)

    // Flutter's embedder puts `mainFlutterWindow` on screen at launch. Under
    // `LSUIElement` that is a window nobody asked for, flashed up on every
    // login, from an app that is supposed to be invisible until it is wanted.
    // Ordered out after `super`, which is where the embedder's own show
    // happens.
    mainFlutterWindow?.orderOut(nil)
  }
}
