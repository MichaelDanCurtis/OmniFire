import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return true
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

    super.applicationDidFinishLaunching(notification)
  }
}
