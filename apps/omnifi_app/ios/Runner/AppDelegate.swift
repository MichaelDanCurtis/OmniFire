import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  /// Registers OmniFi's own plugins on the implicit engine.
  ///
  /// **Not in `didFinishLaunchingWithOptions`, and not via `window`.** This
  /// target is scene-based — `Info.plist` declares a `UIApplicationSceneManifest`
  /// pointing at `SceneDelegate` — so `UIApplicationDelegate.window` is nil
  /// when `didFinishLaunchingWithOptions` runs and there is no
  /// `FlutterViewController` to ask for a registrar yet. The engine is created
  /// later, by the storyboard's `FlutterViewController`, and this callback is
  /// the moment it exists.
  ///
  /// It is also the same callback that already registers the pub plugins, so
  /// OmniFi's plugins are registered on exactly the engine that runs `main()`,
  /// before the Dart entrypoint starts sending on any channel.
  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)

    // Deliberately fatal rather than guarded-and-skipped. Without these
    // registrations every channel answers `MissingPluginException`: the
    // identity is unreadable and unwritable and the clipboard is never
    // observed — an app that launches, looks entirely healthy, and does
    // nothing at all. If this ever stops vending a registrar it should stop
    // the app, not the sync.
    guard
      let secureStore = engineBridge.pluginRegistry.registrar(
        forPlugin: "SecureStorePlugin"),
      let clipboard = engineBridge.pluginRegistry.registrar(
        forPlugin: "ClipboardPlugin")
    else {
      fatalError(
        "the implicit Flutter engine vended no registrar; OmniFi's platform "
        + "channels cannot be registered.")
    }

    SecureStorePlugin.register(with: secureStore)
    ClipboardPlugin.register(with: clipboard)
  }
}
