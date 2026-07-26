import AppKit
import FlutterMacOS
import Foundation

/// Sleep, wake, screen lock and screen unlock, over `com.omnifi/power`.
///
/// Sleep and wake come from `NSWorkspace`'s own notification centre — they are
/// not posted to `NotificationCenter.default`. Lock and unlock have no public
/// API at all; `com.apple.screenIsLocked` / `com.apple.screenIsUnlocked` on the
/// distributed notification centre are the long-standing convention and the
/// only signal available to a non-privileged app.
class PowerPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private var sink: FlutterEventSink?

  static func register(with registrar: FlutterPluginRegistrar) {
    let instance = PowerPlugin()
    let events = FlutterEventChannel(
      name: "com.omnifi/power", binaryMessenger: registrar.messenger)
    events.setStreamHandler(instance)
  }

  func onListen(withArguments arguments: Any?,
                eventSink events: @escaping FlutterEventSink)
      -> FlutterError? {
    // Idempotent. `onListen` runs again whenever Dart re-subscribes, and
    // observers added twice deliver twice: the engine would redial once per
    // duplicate on every wake.
    removeObservers()
    sink = events

    let workspace = NSWorkspace.shared.notificationCenter
    workspace.addObserver(
      self, selector: #selector(onWake),
      name: NSWorkspace.didWakeNotification, object: nil)
    workspace.addObserver(
      self, selector: #selector(onSleep),
      name: NSWorkspace.willSleepNotification, object: nil)

    let distributed = DistributedNotificationCenter.default()
    distributed.addObserver(
      self, selector: #selector(onLock),
      name: NSNotification.Name("com.apple.screenIsLocked"), object: nil)
    distributed.addObserver(
      self, selector: #selector(onUnlock),
      name: NSNotification.Name("com.apple.screenIsUnlocked"), object: nil)
    return nil
  }

  @objc private func onWake() { sink?("wake") }
  @objc private func onSleep() { sink?("sleep") }
  @objc private func onLock() { sink?("lock") }
  @objc private func onUnlock() { sink?("unlock") }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    removeObservers()
    sink = nil
    return nil
  }

  private func removeObservers() {
    NSWorkspace.shared.notificationCenter.removeObserver(self)
    DistributedNotificationCenter.default().removeObserver(self)
  }
}
