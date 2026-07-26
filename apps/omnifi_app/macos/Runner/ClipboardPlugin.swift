import AppKit
import FlutterMacOS
import Foundation

/// The system pasteboard, bridged to `com.omnifi/clipboard`.
///
/// macOS has no clipboard-change notification — no `NSNotification`, no
/// callback, nothing. `NSPasteboard.changeCount` incrementing is the only
/// signal there is, so polling it is the standard approach and the one this
/// takes.
///
/// **Interval: 500 ms.** Reading `changeCount` is a cheap round trip to
/// `pasteboardd` and nothing else happens on a tick where it has not moved,
/// so the cost is one short wakeup twice a second. Halving it to 250 ms
/// doubles the wakeups to shave 250 ms off a sync that already pays a network
/// round trip; doubling it to 1 s is enough delay to be felt when you copy on
/// one machine and immediately reach for paste on the other. The timer is
/// given a 100 ms tolerance so the OS can coalesce it with other work rather
/// than waking the CPU on an exact schedule, and runs in `.common` run-loop
/// mode so it keeps firing while a menu is tracking — which is exactly when
/// "Copy" tends to be clicked.
class ClipboardPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private var sink: FlutterEventSink?
  private var timer: Timer?

  /// Seeded from the current count so the clipboard's *existing* contents are
  /// never emitted at launch. Whatever the user copied before starting OmniFi
  /// was not copied with the intent of syncing it.
  private var lastChangeCount: Int = NSPasteboard.general.changeCount

  private static let pollInterval: TimeInterval = 0.5
  private static let pollTolerance: TimeInterval = 0.1

  /// Password managers mark entries with this type; we must never sync them.
  private static let concealedType =
    NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

  static func register(with registrar: FlutterPluginRegistrar) {
    let instance = ClipboardPlugin()
    let methods = FlutterMethodChannel(
      name: "com.omnifi/clipboard", binaryMessenger: registrar.messenger)
    registrar.addMethodCallDelegate(instance, channel: methods)
    let events = FlutterEventChannel(
      name: "com.omnifi/clipboard/changes",
      binaryMessenger: registrar.messenger)
    events.setStreamHandler(instance)
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "start":
      startPolling()
      result(nil)
    case "stop":
      timer?.invalidate()
      timer = nil
      result(nil)
    case "write":
      guard let args = call.arguments as? [String: Any],
            let format = args["format"] as? String,
            let data = args["data"] as? FlutterStandardTypedData else {
        result(FlutterError(code: "bad_args",
                            message: "format and data required",
                            details: nil))
        return
      }
      // Validated before anything is cleared. `clearContents()` is what makes
      // a pasteboard write possible, and it is also what destroys whatever the
      // user had on the clipboard: doing it first and then discovering the
      // format is unsupported would wipe their clipboard for nothing.
      guard let error = write(format: format, data: data.data) else {
        result(nil)
        return
      }
      result(error)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  /// Returns nil on success, or the error to hand back to Dart.
  private func write(format: String, data: Data) -> FlutterError? {
    let pb = NSPasteboard.general
    switch format {
    case "text":
      guard let text = String(data: data, encoding: .utf8) else {
        return FlutterError(code: "bad_payload",
                            message: "text payload is not valid UTF-8",
                            details: nil)
      }
      pb.clearContents()
      pb.setString(text, forType: .string)
    case "png":
      pb.clearContents()
      pb.setData(data, forType: .png)
    default:
      return FlutterError(code: "unsupported_format",
                          message: "no pasteboard mapping for '\(format)'",
                          details: nil)
    }
    // Claim the change we just made so the next poll does not read our own
    // write back as a fresh local copy and bounce it to the peer that sent it.
    lastChangeCount = pb.changeCount
    return nil
  }

  private func startPolling() {
    timer?.invalidate()
    let timer = Timer(timeInterval: ClipboardPlugin.pollInterval,
                      repeats: true) { [weak self] _ in
      self?.poll()
    }
    timer.tolerance = ClipboardPlugin.pollTolerance
    // `.common`, not the default mode: a timer in the default mode stops
    // firing while a menu or a window resize is tracking the run loop, which
    // is precisely when a "Copy" happens.
    RunLoop.main.add(timer, forMode: .common)
    self.timer = timer
  }

  private func poll() {
    let pb = NSPasteboard.general
    let changeCount = pb.changeCount
    guard changeCount != lastChangeCount else { return }
    // Recorded before the early return below, so a change seen while nothing
    // is listening is a change we have already accounted for rather than one
    // that gets emitted late.
    lastChangeCount = changeCount
    guard let sink = sink else { return }

    let concealed = pb.types?.contains(ClipboardPlugin.concealedType) ?? false

    if concealed {
      // Reported, so the skip is countable, but **the bytes are not read**.
      // This is a password manager telling us it has parked a secret on the
      // clipboard for a few seconds. ClipboardSync drops concealed content
      // without looking at `data`, so copying that secret across the platform
      // channel into the Dart heap would buy nothing and risk everything.
      sink(["format": "text",
            "data": FlutterStandardTypedData(bytes: Data()),
            "concealed": true])
      return
    }

    // PNG first: an image on the pasteboard usually also carries a text
    // representation (a filename, a URL), and the image is what was copied.
    if let png = pb.data(forType: .png) {
      sink(["format": "png",
            "data": FlutterStandardTypedData(bytes: png),
            "concealed": false])
    } else if let text = pb.string(forType: .string) {
      sink(["format": "text",
            "data": FlutterStandardTypedData(bytes: Data(text.utf8)),
            "concealed": false])
    }
    // Anything else — a file promise, RTF only, a custom type — is silently
    // ignored: `supportedClipboardFormats` is {text, png} and there is nothing
    // useful to send.
  }

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
