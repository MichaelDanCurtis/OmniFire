import Flutter
import Foundation
import UIKit

/// `UIPasteboard`, bridged to `com.omnifi/clipboard`.
///
/// **This plugin only ever sees the clipboard while the app is in front of the
/// user, and that is the design.** iOS suspends the process within seconds of
/// backgrounding; `LifecycleBridge` stops the engine before that happens, so
/// `stop` arrives while there is still a run loop to service it.
///
/// Three iOS facts shape everything below.
///
///  1. `UIPasteboard.changedNotification` is **not** the whole story. Since
///     iOS 10 the system stops posting it for changes made by other apps, and
///     it is not delivered at all while this app is suspended — so a copy made
///     in Safari and then a switch back to OmniFi produces no notification.
///     `changeCount` is still monotonic across all of that, so becoming active
///     is the second trigger, and the counter is what decides whether anything
///     actually changed.
///  2. Reading the pasteboard's *contents* on iOS 16+ shows the user a paste
///     permission prompt. That is accepted, not worked around — no
///     `detectPatterns`, no sneaking around it. It is also why nothing is read
///     unless `changeCount` says there is something new: `changeCount`,
///     `hasStrings`, `hasImages` and `contains(pasteboardTypes:)` are all
///     prompt-free, so an activation with an unchanged clipboard costs the
///     user nothing.
///  3. `lastChangeCount` is seeded from the current count at construction, so
///     whatever is already on the clipboard at launch is never emitted and
///     never read. Whatever the user copied before starting OmniFi was not
///     copied in order to sync it — and prompting for it on first launch would
///     be the worst possible introduction.
class ClipboardPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private var sink: FlutterEventSink?
  private var changeObserver: NSObjectProtocol?
  private var activeObserver: NSObjectProtocol?

  /// See fact 3 above.
  private var lastChangeCount: Int = UIPasteboard.general.changeCount

  /// The exact payload of the most recent `write`, held until the pasteboard
  /// change that write raised has been seen and swallowed.
  ///
  /// **Observed, not assumed.** The macOS plugin suppresses its own writes by
  /// re-reading `changeCount` immediately after writing and claiming it;
  /// `NSPasteboard` is synchronous, so that holds. `UIPasteboard` is not — a
  /// simulator run showed the count read straight after `pb.string = ...`
  /// still being the pre-write value, and the resulting
  /// `changedNotification` therefore emitting our own write straight back as
  /// a fresh local copy 15 ms later.
  ///
  /// That echo is not cosmetic. `ClipboardSync` drops it by comparing against
  /// `_lastAppliedHash`, which is a **single slot**: if the user copies
  /// something of their own in the window between our write and its echo,
  /// that slot has already moved on, and the echo is then re-broadcast — so
  /// the content the peer sent a moment ago clobbers what the user just
  /// copied, on every device in the mesh.
  private var lastWritten: (format: String, data: Data)?

  /// Password managers mark a parked secret with this type. It is a macOS
  /// convention that the cross-platform managers also apply on iOS, and
  /// `contains(pasteboardTypes:)` answers it without reading the payload and
  /// without prompting — so a concealed entry costs neither a prompt nor a
  /// copy of the secret.
  private static let concealedType = "org.nspasteboard.ConcealedType"

  static func register(with registrar: FlutterPluginRegistrar) {
    let instance = ClipboardPlugin()
    let methods = FlutterMethodChannel(
      name: "com.omnifi/clipboard",
      binaryMessenger: registrar.messenger())
    registrar.addMethodCallDelegate(instance, channel: methods)
    let events = FlutterEventChannel(
      name: "com.omnifi/clipboard/changes",
      binaryMessenger: registrar.messenger())
    events.setStreamHandler(instance)
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "start":
      startObserving()
      result(nil)
    case "stop":
      stopObserving()
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
      // Validated before the pasteboard is touched. Writing an unsupported
      // format would otherwise replace whatever the user had on their
      // clipboard in order to accomplish nothing.
      if let error = write(format: format, data: data.data) {
        result(error)
        return
      }
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func startObserving() {
    // Re-entrant: `start` runs again on every foreground, and duplicate
    // observers would mean duplicate events for one copy.
    stopObserving()
    let center = NotificationCenter.default
    changeObserver = center.addObserver(
      forName: UIPasteboard.changedNotification,
      object: nil, queue: .main
    ) { [weak self] _ in self?.emitIfChanged() }
    // The one that actually fires for a copy made in another app. See fact 1.
    activeObserver = center.addObserver(
      forName: UIApplication.didBecomeActiveNotification,
      object: nil, queue: .main
    ) { [weak self] _ in self?.emitIfChanged() }
    // And once for this foreground, because `start` is itself called from the
    // resume path: the app is already active by then, so waiting for the next
    // `didBecomeActive` would miss this foreground entirely.
    //
    // **Deferred to the next main-queue turn, and that is not a style
    // choice.** Reading pasteboard *contents* on iOS 16+ raises the paste
    // permission alert, and the read blocks the calling thread until the user
    // answers it. The calling thread here is the platform thread, and this
    // method is running inside the `start` platform-channel call — so a
    // direct call would leave `ClipboardWatcher.start()` un-returned, and
    // therefore `ClipboardSync.start()`, and therefore `engine.start()`,
    // until the alert is dismissed. Observed exactly that on a simulator:
    // after backgrounding with a copy made elsewhere, the engine never
    // restarted, the LAN listener never rebound and no peer reconnected,
    // all waiting behind a modal. Letting `start` return first means the
    // mesh comes back up and the prompt is answered whenever the user gets
    // to it.
    DispatchQueue.main.async { [weak self] in self?.emitIfChanged() }
  }

  private func stopObserving() {
    let center = NotificationCenter.default
    if let changeObserver = changeObserver {
      center.removeObserver(changeObserver)
    }
    if let activeObserver = activeObserver {
      center.removeObserver(activeObserver)
    }
    changeObserver = nil
    activeObserver = nil
  }

  /// Returns nil on success, or the error to hand back to Dart.
  private func write(format: String, data: Data) -> FlutterError? {
    let pb = UIPasteboard.general
    switch format {
    case "text":
      guard let text = String(data: data, encoding: .utf8) else {
        return FlutterError(code: "bad_payload",
                            message: "text payload is not valid UTF-8",
                            details: nil)
      }
      // Recorded **before** the mutation, not after. Measured, not guessed:
      // with the assignment after `pb.string = text` the echo still came
      // through, because `UIPasteboard` raises `changedNotification` during
      // the write itself and the observer had already run and found no
      // record by the time one was made. Setting it first costs nothing —
      // an unchanged clipboard emits nothing anyway, and a write that fails
      // leaves behind a record that only ever suppresses a change to
      // byte-identical content, which is not a change.
      lastWritten = ("text", data)
      pb.string = text
    case "png":
      lastWritten = ("png", data)
      pb.setData(data, forPasteboardType: "public.png")
    default:
      return FlutterError(code: "unsupported_format",
                          message: "no pasteboard mapping for '\(format)'",
                          details: nil)
    }
    // The cheap half of the echo defence, kept because it is free and it does
    // hold whenever the count has settled by the time we read it back. It is
    // `lastWritten` above that actually holds on iOS.
    lastChangeCount = pb.changeCount
    return nil
  }

  private func emitIfChanged() {
    let pb = UIPasteboard.general
    let changeCount = pb.changeCount
    guard changeCount != lastChangeCount else { return }
    // **Not** recorded before the sink check, unlike the macOS plugin. There,
    // a change seen with nobody listening is safely written off because a
    // 500 ms poll will notice the next one. Here there is no poll, and the
    // gap is not hypothetical: `ClipboardSync.start()` calls `start` and
    // *then* subscribes, so the copy the user made in another app
    // immediately before switching back to OmniFi lands precisely in it.
    // Consuming the count there would discard the single most important
    // event this plugin exists to deliver. Left pending instead, and
    // [onListen] re-checks the moment a sink appears.
    guard let sink = sink else { return }
    lastChangeCount = changeCount

    // Prompt-free, and checked first: if this is a password manager parking a
    // secret, we must not read it. Reported anyway so ClipboardSync can count
    // the skip, but with an empty payload — the bytes never leave the
    // pasteboard server, and no paste prompt is raised for content that was
    // going to be dropped.
    if pb.contains(pasteboardTypes: [ClipboardPlugin.concealedType]) {
      sink(["format": "text",
            "data": FlutterStandardTypedData(bytes: Data()),
            "concealed": true])
      return
    }

    // `hasImages` / `hasStrings` are the documented existence checks and do
    // not prompt; only the reads below do. Images first: an image on the
    // pasteboard usually also carries a text representation (a filename, a
    // URL), and the image is what was copied.
    //
    // Anything that is neither — a file promise, a custom UTI — produces no
    // payload and no event: `supportedClipboardFormats` is {text, png} and
    // there is nothing useful to send.
    let payload: (format: String, data: Data)?
    if pb.hasImages {
      // The raw PNG bytes in preference to `UIImage.pngData()`, which would
      // decode and re-encode: that costs work, and it changes the bytes, so
      // the echo check below could never match a PNG we had written
      // ourselves. `UIImage` remains the fallback for an image that is on the
      // pasteboard in some other encoding.
      if let png = pb.data(forPasteboardType: "public.png") {
        payload = ("png", png)
      } else if let image = pb.image, let png = image.pngData() {
        payload = ("png", png)
      } else {
        payload = nil
      }
    } else if pb.hasStrings, let text = pb.string {
      payload = ("text", Data(text.utf8))
    } else {
      payload = nil
    }
    // Nothing readable — an unsupported type, or the user answering "Don't
    // Allow Paste", which makes the read return nil. The count has already
    // been consumed above and that is deliberate: retrying on every
    // activation would re-prompt for content the user has just declined to
    // share. One prompt per copy, not one per foreground.
    guard let payload = payload else { return }

    // Our own write coming back. Swallowed exactly once: a genuine copy of
    // byte-identical content is a no-op anyway, so consuming the record here
    // cannot lose a real change, and anything that differs falls straight
    // through.
    if let written = lastWritten,
       written.format == payload.format, written.data == payload.data {
      lastWritten = nil
      return
    }
    lastWritten = nil

    sink(["format": payload.format,
          "data": FlutterStandardTypedData(bytes: payload.data),
          "concealed": false])
  }

  func onListen(withArguments arguments: Any?,
                eventSink events: @escaping FlutterEventSink)
      -> FlutterError? {
    sink = events
    // Drains whatever [emitIfChanged] had to leave pending for want of a
    // sink. Gated on actually observing, so a subscriber that attaches
    // before `start` — or after `stop` — does not get handed the clipboard's
    // pre-existing contents, which is the launch-time behaviour fact 3
    // exists to prevent. Deferred for the same reason as in
    // [startObserving]: this runs inside the event channel's `listen`.
    if changeObserver != nil {
      DispatchQueue.main.async { [weak self] in self?.emitIfChanged() }
    }
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    sink = nil
    return nil
  }
}
