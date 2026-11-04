import 'dart:async';

import 'package:flutter/services.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// How one [ConnectionStatus] is named on the wire to `StatusItemPlugin`.
///
/// Written as an exhaustive switch rather than `status.name`, for two reasons.
/// A fifth [ConnectionStatus] has to be a compile error here — the Swift end
/// switches on these strings and its default case can only fall back to
/// something meaningless — and the wire format has to stay put when someone
/// renames a Dart enum constant, which `.name` would silently follow.
///
/// The four must stay distinct. They drive four *shapes* in the menu bar, and
/// two states sharing a name is a menu bar that claims a direct link while the
/// bytes are going through a relay.
String statusItemWireName(ConnectionStatus status) => switch (status) {
      ConnectionStatus.connectedDirect => 'connectedDirect',
      ConnectionStatus.connectedRelay => 'connectedRelay',
      ConnectionStatus.reconnecting => 'reconnecting',
      ConnectionStatus.offline => 'offline',
    };

/// The engine, wired to the macOS menu-bar item.
///
/// Pushes state down — the worst peer's [ConnectionStatus] and whether the
/// clipboard is paused — and routes the menu's three commands back up. The
/// menu itself is `NSMenu`, built natively: it is a status line, a checkbox
/// and two commands, and AppKit draws that faster and better than an embedded
/// Flutter surface would.
///
/// Constructed only on macOS. `com.omnifi/status_item` has a plugin behind it
/// nowhere else, and the guard lives in `main()` for the same reason
/// `PowerEvents`' does.
class StatusItemBridge {
  StatusItemBridge(this.engine);

  final OmniFiEngine engine;

  static const MethodChannel _methods =
      MethodChannel('com.omnifi/status_item');
  static const EventChannel _commands =
      EventChannel('com.omnifi/status_item/commands');

  StreamSubscription<ConnectionStatus>? _statusSub;
  StreamSubscription<Object?>? _commandSub;

  /// Subscribes to both directions and seeds the item with the state the
  /// engine is already in.
  ///
  /// The seed is not redundant. `engine.statuses` only fires on a *change*, so
  /// a machine that starts with no peers — the first launch, every launch
  /// before pairing — would otherwise leave the item on whatever the Swift
  /// side defaulted to, for as long as nothing ever connected.
  ///
  /// Idempotent: a second call attaches no second listener. Two subscriptions
  /// to the same broadcast stream would push every status down twice, which
  /// announces itself only as an icon that flickers.
  Future<void> start() async {
    _commandSub ??= _commands
        .receiveBroadcastStream()
        .listen((event) => unawaited(handleCommand(event)));
    _statusSub ??= engine.statuses.listen(
      (status) => unawaited(_pushStatus(status)),
    );
    await _pushStatus(engine.status);
    await pushPaused();
  }

  Future<void> dispose() async {
    await _statusSub?.cancel();
    await _commandSub?.cancel();
    _statusSub = null;
    _commandSub = null;
  }

  /// Republishes [ClipboardSync.isPaused].
  ///
  /// Public because the toggle is two-way: the engine pauses itself when the
  /// screen locks, with no user action and no stream to announce it, so
  /// `main()` re-pushes on every lock and unlock. A menu that tracked only the
  /// user's clicks would read "syncing" straight through a locked screen.
  Future<void> pushPaused() =>
      _invoke('setPaused', {'paused': engine.clipboard.isPaused});

  Future<void> showWindow() => _invoke('show');

  Future<void> hideWindow() => _invoke('hide');

  Future<void> _pushStatus(ConnectionStatus status) =>
      _invoke('setStatus', {'status': statusItemWireName(status)});

  /// Handles one command from the menu.
  ///
  /// Public so a test can drive it without a live event channel; the menu
  /// itself always arrives through [_commands].
  Future<void> handleCommand(Object? command) async {
    switch (command) {
      case 'openWindow':
        await showWindow();
      case 'togglePause':
        // Requested against `isPaused`, but reported back from `isPaused`
        // afterwards, and the two can differ. `ClipboardSync.isPaused` is the
        // OR of a user pause and a lock pause, so clearing the user's half
        // while the screen is locked leaves sync paused. Echoing the value we
        // asked for would clear the checkmark and claim syncing had resumed.
        engine.clipboard.setPaused(!engine.clipboard.isPaused);
        await pushPaused();
      case 'quit':
        // Awaited, and before the terminate below. Tearing the process down
        // first leaves the last peer holding a socket that still looks alive
        // to it until its own liveness timeout expires — minutes of a device
        // that reads "connected" and silently syncs nothing. If the teardown
        // throws there is no clean exit left to make, so the terminate is
        // skipped rather than the error swallowed.
        await engine.stop();
        await _invoke('terminate');
    }
  }

  /// One call down to `StatusItemPlugin`.
  ///
  /// [MissingPluginException] is tolerated and nothing else is. A build
  /// without the plugin should lose its menu bar, not fail to launch — and
  /// the failure is not silent in practice: an app whose platform channels
  /// went unregistered wholesale already dies visibly at
  /// `engine.start()`, which awaits `clipboard.start()` on the same
  /// registration. What is left after that is exactly the case this tolerates,
  /// a status item that is absent and obviously so. A `PlatformException`, by
  /// contrast, is the native side reporting that it tried and failed, and
  /// swallowing that would make a stalled item indistinguishable from a
  /// current one.
  Future<void> _invoke(String method, [Object? arguments]) async {
    try {
      await _methods.invokeMethod<void>(method, arguments);
    } on MissingPluginException {
      return;
    }
  }
}
