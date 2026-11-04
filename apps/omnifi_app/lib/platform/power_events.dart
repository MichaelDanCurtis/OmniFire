import 'package:flutter/services.dart';

/// Sleep, wake, lock and unlock notifications from the host OS.
///
/// Wake matters because macOS suspends sockets on sleep without notifying the
/// peer: the socket stays "connected" from this side and every write into it
/// vanishes. Without this signal the app sits on a dead link until some
/// timeout eventually notices. Flutter's own `didChangeAppLifecycleState` is
/// not a substitute — it reports app foreground/background, and a machine
/// going to sleep with the app frontmost produces nothing at all.
///
/// Emits `'sleep'`, `'wake'`, `'lock'` and `'unlock'`.
class PowerEvents {
  static const EventChannel _events = EventChannel('com.omnifi/power');

  /// Built once. See [PlatformClipboardWatcher.changes] for why.
  late final Stream<String> _stream =
      _events.receiveBroadcastStream().map((e) => e! as String);

  Stream<String> get events => _stream;
}
