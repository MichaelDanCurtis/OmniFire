import 'package:flutter/services.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// The system clipboard, as [ClipboardWatcher].
///
/// Reads and writes go over `com.omnifi/clipboard`; the platform reports
/// changes on `com.omnifi/clipboard/changes` as
/// `{format: String, data: bytes, concealed: bool}`.
class PlatformClipboardWatcher implements ClipboardWatcher {
  static const MethodChannel _methods = MethodChannel('com.omnifi/clipboard');
  static const EventChannel _events =
      EventChannel('com.omnifi/clipboard/changes');

  /// Built once, not per access to [changes].
  ///
  /// [EventChannel.receiveBroadcastStream] sends a fresh `listen` to the
  /// platform on every call, and the plugin holds exactly one event sink — so
  /// a getter that rebuilt the stream each time would let a second subscriber
  /// silently replace the first subscriber's sink. Only one thing subscribes
  /// today ([ClipboardSync]), which is precisely why the failure would go
  /// unnoticed until something else did.
  late final Stream<ClipboardContent> _changes =
      _events.receiveBroadcastStream().map(_decode);

  @override
  Stream<ClipboardContent> get changes => _changes;

  static ClipboardContent _decode(Object? event) {
    final map = event as Map<Object?, Object?>;
    final data = map['data'];
    return ClipboardContent(
      format: map['format']! as String,
      // The standard codec hands `FlutterStandardTypedData(bytes:)` back as a
      // Uint8List already; the `List<int>` branch is for a platform that sends
      // a plain list instead, which the codec decodes as `List<Object?>`.
      data: data is Uint8List
          ? data
          : Uint8List.fromList((data! as List<Object?>).cast<int>()),
      // Absent means "the platform said nothing about concealment", which is
      // the ordinary case and must read as not concealed. Defaulting the other
      // way would make ClipboardSync drop every update.
      isConcealed: map['concealed'] as bool? ?? false,
    );
  }

  @override
  Future<void> write(ClipboardContent content) =>
      _methods.invokeMethod<void>('write', {
        'format': content.format,
        'data': content.data,
      });

  @override
  Future<void> start() => _methods.invokeMethod<void>('start');

  @override
  Future<void> stop() => _methods.invokeMethod<void>('stop');
}
