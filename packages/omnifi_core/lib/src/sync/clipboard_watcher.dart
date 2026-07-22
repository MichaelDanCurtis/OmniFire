import 'dart:async';
import 'dart:typed_data';

class ClipboardContent {
  ClipboardContent({
    required this.format,
    required this.data,
    required this.isConcealed,
  });

  /// One of the values in `supportedClipboardFormats`.
  final String format;
  final Uint8List data;

  /// True when the source marked the content as transient/secret, e.g.
  /// macOS `org.nspasteboard.ConcealedType` or the Windows
  /// `ExcludeClipboardContentFromMonitorProcessing` format.
  final bool isConcealed;
}

/// Platform clipboard access. Implementations live in the Flutter app.
abstract interface class ClipboardWatcher {
  Stream<ClipboardContent> get changes;
  Future<void> write(ClipboardContent content);
  Future<void> start();
  Future<void> stop();
}

/// Headless watcher for tests and integration harnesses.
class FakeClipboardWatcher implements ClipboardWatcher {
  final StreamController<ClipboardContent> _changes =
      StreamController<ClipboardContent>.broadcast();

  ClipboardContent? current;

  @override
  Stream<ClipboardContent> get changes => _changes.stream;

  /// Simulates the platform reporting a clipboard change.
  void emit(ClipboardContent content) {
    current = content;
    _changes.add(content);
  }

  @override
  Future<void> write(ClipboardContent content) async {
    current = content;
  }

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {
    await _changes.close();
  }
}
