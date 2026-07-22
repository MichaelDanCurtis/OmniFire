import 'dart:collection';
import 'dart:typed_data';

const int maxOutboxFrames = 50;
const int maxOutboxBytes = 5242880;

class OutboxEntry {
  OutboxEntry({required this.frame, this.collapseKey});
  final Uint8List frame;
  final String? collapseKey;
}

/// Per-peer send queue held while a peer is unreachable.
///
/// In-memory only by design: a restart should lose queued clipboard
/// updates rather than deliver yesterday's clipboard on next launch.
class Outbox {
  final ListQueue<OutboxEntry> _entries = ListQueue<OutboxEntry>();
  int _byteLength = 0;
  int _droppedCount = 0;

  int get length => _entries.length;
  int get byteLength => _byteLength;
  int get droppedCount => _droppedCount;

  void add(List<int> frame, {String? collapseKey}) {
    if (frame.length > maxOutboxBytes) {
      throw ArgumentError.value(
          frame.length, 'frame', 'exceeds the entire outbox byte cap');
    }
    final entry = OutboxEntry(
      frame: Uint8List.fromList(frame),
      collapseKey: collapseKey,
    );

    if (collapseKey != null) {
      final existing = _entries.toList();
      final index =
          existing.indexWhere((e) => e.collapseKey == collapseKey);
      if (index >= 0) {
        _byteLength -= existing[index].frame.length;
        existing[index] = entry;
        _byteLength += entry.frame.length;
        _entries
          ..clear()
          ..addAll(existing);
        _enforceBounds();
        return;
      }
    }

    _entries.addLast(entry);
    _byteLength += entry.frame.length;
    _enforceBounds();
  }

  void _enforceBounds() {
    while (_entries.length > maxOutboxFrames ||
        _byteLength > maxOutboxBytes) {
      final dropped = _entries.removeFirst();
      _byteLength -= dropped.frame.length;
      _droppedCount++;
    }
  }

  List<OutboxEntry> drain() {
    final out = _entries.toList();
    _entries.clear();
    _byteLength = 0;
    return out;
  }

  void clear() {
    _entries.clear();
    _byteLength = 0;
  }
}
