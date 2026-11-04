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
      // Remove-and-append, never replace in place. Frames reach the outbox
      // already sealed, and sealing assigns a monotonic counter the receiver
      // rejects out of order, so seal order must equal wire order. The
      // replacement was sealed last, so it belongs last: inheriting the
      // superseded entry's queue position would put a later-sealed frame on
      // the wire ahead of an earlier-sealed one and kill the session.
      OutboxEntry? superseded;
      for (final e in _entries) {
        if (e.collapseKey == collapseKey) {
          superseded = e;
          break;
        }
      }
      if (superseded != null) {
        _entries.remove(superseded);
        _byteLength -= superseded.frame.length;
      }
    }

    _entries.addLast(entry);
    _byteLength += entry.frame.length;
    _enforceBounds(protect: entry);
  }

  /// Evicts the oldest entries until both bounds are satisfied, never
  /// evicting [protect] -- the entry the current `add()` call just
  /// inserted or collapsed into.
  ///
  /// Termination is guaranteed: `add()` already rejects any single frame
  /// larger than the entire byte budget before mutating anything, so
  /// [protect] alone always fits within the cap. That means this loop can
  /// always either find a non-protected victim to evict, or the bounds are
  /// already satisfied and the loop exits. The `break` below is defensive
  /// only, so that a future change to that precondition degrades into a
  /// bounds violation rather than an infinite loop.
  void _enforceBounds({OutboxEntry? protect}) {
    while (_entries.length > maxOutboxFrames ||
        _byteLength > maxOutboxBytes) {
      OutboxEntry? victim;
      for (final e in _entries) {
        if (!identical(e, protect)) {
          victim = e;
          break;
        }
      }
      if (victim == null) break;
      _entries.remove(victim);
      _byteLength -= victim.frame.length;
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
