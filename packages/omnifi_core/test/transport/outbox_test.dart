import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('drains in insertion order', () {
    final o = Outbox();
    o.add(utf8.encode('one'));
    o.add(utf8.encode('two'));
    expect(o.drain().map((e) => utf8.decode(e.frame)), ['one', 'two']);
  });

  test('drain empties the outbox', () {
    final o = Outbox();
    o.add(utf8.encode('x'));
    o.drain();
    expect(o.length, 0);
    expect(o.drain(), isEmpty);
  });

  test('tracks byte length', () {
    final o = Outbox();
    o.add(Uint8List(100));
    o.add(Uint8List(50));
    expect(o.byteLength, 150);
  });

  test('collapses entries sharing a key, keeping the newest', () {
    final o = Outbox();
    o.add(utf8.encode('stale'), collapseKey: 'clipboard');
    o.add(utf8.encode('fresh'), collapseKey: 'clipboard');
    final drained = o.drain();
    expect(drained.length, 1);
    expect(utf8.decode(drained.single.frame), 'fresh');
  });

  test('collapse preserves the original queue position', () {
    final o = Outbox();
    o.add(utf8.encode('first'), collapseKey: 'clipboard');
    o.add(utf8.encode('second'));
    o.add(utf8.encode('third'), collapseKey: 'clipboard');
    expect(o.drain().map((e) => utf8.decode(e.frame)), ['third', 'second']);
  });

  test('entries without a key never collapse', () {
    final o = Outbox();
    o.add(utf8.encode('a'));
    o.add(utf8.encode('a'));
    expect(o.length, 2);
  });

  test('drops the oldest entry past the frame cap', () {
    final o = Outbox();
    for (var i = 0; i < maxOutboxFrames + 3; i++) {
      o.add(utf8.encode('frame$i'));
    }
    expect(o.length, maxOutboxFrames);
    expect(o.droppedCount, 3);
    final drained = o.drain();
    expect(utf8.decode(drained.first.frame), 'frame3');
  });

  test('drops the oldest entries past the byte cap', () {
    final o = Outbox();
    final oneMeg = Uint8List(1048576);
    for (var i = 0; i < 7; i++) {
      o.add(oneMeg);
    }
    expect(o.byteLength, lessThanOrEqualTo(maxOutboxBytes));
    expect(o.droppedCount, greaterThan(0));
  });

  test('rejects a frame larger than the entire byte cap', () {
    final o = Outbox();
    expect(() => o.add(Uint8List(maxOutboxBytes + 1)),
        throwsA(isA<ArgumentError>()));
  });

  test('a collapse replacement is never evicted by its own bounds check', () {
    // Reviewer's confirmed repro: A is queued at the front under key 'k'.
    // B fills the outbox to exactly the byte cap. The third add() replaces
    // A in place with a larger frame under the same key, pushing the total
    // over the cap. The eviction loop must not evict the entry add() was
    // just asked to queue (the collapsed replacement) -- it must evict the
    // older, unrelated frame B instead.
    final o = Outbox();
    o.add(Uint8List(1), collapseKey: 'k'); // A, at the front
    o.add(Uint8List(maxOutboxBytes - 1)); // B, fills to exactly the cap
    o.add(Uint8List(maxOutboxBytes), collapseKey: 'k'); // replaces A in place

    final drained = o.drain();
    expect(drained.length, 1);
    expect(drained.single.frame.length, maxOutboxBytes);
    expect(o.droppedCount, 1);
  });

  test('a plain (non-collapsed) append is also protected from eviction', () {
    final o = Outbox();
    // Fill the queue to exactly the byte cap.
    o.add(Uint8List(maxOutboxBytes - 1));
    // Now append one more large frame with no collapse key; this pushes the
    // total over the cap and must trigger eviction of the older frame, not
    // the just-appended one.
    o.add(Uint8List(maxOutboxBytes));

    final drained = o.drain();
    expect(drained.length, 1);
    expect(drained.single.frame.length, maxOutboxBytes);
  });

  test('clear resets contents but not the dropped counter', () {
    final o = Outbox();
    for (var i = 0; i < maxOutboxFrames + 1; i++) {
      o.add(utf8.encode('f$i'));
    }
    final dropped = o.droppedCount;
    o.clear();
    expect(o.length, 0);
    expect(o.byteLength, 0);
    expect(o.droppedCount, dropped);
  });
}
