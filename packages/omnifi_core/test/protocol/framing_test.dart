import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('encodes a 4-byte big-endian length prefix', () {
    final frame = encodeFrame(utf8.encode('hi'));
    expect(frame.sublist(0, 4), [0, 0, 0, 2]);
    expect(utf8.decode(frame.sublist(4)), 'hi');
  });

  test('rejects a payload over the cap', () {
    expect(() => encodeFrame(Uint8List(maxFrameBytes + 1)),
        throwsA(isA<FrameTooLargeError>()));
  });

  test('decodes a single whole frame', () {
    final d = FrameDecoder();
    final out = d.addChunk(encodeFrame(utf8.encode('one'))).toList();
    expect(out.length, 1);
    expect(utf8.decode(out.single), 'one');
  });

  test('decodes two frames arriving in one chunk', () {
    final d = FrameDecoder();
    final chunk = [
      ...encodeFrame(utf8.encode('a')),
      ...encodeFrame(utf8.encode('bb')),
    ];
    final out = d.addChunk(chunk).toList();
    expect(out.map(utf8.decode), ['a', 'bb']);
  });

  test('reassembles a frame split across chunks', () {
    final d = FrameDecoder();
    final frame = encodeFrame(utf8.encode('split me'));
    expect(d.addChunk(frame.sublist(0, 3)).toList(), isEmpty);
    expect(d.addChunk(frame.sublist(3, 7)).toList(), isEmpty);
    final out = d.addChunk(frame.sublist(7)).toList();
    expect(out.map(utf8.decode), ['split me']);
  });

  test('handles a chunk boundary inside the length prefix', () {
    final d = FrameDecoder();
    final frame = encodeFrame(utf8.encode('xy'));
    expect(d.addChunk(frame.sublist(0, 2)).toList(), isEmpty);
    expect(d.addChunk(frame.sublist(2)).map(utf8.decode), ['xy']);
  });

  test('emits an empty payload frame', () {
    final d = FrameDecoder();
    expect(d.addChunk(encodeFrame(const [])).single, isEmpty);
  });

  test('rejects an oversized declared length', () {
    final d = FrameDecoder();
    final header = Uint8List(4);
    ByteData.view(header.buffer).setUint32(0, maxFrameBytes + 1);
    expect(() => d.addChunk(header).toList(),
        throwsA(isA<FrameTooLargeError>()));
  });

  test('reset discards a partial frame', () {
    final d = FrameDecoder();
    d.addChunk(encodeFrame(utf8.encode('partial')).sublist(0, 5)).toList();
    d.reset();
    final out = d.addChunk(encodeFrame(utf8.encode('fresh'))).toList();
    expect(out.map(utf8.decode), ['fresh']);
  });

  // Fix 1 regression test: an oversized declared length must leave the
  // decoder's buffer fully cleared, even when a valid frame preceded it in
  // the same chunk. Otherwise the still-buffered bytes (including the
  // already-delivered frame) are re-parsed and re-emitted on the next call.
  test('clears the buffer before throwing so a later chunk is not '
      'corrupted by a stale frame', () {
    final d = FrameDecoder();
    final good = encodeFrame(utf8.encode('ok'));
    final badHeader = Uint8List(4);
    ByteData.view(badHeader.buffer).setUint32(0, maxFrameBytes + 1);
    final chunk = Uint8List.fromList([...good, ...badHeader]);

    // One chunk: a valid frame followed by a header declaring an oversized
    // length. The valid frame is decoded before the oversized length is
    // detected and the error is thrown.
    final firstDecoded = <String>[];
    expect(() {
      for (final f in d.addChunk(chunk)) {
        firstDecoded.add(utf8.decode(f));
      }
    }, throwsA(isA<FrameTooLargeError>()));

    // Feed a fresh, unrelated valid frame. If the buffer was not cleared
    // before the throw above, the decoder is still desynchronised: it will
    // re-parse the stale 'ok' frame (a duplicate) and/or re-throw on the
    // still-buffered oversized header instead of cleanly emitting only the
    // new frame.
    final fresh = encodeFrame(utf8.encode('fresh'));
    final secondDecoded = <String>[];
    FrameTooLargeError? secondError;
    try {
      for (final f in d.addChunk(fresh)) {
        secondDecoded.add(utf8.decode(f));
      }
    } on FrameTooLargeError catch (e) {
      secondError = e;
    }
    expect(secondError, isNull,
        reason: 'decoder must not still be desynchronised after the throw');
    expect(secondDecoded, ['fresh'],
        reason: 'only the new frame may be emitted — no duplicate of "ok"');
  });

  // Fix 2 regression test: addChunk's buffering side effect must happen
  // eagerly on call, not only when the returned Iterable is iterated.
  test('buffers a chunk even when the returned frames are never iterated',
      () {
    final d = FrameDecoder();
    final frame = encodeFrame(utf8.encode('eager'));

    // Bare statement: result intentionally discarded, never iterated.
    d.addChunk(frame.sublist(0, 3));

    final out = d.addChunk(frame.sublist(3)).toList();
    expect(out.map(utf8.decode), ['eager']);
  });
}
