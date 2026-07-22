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
}
