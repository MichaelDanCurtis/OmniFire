import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

Envelope sample({MessageType type = MessageType.clipboardUpdate}) => Envelope(
      version: omnifiProtocolVersion,
      type: type,
      senderDeviceId: 'a' * 32,
      messageId: 'b' * 32,
      timestampMs: 1753200000000,
      payload: {'k': 'v'},
    );

void main() {
  test('round-trips an envelope', () {
    final decoded = decodeEnvelope(encodeEnvelope(sample()));
    expect(decoded.version, omnifiProtocolVersion);
    expect(decoded.type, MessageType.clipboardUpdate);
    expect(decoded.senderDeviceId, 'a' * 32);
    expect(decoded.messageId, 'b' * 32);
    expect(decoded.timestampMs, 1753200000000);
    expect(decoded.payload['k'], 'v');
  });

  test('round-trips every message type', () {
    for (final t in MessageType.values) {
      expect(decodeEnvelope(encodeEnvelope(sample(type: t))).type, t);
    }
  });

  test('message type wire names are unique and stable', () {
    final names = MessageType.values.map((t) => t.wireName).toList();
    expect(names.toSet().length, names.length);
    expect(MessageType.clipboardUpdate.wireName, 'clipboard_update');
    expect(MessageType.heartbeat.wireName, 'heartbeat');
  });

  test('rejects an unknown protocol version', () {
    final bad = Envelope(
      version: 99,
      type: MessageType.heartbeat,
      senderDeviceId: 'a' * 32,
      messageId: 'b' * 32,
      timestampMs: 1,
      payload: const {},
    );
    expect(() => decodeEnvelope(encodeEnvelope(bad)),
        throwsA(isA<EnvelopeError>()));
  });

  test('rejects malformed bytes', () {
    expect(() => decodeEnvelope(utf8.encode('not cbor at all')),
        throwsA(isA<EnvelopeError>()));
  });

  test('clipboard payload round-trips text', () {
    final p = ClipboardPayload(
      format: 'text',
      data: Uint8List.fromList(utf8.encode('copied')),
      timestampMs: 1753200000000,
      contentHash: 'deadbeef',
    );
    final back = ClipboardPayload.fromMap(p.toMap());
    expect(back.format, 'text');
    expect(utf8.decode(back.data), 'copied');
    expect(back.contentHash, 'deadbeef');
    expect(back.timestampMs, 1753200000000);
  });

  test('clipboard payload survives an envelope round-trip', () {
    final p = ClipboardPayload(
      format: 'png',
      data: Uint8List.fromList([137, 80, 78, 71]),
      timestampMs: 5,
      contentHash: 'abc123',
    );
    final e = Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'a' * 32,
      messageId: 'b' * 32,
      timestampMs: 5,
      payload: p.toMap(),
    );
    final back =
        ClipboardPayload.fromMap(decodeEnvelope(encodeEnvelope(e)).payload);
    expect(back.data, [137, 80, 78, 71]);
    expect(back.format, 'png');
  });

  test('clipboard payload rejects an unknown format', () {
    expect(
      () => ClipboardPayload.fromMap({
        'format': 'video',
        'data': <int>[],
        'ts': 1,
        'hash': 'x',
      }),
      throwsA(isA<EnvelopeError>()),
    );
  });
}
