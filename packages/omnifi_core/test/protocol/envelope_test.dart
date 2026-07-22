import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
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

/// Builds raw envelope bytes with a hand-crafted `p` (payload) CBOR value,
/// bypassing [encodeEnvelope] so tests can smuggle in payload shapes that
/// [Envelope] itself could never produce (e.g. non-string map keys).
Uint8List encodeEnvelopeWithRawPayload(CborValue rawPayload) {
  return Uint8List.fromList(cbor.encode(CborValue({
    'v': omnifiProtocolVersion,
    't': MessageType.clipboardUpdate.wireName,
    'from': 'a' * 32,
    'mid': 'b' * 32,
    'ts': 1,
    'p': rawPayload,
  })));
}

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

  test('rejects CBOR that decodes to a non-map', () {
    // `utf8.encode('not cbor at all')` is well-formed CBOR: 0x6E is a
    // major-type-3 (text string) header declaring length 14, and 14 bytes
    // follow, so this decodes successfully to the string "ot cbor at all".
    // This exercises the `decoded is! Map` guard, not the CBOR parse-error
    // path (see the "rejects genuinely malformed CBOR bytes" test below).
    expect(() => decodeEnvelope(utf8.encode('not cbor at all')),
        throwsA(isA<EnvelopeError>()));
  });

  test('rejects genuinely malformed CBOR bytes', () {
    // 0x6E is a major-type-3 (text string) header declaring length 14, but
    // only 2 bytes follow. This is truncated CBOR that package:cbor cannot
    // parse at all, so it must be caught by decodeEnvelope's `catch` around
    // cbor.decode (verified empirically to throw a FormatException there),
    // not by any downstream type check.
    expect(() => decodeEnvelope(const [0x6E, 0x61, 0x62]),
        throwsA(isA<EnvelopeError>()));
  });

  test('rejects a payload map with non-string keys', () {
    // A hostile peer could send an integer key `0` alongside a string key
    // `"0"`. Both are distinct, valid CBOR map keys, but naively coercing
    // keys with `.toString()` would collide them, letting the
    // later-inserted entry silently win and potentially override a
    // legitimate field. decodeEnvelope must reject this outright instead
    // of coercing.
    final rawPayload = CborMap({
      const CborSmallInt(0): CborString('malicious'),
      CborString('0'): CborString('legit'),
    });
    expect(() => decodeEnvelope(encodeEnvelopeWithRawPayload(rawPayload)),
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
