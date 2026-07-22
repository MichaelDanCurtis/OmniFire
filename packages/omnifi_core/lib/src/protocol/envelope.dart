import 'dart:typed_data';

import 'package:cbor/cbor.dart';

import '../version.dart';
import 'messages.dart';

class EnvelopeError implements Exception {
  const EnvelopeError(this.reason);
  final String reason;
  @override
  String toString() => 'EnvelopeError: $reason';
}

class Envelope {
  const Envelope({
    required this.version,
    required this.type,
    required this.senderDeviceId,
    required this.messageId,
    required this.timestampMs,
    required this.payload,
  });

  final int version;
  final MessageType type;
  final String senderDeviceId;
  final String messageId;
  final int timestampMs;
  final Map<String, Object?> payload;
}

Uint8List encodeEnvelope(Envelope e) {
  return Uint8List.fromList(cbor.encode(CborValue({
    'v': e.version,
    't': e.type.wireName,
    'from': e.senderDeviceId,
    'mid': e.messageId,
    'ts': e.timestampMs,
    'p': e.payload,
  })));
}

Envelope decodeEnvelope(List<int> bytes) {
  final Object? decoded;
  try {
    decoded = cbor.decode(bytes).toObject();
  } catch (_) {
    throw const EnvelopeError('payload is not valid CBOR');
  }
  if (decoded is! Map) {
    throw const EnvelopeError('envelope is not a map');
  }

  final version = decoded['v'];
  if (version is! int) {
    throw const EnvelopeError('missing or malformed version');
  }
  if (version != omnifiProtocolVersion) {
    throw EnvelopeError('unsupported protocol version: $version');
  }

  final type = decoded['t'];
  final from = decoded['from'];
  final mid = decoded['mid'];
  final ts = decoded['ts'];
  final payload = decoded['p'];

  if (type is! String || from is! String || mid is! String || ts is! int) {
    throw const EnvelopeError('malformed envelope header');
  }
  if (payload is! Map) {
    throw const EnvelopeError('malformed envelope payload');
  }

  return Envelope(
    version: version,
    type: MessageType.fromWireName(type),
    senderDeviceId: from,
    messageId: mid,
    timestampMs: ts,
    payload: payload.map((k, v) => MapEntry(k.toString(), v)),
  );
}
