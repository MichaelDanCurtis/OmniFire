import 'dart:typed_data';

import 'envelope.dart';

enum MessageType {
  hello('hello'),
  heartbeat('heartbeat'),
  heartbeatAck('heartbeat_ack'),
  rosterUpdate('roster_update'),
  clipboardUpdate('clipboard_update'),
  clipboardTooLarge('clipboard_too_large'),
  pairRequest('pair_request'),
  pairAccept('pair_accept');

  const MessageType(this.wireName);

  /// Stable on-the-wire identifier. Never change these without a
  /// protocol version bump.
  final String wireName;

  static MessageType fromWireName(String name) {
    for (final t in MessageType.values) {
      if (t.wireName == name) return t;
    }
    throw EnvelopeError('unknown message type: $name');
  }
}

const Set<String> supportedClipboardFormats = {'text', 'png'};

class ClipboardPayload {
  ClipboardPayload({
    required this.format,
    required this.data,
    required this.timestampMs,
    required this.contentHash,
  }) {
    if (!supportedClipboardFormats.contains(format)) {
      throw EnvelopeError('unsupported clipboard format: $format');
    }
  }

  final String format;
  final Uint8List data;
  final int timestampMs;
  final String contentHash;

  Map<String, Object?> toMap() => {
        'format': format,
        'data': data,
        'ts': timestampMs,
        'hash': contentHash,
      };

  factory ClipboardPayload.fromMap(Map<String, Object?> map) {
    final format = map['format'];
    final data = map['data'];
    final ts = map['ts'];
    final hash = map['hash'];
    if (format is! String || data is! List<int> || ts is! int ||
        hash is! String) {
      throw const EnvelopeError('malformed clipboard payload');
    }
    return ClipboardPayload(
      format: format,
      data: Uint8List.fromList(data),
      timestampMs: ts,
      contentHash: hash,
    );
  }
}
