import 'dart:async';
import 'dart:typed_data';

import '../crypto/aead_session.dart';
import '../identity/device_identity.dart';
import '../protocol/envelope.dart';
import '../protocol/messages.dart';
import '../transport/link.dart';
import '../transport/outbox.dart';
import '../version.dart';

/// Raised when a frame cannot be authenticated or does not come from the
/// expected peer. The session is dead afterwards: per the spec, a
/// decryption failure forces a fresh handshake rather than a counter resync.
class SessionRejectedError implements Exception {
  const SessionRejectedError(this.reason);
  final String reason;
  @override
  String toString() => 'SessionRejectedError: $reason';
}

/// An established, authenticated channel to exactly one peer device.
///
/// The session is keyed to the device pair, not to a socket. [attach] can
/// be called repeatedly to move the session onto a better link without
/// renegotiating crypto or resetting nonce counters.
class PeerSession {
  PeerSession({
    required this.localDeviceId,
    required this.peerDeviceId,
    required AeadSession crypto,
    required int Function() clock,
  })  : _crypto = crypto,
        _clock = clock;

  final String localDeviceId;
  final String peerDeviceId;
  final AeadSession _crypto;
  final int Function() _clock;

  final Outbox _outbox = Outbox();
  final StreamController<Envelope> _inbound =
      StreamController<Envelope>.broadcast();
  final StreamController<Object> _errors =
      StreamController<Object>.broadcast();

  Link? _link;
  StreamSubscription<Uint8List>? _linkSub;
  bool _dead = false;

  Link? get link => _link;
  Stream<Envelope> get inbound => _inbound.stream;
  Stream<Object> get errors => _errors.stream;
  bool get isAttached => _link?.state == LinkState.connected;
  bool get isDead => _dead;
  int get queuedFrameCount => _outbox.length;

  /// Moves the session onto [link], replacing any current link, then
  /// flushes anything queued while detached.
  void attach(Link link) {
    _linkSub?.cancel();
    _link = link;
    _linkSub = link.inbound.listen(_onFrame, onError: _errors.add);
    unawaited(_flush());
  }

  Future<void> send(
    MessageType type,
    Map<String, Object?> payload, {
    String? collapseKey,
  }) async {
    if (_dead) {
      throw const SessionRejectedError('session is dead; re-handshake first');
    }
    final envelope = Envelope(
      version: omnifiProtocolVersion,
      type: type,
      senderDeviceId: localDeviceId,
      messageId: randomHexId(),
      timestampMs: _clock(),
      payload: payload,
    );
    final sealed = await _crypto.seal(encodeEnvelope(envelope));
    await _dispatch(sealed, collapseKey: collapseKey);
  }

  Future<void> _dispatch(Uint8List frame, {String? collapseKey}) async {
    final link = _link;
    if (link == null || link.state != LinkState.connected) {
      _outbox.add(frame, collapseKey: collapseKey);
      return;
    }
    try {
      await link.send(frame);
    } on Object {
      // The socket died mid-write. Requeue so the frame survives the
      // reconnect rather than vanishing.
      _outbox.add(frame, collapseKey: collapseKey);
    }
  }

  Future<void> _flush() async {
    final link = _link;
    if (link == null || link.state != LinkState.connected) return;
    for (final entry in _outbox.drain()) {
      try {
        await link.send(entry.frame);
      } on Object {
        _outbox.add(entry.frame, collapseKey: entry.collapseKey);
        return;
      }
    }
  }

  Future<void> _onFrame(Uint8List frame) async {
    if (_dead) return;
    final Uint8List plaintext;
    try {
      plaintext = await _crypto.open(frame);
    } on ReplayError catch (e) {
      _fail('replayed frame: $e');
      return;
    } on DecryptionError catch (e) {
      _fail('undecryptable frame: $e');
      return;
    }

    final Envelope envelope;
    try {
      envelope = decodeEnvelope(plaintext);
    } on EnvelopeError catch (e) {
      _fail('malformed envelope: $e');
      return;
    }

    if (envelope.senderDeviceId != peerDeviceId) {
      _fail('frame claims sender ${envelope.senderDeviceId}, '
          'expected $peerDeviceId');
      return;
    }

    _inbound.add(envelope);
  }

  void _fail(String reason) {
    _dead = true;
    _errors.add(SessionRejectedError(reason));
  }

  Future<void> dispose() async {
    await _linkSub?.cancel();
    await _inbound.close();
    await _errors.close();
  }
}
