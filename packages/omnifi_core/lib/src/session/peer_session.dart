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

  /// Tail of the outbound serialization chain. Every outbound operation
  /// chains onto it so that sealing and transmitting are one indivisible
  /// step: [AeadSession.seal] assigns a monotonic counter, and the receiver
  /// rejects anything that arrives out of counter order, so a reordering
  /// between seal and write is fatal to the session.
  Future<void> _outboundTail = Future<void>.value();

  /// Bumped on every [attach]. Frames carrying a stale generation come from
  /// a link the session has already migrated off and are discarded.
  int _generation = 0;

  /// Runs [action] after every previously queued outbound action.
  ///
  /// The chained callback swallows failures into the per-call completer, so
  /// one failing action never leaves [_outboundTail] in a rejected state
  /// that would poison every later send.
  Future<T> _serialized<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    _outboundTail = _outboundTail.then((_) async {
      try {
        completer.complete(await action());
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });
    return completer.future;
  }

  Link? get link => _link;
  Stream<Envelope> get inbound => _inbound.stream;
  Stream<Object> get errors => _errors.stream;
  bool get isAttached => _link?.state == LinkState.connected;
  bool get isDead => _dead;
  int get queuedFrameCount => _outbox.length;

  /// Moves the session onto [link], replacing any current link, then
  /// flushes anything queued while detached.
  void attach(Link link) {
    // Cancelling is asynchronous, so the old link can still push a frame
    // that is already in flight. The generation stamp, not the cancel, is
    // what stops a stale frame from being acted on.
    unawaited(_linkSub?.cancel() ?? Future<void>.value());
    _link = link;
    final generation = ++_generation;
    _linkSub = link.inbound.listen(
      (frame) => _onFrame(frame, generation),
      onError: (Object error) => _emitError(error),
    );
    unawaited(_flush().catchError((Object _) {}));
  }

  Future<void> send(
    MessageType type,
    Map<String, Object?> payload, {
    String? collapseKey,
  }) {
    // The whole build-seal-dispatch sequence runs under the outbound lock.
    // Sealing outside it would assign the nonce counter outside the lock
    // and reintroduce the reordering this serialization exists to prevent.
    return _serialized(() async {
      _throwIfDead();
      final envelope = Envelope(
        version: omnifiProtocolVersion,
        type: type,
        senderDeviceId: localDeviceId,
        messageId: randomHexId(),
        timestampMs: _clock(),
        payload: payload,
      );
      final sealed = await _crypto.seal(encodeEnvelope(envelope));
      // The session can have died while we were sealing.
      _throwIfDead();
      await _dispatch(sealed, collapseKey: collapseKey);
    });
  }

  void _throwIfDead() {
    if (_dead) {
      throw const SessionRejectedError('session is dead; re-handshake first');
    }
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

  Future<void> _flush() => _serialized(_flushLocked);

  Future<void> _flushLocked() async {
    final start = _link;
    if (start == null || start.state != LinkState.connected) return;
    final entries = _outbox.drain();
    for (var i = 0; i < entries.length; i++) {
      // Re-read the link every iteration: an attach() between writes would
      // otherwise leave the rest of the flush writing to an abandoned link.
      final link = _link;
      if (link == null ||
          !identical(link, start) ||
          link.state != LinkState.connected) {
        _requeueFrom(entries, i);
        return;
      }
      try {
        await link.send(entries[i].frame);
      } on Object {
        _requeueFrom(entries, i);
        return;
      }
    }
  }

  /// Puts [entries] from [from] onward back on the outbox, in order.
  ///
  /// Safe because the outbound lock guarantees no concurrent send can have
  /// added anything since [Outbox.drain] emptied the queue, so re-adding in
  /// order reproduces the original order exactly.
  void _requeueFrom(List<OutboxEntry> entries, int from) {
    for (var i = from; i < entries.length; i++) {
      _outbox.add(entries[i].frame, collapseKey: entries[i].collapseKey);
    }
  }

  Future<void> _onFrame(Uint8List frame, int generation) async {
    if (_isStale(generation)) return;
    final Uint8List plaintext;
    try {
      plaintext = await _crypto.open(frame);
    } on ReplayError catch (e) {
      if (_isStale(generation)) return;
      _fail('replayed frame: $e');
      return;
    } on DecryptionError catch (e) {
      if (_isStale(generation)) return;
      _fail('undecryptable frame: $e');
      return;
    }
    // Deliberately no generation re-check here. AeadSession.open has
    // already authenticated this frame and, on success, irreversibly
    // advanced the receive counter — so a retransmission would now be
    // rejected as a replay. The link a frame arrived on says nothing about
    // whether it is really from the peer; only decryption does. Discarding
    // an authenticated frame at this point because it arrived on a
    // since-migrated-off link would destroy data the peer can never resend,
    // for no security benefit: do not "tighten" this back in. We still bail
    // out if the session died (e.g. a concurrent frame failed to
    // authenticate) — that is a real trust event, unrelated to generation.
    if (_dead) return;

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

    if (!_inbound.isClosed) _inbound.add(envelope);
  }

  /// True when this frame must not be acted on: the session is dead, or the
  /// frame arrived on a link the session has since migrated off.
  bool _isStale(int generation) => _dead || generation != _generation;

  void _fail(String reason) {
    if (_dead) return;
    _dead = true;
    _emitError(SessionRejectedError(reason));
  }

  void _emitError(Object error) {
    if (!_errors.isClosed) _errors.add(error);
  }

  Future<void> dispose() async {
    // Retire the current generation so a frame already in flight cannot
    // reach a closed controller.
    _generation++;
    await _linkSub?.cancel();
    _linkSub = null;
    await _inbound.close();
    await _errors.close();
  }
}
