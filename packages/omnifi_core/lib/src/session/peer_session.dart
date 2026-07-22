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

  /// How long to wait before re-attempting a flush after a failed write.
  /// Short enough that a transient failure self-heals promptly, long enough
  /// that a persistently failing link is retried at a modest rate.
  static const Duration outboundRetryDelay = Duration(milliseconds: 500);

  Timer? _retry;
  Link? _link;
  StreamSubscription<Uint8List>? _linkSub;
  StreamSubscription<LinkState>? _stateSub;
  bool _dead = false;
  bool _disposed = false;

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
    // A disposed session owns no link and will never drain its outbox again.
    // Re-subscribing here would resurrect it: the flush below would write
    // leftover frames to a link the caller has moved on to.
    if (_disposed) return;
    // Cancelling is asynchronous, so the old link can still push a frame
    // that is already in flight. The generation stamp, not the cancel, is
    // what stops a stale frame from being acted on.
    unawaited(_linkSub?.cancel() ?? Future<void>.value());
    unawaited(_stateSub?.cancel() ?? Future<void>.value());
    _link = link;
    final generation = ++_generation;
    _linkSub = link.inbound.listen(
      (frame) => _onFrame(frame, generation),
      // Same generation stamp as the frame path: a link the session has
      // already migrated off must not be able to surface an error on
      // [errors], any more than it can surface a frame on [inbound].
      onError: (Object error) {
        if (_isStale(generation)) return;
        _emitError(error);
      },
    );
    // attach() is not the only moment a link becomes writable: a link can
    // drop and recover in place without the session ever being re-attached,
    // and anything queued during that outage has to go out before the next
    // freshly sealed frame does.
    _stateSub = link.states.listen(
      (state) {
        if (_isStale(generation)) return;
        if (state == LinkState.connected) {
          unawaited(_flush().catchError((Object _) {}));
        }
      },
      onError: (Object error) {
        if (_isStale(generation)) return;
        _emitError(error);
      },
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
    if (_disposed) {
      throw const SessionRejectedError('session is disposed');
    }
    if (_dead) {
      throw const SessionRejectedError('session is dead; re-handshake first');
    }
  }

  Future<void> _dispatch(Uint8List frame, {String? collapseKey}) async {
    final link = _link;
    // The outbox is the single FIFO for everything already sealed. Writing
    // straight to the link while it holds anything would put a
    // later-sealed frame on the wire ahead of an earlier-sealed one, and
    // the receiver treats a non-advancing counter as fatal.
    if (link == null ||
        link.state != LinkState.connected ||
        _outbox.length > 0) {
      _outbox.add(frame, collapseKey: collapseKey);
      return;
    }
    try {
      await link.send(frame);
    } on Object catch (e) {
      // The socket died mid-write. Requeue so the frame survives the
      // reconnect rather than vanishing.
      _outbox.add(frame, collapseKey: collapseKey);
      _onWriteFailure(e);
    }
  }

  /// Handles a write that failed mid-flight, after the frame has been put
  /// back on the outbox.
  ///
  /// A link can fail a write and stay `connected` -- that is what a real
  /// socket does on a transient write error -- so no state transition is
  /// guaranteed to arrive and re-trigger a flush. Without this, one failed
  /// write mutes the session permanently while it still reports itself
  /// healthy, because every later send sees a non-empty outbox and queues
  /// behind the stuck frame.
  ///
  /// The session is deliberately *not* marked dead: a failed write is not an
  /// authentication failure and must not force a re-handshake.
  ///
  /// Retry policy stays deliberately trivial -- one delayed re-attempt per
  /// failure, at most one outstanding. Real backoff belongs to LinkManager,
  /// which owns reconnection.
  void _onWriteFailure(Object error) {
    _emitError(error);
    if (_disposed) return;
    _retry?.cancel();
    _retry = Timer(outboundRetryDelay, () {
      _retry = null;
      if (_disposed || _dead) return;
      unawaited(_flush().catchError((Object _) {}));
    });
  }

  Future<void> _flush() => _serialized(_flushLocked);

  Future<void> _flushLocked() async {
    // A flush can already be queued on the outbound chain (retry timer,
    // link-states listener, or attach) at the moment dispose() runs. Once
    // disposed, this session owns no link and must not write queued frames
    // to whatever link happened to be current when it was scheduled.
    if (_disposed) return;
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
      } on Object catch (e) {
        _requeueFrom(entries, i);
        _onWriteFailure(e);
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
    if (_disposed) return;
    // Mark the session unusable before anything else: a send() racing
    // dispose() must be refused rather than seal a counter and then write
    // to a link the session no longer manages, or queue into an outbox
    // nobody will ever drain.
    _disposed = true;
    _retry?.cancel();
    _retry = null;
    // Retire the current generation so a frame already in flight cannot
    // reach a closed controller.
    _generation++;
    await _linkSub?.cancel();
    _linkSub = null;
    await _stateSub?.cancel();
    _stateSub = null;
    // Disposed means disposed: this session no longer owns a link. A flush
    // already queued on _outboundTail (from the retry timer, the
    // link-states listener, or attach) is stopped by the _disposed guard in
    // _flushLocked, not by this becoming null, but nulling it here still
    // makes the invariant hold for anything reading `link`/`_link` after.
    _link = null;
    // Let any already-queued outbound action finish (it will refuse itself
    // via _throwIfDead) so nothing runs after the controllers are closed.
    await _outboundTail;
    await _inbound.close();
    await _errors.close();
  }
}
