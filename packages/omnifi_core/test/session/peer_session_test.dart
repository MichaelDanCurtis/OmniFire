import 'dart:async';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

int fixedClock() => 1753200000000;

final List<int> _aSendKey = List<int>.filled(32, 11);
final List<int> _aReceiveKey = List<int>.filled(32, 22);

/// A [Link] whose `send` genuinely suspends, like a real socket write, and
/// which can be told to fail on a specific send index. `FakeLink` completes
/// its writes without ever yielding, which hides ordering races.
class DelayedLink implements Link {
  DelayedLink(this.id, {this.sendDelay = const Duration(milliseconds: 5)});

  @override
  final String id;
  final Duration sendDelay;

  @override
  LinkKind get kind => LinkKind.lan;

  final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  DelayedLink? _peer;
  LinkState _state = LinkState.connected;

  /// Zero-based send indices that should throw instead of delivering.
  final Set<int> failAt = <int>{};
  int sendCount = 0;
  final List<Uint8List> sent = <Uint8List>[];

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality => const LinkQuality(kind: LinkKind.lan);

  void setState(LinkState next) {
    _state = next;
    _states.add(next);
  }

  void deliver(List<int> frame) => _inbound.add(Uint8List.fromList(frame));

  @override
  Future<void> send(List<int> frame) async {
    final index = sendCount++;
    await Future<void>.delayed(sendDelay);
    if (_state != LinkState.connected || failAt.contains(index)) {
      throw LinkClosedError(id);
    }
    sent.add(Uint8List.fromList(frame));
    _peer?.deliver(frame);
  }

  @override
  Future<void> close() async {
    setState(LinkState.disconnected);
    await _inbound.close();
    await _states.close();
  }

  static ({DelayedLink a, DelayedLink b}) pair() {
    final a = DelayedLink('delayed-a');
    final b = DelayedLink('delayed-b');
    a._peer = b;
    b._peer = a;
    return (a: a, b: b);
  }
}

/// A [Link] whose inbound subscription takes a while to actually cancel, so
/// events raised during that window still reach the handler that was
/// installed before migration. Real transports behave this way: `cancel()`
/// is asynchronous, and the session must not rely on it to silence a link
/// it has already migrated off.
class LaggyCancelLink implements Link {
  LaggyCancelLink(this.id,
      {this.cancelLag = const Duration(milliseconds: 60)});

  @override
  final String id;
  final Duration cancelLag;

  final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  @override
  LinkKind get kind => LinkKind.lan;

  @override
  Stream<Uint8List> get inbound => _LaggyCancelStream<Uint8List>(
        _inbound.stream,
        cancelLag,
      );

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => LinkState.connected;

  @override
  LinkQuality get quality => const LinkQuality(kind: LinkKind.lan);

  void raise(Object error) => _inbound.addError(error);

  @override
  Future<void> send(List<int> frame) async {}

  @override
  Future<void> close() async {
    await _inbound.close();
    await _states.close();
  }
}

class _LaggyCancelStream<T> extends Stream<T> {
  _LaggyCancelStream(this._source, this._lag);
  final Stream<T> _source;
  final Duration _lag;

  @override
  bool get isBroadcast => true;

  @override
  StreamSubscription<T> listen(
    void Function(T event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      _LaggyCancelSubscription<T>(
        _source.listen(onData,
            onError: onError, onDone: onDone, cancelOnError: cancelOnError),
        _lag,
      );
}

class _LaggyCancelSubscription<T> implements StreamSubscription<T> {
  _LaggyCancelSubscription(this._inner, this._lag);
  final StreamSubscription<T> _inner;
  final Duration _lag;

  @override
  Future<void> cancel() async {
    await Future<void>.delayed(_lag);
    await _inner.cancel();
  }

  @override
  bool get isPaused => _inner.isPaused;
  @override
  void pause([Future<void>? resumeSignal]) => _inner.pause(resumeSignal);
  @override
  void resume() => _inner.resume();
  @override
  void onData(void Function(T)? handleData) => _inner.onData(handleData);
  @override
  void onError(Function? handleError) => _inner.onError(handleError);
  @override
  void onDone(void Function()? handleDone) => _inner.onDone(handleDone);
  @override
  Future<E> asFuture<E>([E? futureValue]) => _inner.asFuture<E>(futureValue);
}

/// Seals an envelope as device `a` would, without going through a session,
/// so tests can inject a frame at an exact moment.
Future<Uint8List> sealAsPeerA(AeadSession sender, MessageType type) async {
  return sender.seal(encodeEnvelope(Envelope(
    version: omnifiProtocolVersion,
    type: type,
    senderDeviceId: 'a' * 32,
    messageId: randomHexId(),
    timestampMs: fixedClock(),
    payload: const {},
  )));
}

({PeerSession a, PeerSession b}) sessionPair() {
  final k1 = List<int>.filled(32, 11);
  final k2 = List<int>.filled(32, 22);
  return (
    a: PeerSession(
      localDeviceId: 'a' * 32,
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(sendKey: k1, receiveKey: k2),
      clock: fixedClock,
    ),
    b: PeerSession(
      localDeviceId: 'b' * 32,
      peerDeviceId: 'a' * 32,
      crypto: AeadSession(sendKey: k2, receiveKey: k1),
      clock: fixedClock,
    ),
  );
}

void main() {
  test('delivers a message end to end', () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.a.attach(links.a);
    s.b.attach(links.b);

    final received = s.b.inbound.first;
    await s.a.send(MessageType.clipboardUpdate, {'text': 'hello'});

    final envelope = await received;
    expect(envelope.type, MessageType.clipboardUpdate);
    expect(envelope.senderDeviceId, 'a' * 32);
    expect(envelope.payload['text'], 'hello');
  });

  test('queues while detached and flushes on attach', () async {
    final s = sessionPair();
    await s.a.send(MessageType.heartbeat, const {});
    await s.a.send(MessageType.heartbeat, const {});
    expect(s.a.isAttached, isFalse);
    expect(s.a.queuedFrameCount, 2);

    final links = FakeLink.connectedPair();
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);

    s.a.attach(links.a);
    await Future<void>.delayed(const Duration(milliseconds: 10));
    expect(s.a.queuedFrameCount, 0);
    expect(seen.length, 2);
  });

  test('migrating to a new link preserves counters', () async {
    final s = sessionPair();
    final first = FakeLink.connectedPair();
    s.a.attach(first.a);
    s.b.attach(first.b);
    await s.a.send(MessageType.heartbeat, const {});
    await Future<void>.delayed(const Duration(milliseconds: 10));

    // Swap both ends onto a fresh pair of links, as happens when a LAN
    // path appears while a relay session is live.
    final second = FakeLink.connectedPair();
    s.a.attach(second.a);
    s.b.attach(second.b);

    final received = s.b.inbound.first;
    await s.a.send(MessageType.clipboardUpdate, {'text': 'after migration'});
    expect((await received).payload['text'], 'after migration');
    expect(s.a.isDead, isFalse);
  });

  test('migration does not drop frames queued during the gap', () async {
    final s = sessionPair();
    final first = FakeLink.connectedPair();
    s.a.attach(first.a);
    s.b.attach(first.b);

    first.a.setState(LinkState.disconnected);
    await s.a.send(MessageType.clipboardUpdate, {'text': 'queued'});
    expect(s.a.queuedFrameCount, 1);

    final second = FakeLink.connectedPair();
    s.b.attach(second.b);
    final received = s.b.inbound.first;
    s.a.attach(second.a);

    expect((await received).payload['text'], 'queued');
  });

  test('collapse key replaces a queued message of the same key', () async {
    final s = sessionPair();
    await s.a.send(MessageType.clipboardUpdate, {'text': 'stale'},
        collapseKey: 'clipboard');
    await s.a.send(MessageType.clipboardUpdate, {'text': 'fresh'},
        collapseKey: 'clipboard');
    expect(s.a.queuedFrameCount, 1);

    final links = FakeLink.connectedPair();
    s.b.attach(links.b);
    final received = s.b.inbound.first;
    s.a.attach(links.a);
    expect((await received).payload['text'], 'fresh');
  });

  test('a send failure requeues rather than losing the frame', () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.a.attach(links.a);
    links.a.failNextSend();
    await s.a.send(MessageType.clipboardUpdate, {'text': 'retry me'});
    expect(s.a.queuedFrameCount, 1);
  });

  test('a garbage frame marks the session dead and reports an error',
      () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.b.attach(links.b);

    final error = s.b.errors.first;
    links.b.deliver(List<int>.filled(64, 0xAB));

    expect(await error, isA<SessionRejectedError>());
    expect(s.b.isDead, isTrue);
  });

  test('a dead session refuses further sends', () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.b.attach(links.b);
    s.b.errors.listen((_) {});
    links.b.deliver(List<int>.filled(64, 0xAB));
    await Future<void>.delayed(const Duration(milliseconds: 10));

    expect(() => s.b.send(MessageType.heartbeat, const {}),
        throwsA(isA<SessionRejectedError>()));
  });

  test('rejects a frame whose sender is not the expected peer', () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.a.attach(links.a);
    s.b.attach(links.b);

    final impostor = PeerSession(
      localDeviceId: 'c' * 32,
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(
        sendKey: List<int>.filled(32, 11),
        receiveKey: List<int>.filled(32, 22),
      ),
      clock: fixedClock,
    );
    impostor.attach(links.a);

    final error = s.b.errors.first;
    await impostor.send(MessageType.heartbeat, const {});
    expect(await error, isA<SessionRejectedError>());
  });

  test('a live send does not overtake an in-flight flush', () async {
    final s = sessionPair();
    for (var i = 0; i < 3; i++) {
      await s.a.send(MessageType.heartbeat, {'i': i});
    }
    expect(s.a.queuedFrameCount, 3);

    final links = DelayedLink.pair();
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);
    final errors = <Object>[];
    s.b.errors.listen(errors.add);

    s.a.attach(links.a);
    await s.a.send(MessageType.clipboardUpdate, {'i': 3});
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(errors, isEmpty);
    expect(s.b.isDead, isFalse);
    expect(seen.map((e) => e.payload['i']).toList(), [0, 1, 2, 3]);
  });

  test('a mid-flush failure requeues the remainder in order', () async {
    final s = sessionPair();
    for (var i = 0; i < 3; i++) {
      await s.a.send(MessageType.heartbeat, {'i': i});
    }

    final first = DelayedLink.pair();
    first.a.failAt.add(1);
    s.b.attach(first.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);

    s.a.attach(first.a);
    await Future<void>.delayed(const Duration(milliseconds: 200));

    // The failing frame plus the untried remainder must both survive.
    expect(s.a.queuedFrameCount, 2);

    final second = DelayedLink.pair();
    s.b.attach(second.b);
    s.a.attach(second.a);
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(s.a.queuedFrameCount, 0);
    expect(seen.map((e) => e.payload['i']).toList(), [0, 1, 2]);
    expect(s.b.isDead, isFalse);
  });

  test('a failed outbound action does not latch the serialization chain',
      () async {
    final s = sessionPair();
    // Oversized payload: the outbox rejects the frame, so the outbound
    // action throws rather than being swallowed by the requeue path.
    final oversized = 'x' * (maxOutboxBytes + 1024);
    await expectLater(
      s.a.send(MessageType.clipboardUpdate, {'text': oversized}),
      throwsA(isA<ArgumentError>()),
    );

    await s.a
        .send(MessageType.heartbeat, const {})
        .timeout(const Duration(seconds: 10));
    expect(s.a.queuedFrameCount, 1);
  });

  test('a dead session emits exactly one error and no further envelopes',
      () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.b.attach(links.b);
    final errors = <Object>[];
    s.b.errors.listen(errors.add);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);

    final sender =
        AeadSession(sendKey: _aSendKey, receiveKey: _aReceiveKey);
    // Two frames that authenticate-fail (so the failure is decided after a
    // real suspension) plus one perfectly good frame, all in the same turn.
    final bad0 = await sealAsPeerA(sender, MessageType.heartbeat);
    bad0[bad0.length - 1] ^= 0xFF;
    final bad1 = await sealAsPeerA(sender, MessageType.heartbeat);
    bad1[bad1.length - 1] ^= 0xFF;
    final good = await sealAsPeerA(sender, MessageType.heartbeat);

    links.b.deliver(bad0);
    links.b.deliver(bad1);
    links.b.deliver(good);
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(s.b.isDead, isTrue);
    expect(errors.length, 1);
    expect(seen, isEmpty);

    // And nothing arriving later gets through either.
    links.b.deliver(await sealAsPeerA(sender, MessageType.heartbeat));
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(seen, isEmpty);
    expect(errors.length, 1);
  });

  test('a stale link delivers nothing once migration is complete', () async {
    final s = sessionPair();
    final first = FakeLink.connectedPair();
    s.b.attach(first.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);
    final errors = <Object>[];
    s.b.errors.listen(errors.add);

    final sender =
        AeadSession(sendKey: _aSendKey, receiveKey: _aReceiveKey);

    final second = FakeLink.connectedPair();
    s.b.attach(second.b);
    await Future<void>.delayed(const Duration(milliseconds: 50));

    // A frame delivered on the abandoned link, which has not begun
    // decryption, is dropped by the pre-decrypt generation guard. (A frame
    // that was already mid-decrypt at the moment of migration is a
    // different case, covered separately: it authenticates successfully and
    // must still be delivered -- see "a frame already mid-decrypt at
    // migration is still delivered..." below.)
    first.b.deliver(await sealAsPeerA(sender, MessageType.heartbeat));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(seen, isEmpty);
    expect(errors, isEmpty);
  });

  test(
      'a frame already mid-decrypt at migration is still delivered, but one '
      'that has not begun decrypting is not', () async {
    final s = sessionPair();
    final first = DelayedLink.pair();
    s.b.attach(first.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);
    final errors = <Object>[];
    s.b.errors.listen(errors.add);

    final sender = AeadSession(sendKey: _aSendKey, receiveKey: _aReceiveKey);
    final inFlightFrame = await sealAsPeerA(sender, MessageType.heartbeat);

    // Frame is in flight inside _onFrame at the moment the session
    // migrates: the microtask that starts decryption has already run, so
    // AeadSession.open is genuinely suspended mid-decrypt when attach(B)
    // bumps the generation.
    first.b.deliver(inFlightFrame);
    await null;
    final second = DelayedLink.pair();
    s.b.attach(second.b);
    await Future<void>.delayed(const Duration(milliseconds: 50));

    // The frame authenticated successfully under the session key, so it is
    // genuinely from the peer and the receive counter has already moved
    // past it -- discarding it here would be irrecoverable data loss.
    expect(seen.length, 1);
    expect(errors, isEmpty);

    // A second frame delivered on the now-abandoned link, which has not
    // begun decryption, must still be dropped by the pre-decrypt
    // generation guard.
    first.b.deliver(await sealAsPeerA(sender, MessageType.heartbeat));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(seen.length, 1);
    expect(errors, isEmpty);
  });

  test('a live send does not overtake a requeued frame on the same link',
      () async {
    final s = sessionPair();
    final links = DelayedLink.pair();
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);
    final errors = <Object>[];
    s.b.errors.listen(errors.add);

    // The first write fails mid-flight, so 'one' is requeued holding nonce
    // counter 0 while the link stays connected.
    links.a.failAt.add(0);
    s.a.attach(links.a);
    await s.a.send(MessageType.clipboardUpdate, {'text': 'one'});
    expect(s.a.queuedFrameCount, 1);

    // 'two' seals counter 1. It must not reach the wire ahead of counter 0.
    await s.a.send(MessageType.clipboardUpdate, {'text': 'two'});

    s.a.attach(links.a);
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(seen.map((e) => e.payload['text']).toList(), ['one', 'two']);
    expect(errors, isEmpty);
    expect(s.b.isDead, isFalse);
    expect(s.a.queuedFrameCount, 0);
  });

  test('a link that reconnects in place drains the outbox', () async {
    final s = sessionPair();
    final links = DelayedLink.pair();
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);
    s.a.attach(links.a);

    links.a.setState(LinkState.disconnected);
    await s.a.send(MessageType.clipboardUpdate, {'text': 'during outage'});
    expect(s.a.queuedFrameCount, 1);

    // The same link recovers without being re-attached.
    links.a.setState(LinkState.connected);
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(s.a.queuedFrameCount, 0);
    expect(seen.map((e) => e.payload['text']).toList(), ['during outage']);
    expect(s.b.isDead, isFalse);
  });

  test('send after dispose throws and neither seals nor queues', () async {
    final s = sessionPair();
    await s.a.dispose();

    await expectLater(
      s.a.send(MessageType.clipboardUpdate, {'text': 'too late'}),
      throwsA(isA<SessionRejectedError>()),
    );
    expect(s.a.queuedFrameCount, 0);
  });

  test('a collapsed frame goes out last, not in the superseded slot',
      () async {
    // Reviewer's confirmed repro. 'clip-old' seals counter 0, 'other' seals
    // counter 1, 'clip-new' seals counter 2 and collapses 'clip-old' away.
    // If the replacement inherited the superseded entry's queue position,
    // counter 2 would hit the wire before counter 1 and the receiver would
    // tear the session down on the non-advancing counter, losing 'other'.
    final s = sessionPair();
    await s.a.send(MessageType.clipboardUpdate, {'text': 'clip-old'},
        collapseKey: 'clip');
    await s.a.send(MessageType.heartbeat, {'text': 'other'});
    await s.a.send(MessageType.clipboardUpdate, {'text': 'clip-new'},
        collapseKey: 'clip');
    expect(s.a.queuedFrameCount, 2);

    final links = DelayedLink.pair();
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);
    final errors = <Object>[];
    s.b.errors.listen(errors.add);

    s.a.attach(links.a);
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(seen.map((e) => e.payload['text']).toList(), ['other', 'clip-new']);
    expect(errors, isEmpty);
    expect(s.b.isDead, isFalse);
    expect(s.a.queuedFrameCount, 0);
  });

  test('a failed write is reported and retried rather than stalling forever',
      () async {
    // The link stays `connected` after the failed write -- what a real socket
    // does on a transient write error -- so no state transition will ever
    // arrive to trigger a flush. The session must arm its own retry, and must
    // say on `errors` that the outbound path stumbled, without dying: a
    // failed write is not an authentication failure.
    final s = sessionPair();
    final links = DelayedLink.pair();
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);
    final errors = <Object>[];
    s.a.errors.listen(errors.add);

    links.a.failAt.add(0);
    s.a.attach(links.a);
    await s.a.send(MessageType.clipboardUpdate, {'text': 'one'});
    for (var i = 1; i < 6; i++) {
      await s.a.send(MessageType.clipboardUpdate, {'text': 'f$i'});
    }
    expect(s.a.queuedFrameCount, 6);
    expect(errors, isNotEmpty);

    for (var i = 0; i < 60 && s.a.queuedFrameCount > 0; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    // The outbox empties when the flush starts, not when the last write
    // lands, so let the in-flight writes settle before checking the wire.
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(s.a.queuedFrameCount, 0);
    expect(s.a.isDead, isFalse);
    expect(seen.map((e) => e.payload['text']).toList(),
        ['one', 'f1', 'f2', 'f3', 'f4', 'f5']);
    expect(s.b.isDead, isFalse);
  });

  test('attach after dispose does not resurrect the session', () async {
    final s = sessionPair();
    // Queue something so a stray flush would have material to write.
    await s.a.send(MessageType.clipboardUpdate, {'text': 'queued'});
    await s.a.dispose();

    final links = DelayedLink.pair();
    s.a.attach(links.a);
    await Future<void>.delayed(const Duration(milliseconds: 100));

    expect(links.a.sent, isEmpty);
    expect(s.a.link, isNull);
  });

  test(
      'a second write failure before the first retry fires cancels it, '
      'leaving only one outstanding retry', () async {
    final s = sessionPair();
    final links = DelayedLink.pair();
    // Attempt 0 (the initial direct-dispatch send) and attempt 1 (triggered
    // below by a synthetic in-place-reconnect event) both fail; attempt 2
    // succeeds.
    links.a.failAt.addAll([0, 1]);
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);
    final errors = <Object>[];
    s.a.errors.listen(errors.add);

    s.a.attach(links.a);
    await s.a.send(MessageType.clipboardUpdate, {'text': 'retry-race'});
    expect(s.a.queuedFrameCount, 1);
    // A retry timer is now armed, ~outboundRetryDelay from now (t0).

    await Future<void>.delayed(const Duration(milliseconds: 250));
    // A second, independent trigger for a flush -- exactly what the
    // link-states listener produces on an in-place reconnect -- fails
    // again. If _onWriteFailure correctly cancels the outstanding timer
    // before arming a new one, only the *new* timer (armed here, firing
    // ~outboundRetryDelay from now) can ever deliver the frame. If it does
    // not cancel, the stale first timer -- unaware this second failure
    // already consumed attempt 1 -- would still fire at its original mark
    // (~outboundRetryDelay after t0) and succeed early, since by then the
    // only remaining failing attempt has already been spent.
    links.a.setState(LinkState.connected);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(errors.length, 2);
    expect(s.a.queuedFrameCount, 1);

    // Past where an uncancelled first timer would have fired and succeeded
    // (t0 + outboundRetryDelay), but still short of where the single
    // correctly-rescheduled timer fires (second failure + outboundRetryDelay).
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(s.a.queuedFrameCount, 1,
        reason: 'must not be delivered by a leftover, uncancelled first '
            'retry timer');

    // Past where the single correctly-rescheduled timer fires.
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(s.a.queuedFrameCount, 0);
    expect(seen.map((e) => e.payload['text']).toList(), ['retry-race']);
    expect(errors.length, 2);
  });

  test(
      'a retry armed before dispose does not fire on the already-attached '
      'link', () async {
    final s = sessionPair();
    final links = DelayedLink.pair();
    links.a.failAt.add(0);
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);

    // Unlike "attach after dispose does not resurrect the session", this
    // link is not fresh: it is the very link already in use, with a retry
    // timer already armed on it, at the moment dispose() runs.
    s.a.attach(links.a);
    await s.a.send(MessageType.clipboardUpdate, {'text': 'never lands'});
    expect(s.a.queuedFrameCount, 1);

    await s.a.dispose();
    expect(s.a.link, isNull);

    await Future<void>.delayed(
        PeerSession.outboundRetryDelay + const Duration(milliseconds: 200));

    expect(links.a.sent, isEmpty);
    expect(seen, isEmpty);
    expect(s.a.queuedFrameCount, 1);
  });

  test('a stale link stream error is not emitted after migration', () async {
    final s = sessionPair();
    final first = LaggyCancelLink('laggy-first');
    s.b.attach(first);
    final errors = <Object>[];
    s.b.errors.listen(errors.add);

    final second = FakeLink.connectedPair();
    s.b.attach(second.b);

    // The old subscription has not finished cancelling yet, so the error
    // still reaches the handler installed for the retired generation.
    await Future<void>.delayed(const Duration(milliseconds: 10));
    first.raise(const LinkClosedError('laggy-first'));
    await Future<void>.delayed(const Duration(milliseconds: 100));

    expect(errors, isEmpty);
  });
}
