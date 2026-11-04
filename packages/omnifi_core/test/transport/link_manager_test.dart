import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

int _now = 1753200000000;
int testClock() => _now;

/// Lets pending microtasks and zero-duration timers run.
Future<void> pump() async {
  for (var i = 0; i < 3; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

/// Polls until [done], for the tests whose subject is a real [Timer] firing.
Future<void> pumpUntil(
  bool Function() done, {
  Duration timeout = const Duration(seconds: 5),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (!done()) {
    if (DateTime.now().isAfter(deadline)) {
      throw StateError('condition was not met within $timeout');
    }
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
}

/// A [Link] that records how often it was closed and tolerates a double
/// close, so a test can tell whether the manager disposed of it. Local to
/// this file: the shared [FakeLink] is depended on by other suites.
class _ControlledLink implements Link {
  _ControlledLink({required this.id, this.kind = LinkKind.lan});

  @override
  final String id;

  @override
  final LinkKind kind;

  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  LinkState _state = LinkState.connected;
  int closeCount = 0;

  bool get closed => closeCount > 0;

  @override
  Stream<Uint8List> get inbound => const Stream<Uint8List>.empty();

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality =>
      LinkQuality(kind: kind, rtt: const Duration(milliseconds: 10));

  @override
  Future<void> send(List<int> frame) async {
    if (_state != LinkState.connected) throw LinkClosedError(id);
  }

  @override
  Future<void> close() async {
    closeCount++;
    _state = LinkState.disconnected;
    if (!_states.isClosed) {
      _states.add(LinkState.disconnected);
      await _states.close();
    }
  }
}

PeerSession newSession() => PeerSession(
      localDeviceId: 'a' * 32,
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(
        sendKey: List<int>.filled(32, 11),
        receiveKey: List<int>.filled(32, 22),
      ),
      clock: testClock,
    );

void main() {
  setUp(() => _now = 1753200000000);

  group('BackoffPolicy', () {
    test('grows exponentially from the base', () {
      final b = BackoffPolicy(jitter: 0, random: Random(1));
      expect(b.delayFor(0), const Duration(seconds: 1));
      expect(b.delayFor(1), const Duration(seconds: 2));
      expect(b.delayFor(2), const Duration(seconds: 4));
      expect(b.delayFor(3), const Duration(seconds: 8));
    });

    test('caps at 30 seconds', () {
      final b = BackoffPolicy(jitter: 0, random: Random(1));
      expect(b.delayFor(20), const Duration(seconds: 30));
    });

    test('jitter stays within the configured fraction', () {
      final b = BackoffPolicy(jitter: 0.25, random: Random(42));
      for (var attempt = 0; attempt < 8; attempt++) {
        final d = b.delayFor(attempt).inMilliseconds;
        final nominal = min(1000 * (1 << attempt), 30000);
        expect(d, greaterThanOrEqualTo((nominal * 0.75).floor()));
        expect(d, lessThanOrEqualTo((nominal * 1.25).ceil()));
      }
    });

    test('never returns a negative delay', () {
      final b = BackoffPolicy(jitter: 0.9, random: Random(7));
      for (var i = 0; i < 20; i++) {
        expect(b.delayFor(i).inMilliseconds, greaterThanOrEqualTo(0));
      }
    });
  });

  group('LinkManager', () {
    test('starts offline before any link connects', () {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      expect(m.status, ConnectionStatus.offline);
    });

    test('reports connectedRelay when only a relay link is offered',
        () async {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'relay', kind: LinkKind.relay));
      expect(m.status, ConnectionStatus.connectedRelay);
    });

    test('adopts a LAN link offered while on relay', () async {
      final session = newSession();
      final m = LinkManager(
        session: session,
        dialers: const [],
        clock: testClock,
      );
      final relay = FakeLink(id: 'relay', kind: LinkKind.relay);
      m.offer(relay);
      expect(m.status, ConnectionStatus.connectedRelay);

      final lan = FakeLink(id: 'lan', kind: LinkKind.lan);
      m.offer(lan);
      expect(m.status, ConnectionStatus.connectedDirect);
      expect(session.link?.id, 'lan');
    });

    test('keeps the LAN link when a relay link is offered afterwards', () {
      final session = newSession();
      final m = LinkManager(
        session: session,
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      m.offer(FakeLink(id: 'relay', kind: LinkKind.relay));
      expect(session.link?.id, 'lan');
      expect(m.status, ConnectionStatus.connectedDirect);
    });

    test('falls back to relay when the LAN link disconnects', () async {
      final session = newSession();
      final m = LinkManager(
        session: session,
        dialers: const [],
        clock: testClock,
      );
      final relay = FakeLink(id: 'relay', kind: LinkKind.relay);
      final lan = FakeLink(id: 'lan', kind: LinkKind.lan);
      m.offer(relay);
      m.offer(lan);
      expect(session.link?.id, 'lan');

      lan.setState(LinkState.disconnected);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(session.link?.id, 'relay');
      expect(m.status, ConnectionStatus.connectedRelay);
    });

    test('emits status transitions', () async {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      final seen = <ConnectionStatus>[];
      m.statuses.listen(seen.add);
      m.offer(FakeLink(id: 'relay', kind: LinkKind.relay));
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      await Future<void>.delayed(Duration.zero);
      expect(seen, [
        ConnectionStatus.connectedRelay,
        ConnectionStatus.connectedDirect,
      ]);
    });

    test('is live immediately after an ack', () {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      m.onHeartbeatAck(_now);
      expect(m.isLive, isTrue);
    });

    test('is not live after the 45 second timeout elapses', () {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      m.onHeartbeatAck(_now);
      _now += 46000;
      expect(m.isLive, isFalse);
    });

    test('is still live at 44 seconds', () {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      m.onHeartbeatAck(_now);
      _now += 44000;
      expect(m.isLive, isTrue);
    });

    test('wake drops the current link and redials while running', () async {
      final session = newSession();
      var dials = 0;
      final m = LinkManager(
        session: session,
        dialers: [
          () async => FakeLink(id: 'redial-${++dials}', kind: LinkKind.relay),
        ],
        clock: testClock,
      );
      await m.start();
      await pump();
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      expect(session.link?.id, 'lan');
      expect(m.status, ConnectionStatus.connectedDirect);

      await m.onWake();
      await pump();
      // A sleeping socket looks alive and is not, so wake tears down
      // unconditionally rather than waiting out the liveness timeout, then
      // redials because the manager is still running.
      expect(session.link?.id, isNot('lan'));
      expect(session.link?.id, 'redial-2');
      expect(m.status, ConnectionStatus.connectedRelay);
    });

    test('wake after stop does not redial and stays offline', () async {
      final session = newSession();
      var dials = 0;
      final m = LinkManager(
        session: session,
        dialers: [
          () async => FakeLink(id: 'redial-${++dials}', kind: LinkKind.lan),
        ],
        clock: testClock,
      );
      await m.start();
      await pump();
      await m.stop();
      final dialsAfterStop = dials;

      await m.onWake();
      await pump();
      // A stopped manager is stopped: a wake event must not resurrect it.
      expect(dials, dialsAfterStop);
      expect(m.status, ConnectionStatus.offline);
      expect(m.candidates, isEmpty);
      // stop() leaves the session's last link in place by design; what must
      // not happen is a fresh one being attached by the wake.
      expect(session.link?.id, 'redial-1');
    });

    test('discards a dial that completes after onWake', () async {
      final session = newSession();
      final gate = Completer<void>();
      final stale = _ControlledLink(id: 'stale', kind: LinkKind.lan);
      final fresh = _ControlledLink(id: 'fresh', kind: LinkKind.relay);
      var dials = 0;
      final m = LinkManager(
        session: session,
        dialers: [
          () async {
            dials++;
            if (dials == 1) {
              await gate.future;
              return stale;
            }
            return fresh;
          },
        ],
        clock: testClock,
      );

      await m.start();
      await pump();
      expect(dials, 1);

      await m.onWake();
      await pump();
      expect(m.candidates.containsKey('fresh'), isTrue);

      gate.complete();
      await pump();

      expect(stale.closed, isTrue);
      expect(m.candidates.containsKey('stale'), isFalse);
      expect(session.link?.id, isNot('stale'));
      expect(session.link?.id, 'fresh');
    });

    test('discards a dial that completes after stop', () async {
      final session = newSession();
      final gate = Completer<void>();
      final stale = _ControlledLink(id: 'stale', kind: LinkKind.lan);
      final m = LinkManager(
        session: session,
        dialers: [
          () async {
            await gate.future;
            return stale;
          },
        ],
        clock: testClock,
      );

      await m.start();
      await pump();
      await m.stop();

      gate.complete();
      await pump();

      expect(stale.closed, isTrue);
      expect(m.candidates, isEmpty);
      expect(session.link, isNull);
      expect(m.status, ConnectionStatus.offline);
    });

    test('stop does not throw when a link disconnects during teardown',
        () async {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      final lan = FakeLink(id: 'lan', kind: LinkKind.lan);
      final relay = FakeLink(id: 'relay', kind: LinkKind.relay);
      m.offer(lan);
      m.offer(relay);

      // Queued, not yet delivered: the listener runs inside stop()'s awaits
      // and mutates the very maps stop() is iterating.
      relay.setState(LinkState.disconnected);

      await expectLater(m.stop(), completes);
      expect(m.status, ConnectionStatus.offline);
      expect(m.candidates, isEmpty);
    });

    test('stop closes links and reports offline', () async {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      await m.stop();
      expect(m.status, ConnectionStatus.offline);
    });

    test('offering a link with no session yet reports reconnecting rather '
        'than throwing', () async {
      // The engine constructs a manager without a session and assigns one
      // from inside its dialer. offer() is synchronous and is called from
      // inside an unawaited .then, so a LateInitializationError out of
      // _selectBest would surface as an unhandled async error -- with the
      // link left in _candidates, never attached, never closed, and the
      // status never updated.
      final m = LinkManager(dialers: const [], clock: testClock);
      await m.start();
      final orphan = FakeLink(id: 'lan', kind: LinkKind.lan);
      expect(() => m.offer(orphan), returnsNormally);
      expect(m.status, ConnectionStatus.reconnecting);
      expect(m.candidates.keys, ['lan']);
      await m.stop();
    });
  });

  // ---- The backoff must actually drive a redial ----

  group('LinkManager retry', () {
    test('redials on its own when the only candidate disconnects', () async {
      final session = newSession();
      final dialed = <_ControlledLink>[];
      final m = LinkManager(
        session: session,
        dialers: [
          () async {
            final link = _ControlledLink(
              id: 'dial-${dialed.length + 1}',
              kind: LinkKind.relay,
            );
            dialed.add(link);
            return link;
          },
        ],
        clock: testClock,
        backoff: BackoffPolicy(
          base: const Duration(milliseconds: 10),
          jitter: 0,
        ),
      );

      await m.start();
      await pumpUntil(() => session.link?.id == 'dial-1');

      // The network drops. Nothing sleeps, nothing wakes, nobody calls
      // onWake -- which used to be the only thing that ever redialed.
      await dialed.first.close();

      await pumpUntil(() => session.link?.id == 'dial-2');
      expect(m.status, ConnectionStatus.connectedRelay);
      await m.stop();
    });

    test('a failed dial is retried without a wake event', () async {
      var dials = 0;
      final m = LinkManager(
        session: newSession(),
        dialers: [
          () async {
            if (++dials == 1) throw StateError('connection refused');
            return _ControlledLink(id: 'dial-$dials', kind: LinkKind.relay);
          },
        ],
        clock: testClock,
        backoff: BackoffPolicy(
          base: const Duration(milliseconds: 10),
          jitter: 0,
        ),
      );

      await m.start();
      await pumpUntil(() => m.status == ConnectionStatus.connectedRelay);
      expect(dials, 2);
      await m.stop();
    });

    test('several dialers failing together schedule one redial, not one each',
        () async {
      var dials = 0;
      final m = LinkManager(
        session: newSession(),
        dialers: [
          () async {
            dials++;
            throw StateError('refused');
          },
          () async {
            dials++;
            throw StateError('refused');
          },
        ],
        clock: testClock,
        backoff: BackoffPolicy(
          base: const Duration(milliseconds: 50),
          jitter: 0,
        ),
      );

      await m.start();
      // One retry round lands at 2*base = 100ms. A second, redundant timer
      // armed by the second failure would land at 4*base = 200ms and dial
      // both dialers again.
      await Future<void>.delayed(const Duration(milliseconds: 300));
      expect(dials, 4);
      await m.stop();
    });

    test('a stopped manager performs no redial', () async {
      var dials = 0;
      final m = LinkManager(
        session: newSession(),
        dialers: [
          () async {
            dials++;
            throw StateError('connection refused');
          },
        ],
        clock: testClock,
        backoff: BackoffPolicy(
          base: const Duration(milliseconds: 10),
          jitter: 0,
        ),
      );

      await m.start();
      await pump();
      expect(dials, 1);

      // The retry is armed by now. Stopping must cancel it, and it must not
      // fire afterwards either.
      await m.stop();
      await Future<void>.delayed(const Duration(milliseconds: 150));
      expect(dials, 1);
      expect(m.status, ConnectionStatus.offline);
      expect(m.candidates, isEmpty);
    });
  });
}
