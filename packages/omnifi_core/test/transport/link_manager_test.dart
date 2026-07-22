import 'dart:math';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

int _now = 1753200000000;
int testClock() => _now;

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

    test('wake drops the current link and goes to reconnecting', () async {
      final session = newSession();
      final m = LinkManager(
        session: session,
        dialers: [() async => FakeLink(id: 'redial', kind: LinkKind.lan)],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      expect(m.status, ConnectionStatus.connectedDirect);

      await m.onWake();
      // A sleeping socket looks alive and is not, so wake tears down
      // unconditionally rather than waiting out the liveness timeout.
      expect(session.link?.id, isNot('lan'));
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
  });
}
