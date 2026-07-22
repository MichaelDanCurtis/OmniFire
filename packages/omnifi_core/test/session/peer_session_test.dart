import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

int fixedClock() => 1753200000000;

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
}
