import 'dart:convert';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

void main() {
  test('lan is preferred over relay', () {
    const lan = LinkQuality(kind: LinkKind.lan, rtt: Duration(milliseconds: 40));
    const relay =
        LinkQuality(kind: LinkKind.relay, rtt: Duration(milliseconds: 5));
    expect(lan.preferenceScore, lessThan(relay.preferenceScore));
    expect(lan.isDirect, isTrue);
    expect(relay.isDirect, isFalse);
  });

  test('within the same kind, lower rtt is preferred', () {
    const fast = LinkQuality(kind: LinkKind.lan, rtt: Duration(milliseconds: 5));
    const slow =
        LinkQuality(kind: LinkKind.lan, rtt: Duration(milliseconds: 90));
    expect(fast.preferenceScore, lessThan(slow.preferenceScore));
  });

  test('unknown rtt ranks behind a measured one of the same kind', () {
    const measured =
        LinkQuality(kind: LinkKind.lan, rtt: Duration(milliseconds: 90));
    const unknown = LinkQuality(kind: LinkKind.lan, rtt: null);
    expect(measured.preferenceScore, lessThan(unknown.preferenceScore));
  });

  test('a connected fake pair carries frames both ways', () async {
    final p = FakeLink.connectedPair();
    final fromB = p.b.inbound.first;
    await p.a.send(utf8.encode('a to b'));
    expect(utf8.decode(await fromB), 'a to b');

    final fromA = p.a.inbound.first;
    await p.b.send(utf8.encode('b to a'));
    expect(utf8.decode(await fromA), 'b to a');
  });

  test('fake link records what was sent', () async {
    final p = FakeLink.connectedPair();
    await p.a.send(utf8.encode('one'));
    await p.a.send(utf8.encode('two'));
    expect(p.a.sent.map(utf8.decode), ['one', 'two']);
  });

  test('sending on a disconnected link throws', () async {
    final p = FakeLink.connectedPair();
    p.a.setState(LinkState.disconnected);
    expect(() => p.a.send(utf8.encode('nope')),
        throwsA(isA<LinkClosedError>()));
  });

  test('state changes are observable', () async {
    final p = FakeLink.connectedPair();
    final seen = <LinkState>[];
    p.a.states.listen(seen.add);
    p.a.setState(LinkState.disconnected);
    p.a.setState(LinkState.connecting);
    p.a.setState(LinkState.connected);
    await Future<void>.delayed(Duration.zero);
    expect(seen, [
      LinkState.disconnected,
      LinkState.connecting,
      LinkState.connected,
    ]);
  });

  test('close moves the link to disconnected', () async {
    final p = FakeLink.connectedPair();
    await p.a.close();
    expect(p.a.state, LinkState.disconnected);
  });

  test('two connected pairs yield four distinct ids', () {
    final first = FakeLink.connectedPair();
    final second = FakeLink.connectedPair();
    final ids = {first.a.id, first.b.id, second.a.id, second.b.id};
    expect(ids, hasLength(4));
  });

  test('explicit ids override the generated ones', () {
    final p = FakeLink.connectedPair(idA: 'left', idB: 'right');
    expect(p.a.id, 'left');
    expect(p.b.id, 'right');
  });

  test('close is idempotent', () async {
    final p = FakeLink.connectedPair();
    await p.a.close();
    await p.a.close();
    expect(p.a.state, LinkState.disconnected);
  });

  test(
      'closing one end of a pair closes the other, so sending on it '
      'surfaces LinkClosedError, not StateError', () async {
    // close() closes both ends of a connected pair (see FakeLink.close), so
    // this exercises `a`'s own `_closed` guard in send() -- reached because
    // closing `b` recursively closed `a` too -- rather than any state
    // specific to "the peer, not me, is what closed".
    final p = FakeLink.connectedPair();
    await p.b.close();
    await expectLater(
      p.a.send(utf8.encode('orphan')),
      throwsA(isA<LinkClosedError>()),
    );
  });

  test('deliver after close does not throw', () async {
    final p = FakeLink.connectedPair();
    await p.a.close();
    expect(() => p.a.deliver(utf8.encode('late')), returnsNormally);
  });

  test('a link closed during a suspended send fails that send', () async {
    final p = FakeLink.connectedPair();
    final pending = p.a.send(utf8.encode('inflight'));
    await p.a.close();
    await expectLater(pending, throwsA(isA<LinkClosedError>()));
  });
}
