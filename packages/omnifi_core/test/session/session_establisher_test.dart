import 'dart:async';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

Future<DeviceIdentity> identity(String name) =>
    loadOrCreateIdentity(store: InMemorySecureStore(), displayName: name);

/// The roster entry another device would hold for [id].
PeerRecord rosterEntryFor(DeviceIdentity id) => PeerRecord(
      deviceId: id.deviceId,
      publicKey: id.keys.publicKey,
      displayName: id.displayName,
      addedAtMs: 1,
    );

Future<OmniFiEngine> engine(String name) => OmniFiEngine.create(
      store: InMemorySecureStore(),
      watcher: FakeClipboardWatcher(),
      config: EngineConfig(
        relayBases: [Uri.parse('http://localhost:8787')],
        displayName: name,
        lanEnabled: false,
      ),
      clock: () => 1753200000000,
    );

/// A handshake for the peer half of an exchange, driven by hand.
Handshake peerHandshakeAgainst(DeviceIdentity peer, DeviceIdentity local) =>
    isInitiatorFor(peer.deviceId, local.deviceId)
        ? OmniFiHandshakeV1.initiator(
            staticKeys: peer.keys,
            deviceId: peer.deviceId,
            expectedPeerStaticPublicKey: local.keys.publicKey,
          )
        : OmniFiHandshakeV1.responder(
            staticKeys: peer.keys,
            deviceId: peer.deviceId,
            expectedPeerStaticPublicKey: local.keys.publicKey,
          );

void main() {
  test('two rostered devices establish a working session over a link pair',
      () async {
    final a = await identity('Mac');
    final b = await identity('PC');
    final links = FakeLink.connectedPair();

    // Both sides run concurrently, as they do on a real reconnect: neither
    // waits for the other to go first, and neither is told which role to
    // take.
    final aPending = SessionEstablisher.establish(
        link: links.a, identity: a, peer: rosterEntryFor(b));
    final bPending = SessionEstablisher.establish(
        link: links.b, identity: b, peer: rosterEntryFor(a));

    final sa = await aPending;
    final sb = await bPending;

    final sealed = await sa.seal([1, 2, 3]);
    expect(await sb.open(sealed), [1, 2, 3]);
    final back = await sb.seal([4, 5, 6]);
    expect(await sa.open(back), [4, 5, 6]);

    // Establishment does not tear down the link it ran over: the caller goes
    // on to adopt it.
    expect(links.a.state, LinkState.connected);
    expect(links.b.state, LinkState.connected);
  });

  test('role assignment is deterministic and opposite', () async {
    expect(isInitiatorFor('aaaa', 'bbbb'), isTrue);
    expect(isInitiatorFor('bbbb', 'aaaa'), isFalse);
    // Both orderings of the same argument list, so a sign error cannot hide.
    expect(isInitiatorFor('bbbb', 'cccc'), isTrue);
    expect(isInitiatorFor('cccc', 'bbbb'), isFalse);

    // Nothing is negotiated: each side computes its own role from the pair of
    // ids, and the two answers must always disagree.
    for (var i = 0; i < 32; i++) {
      final x = randomHexId();
      final y = randomHexId();
      expect(isInitiatorFor(x, y), isNot(isInitiatorFor(y, x)),
          reason: 'both sides claimed the same role for $x / $y');
    }

    // Deterministic: the same pair always gives the same answer.
    final one = randomHexId();
    final two = randomHexId();
    final first = isInitiatorFor(one, two);
    for (var i = 0; i < 8; i++) {
      expect(isInitiatorFor(one, two), first);
    }
  });

  test('a peer whose static key is not the rostered one is rejected',
      () async {
    final a = await identity('Mac');
    final b = await identity('PC');
    final imposter = await identity('Imposter');
    final links = FakeLink.connectedPair();

    // A's roster entry names B's device id but carries somebody else's static
    // key. B is honest and presents its own. Authentication is what must
    // catch this: a matching device id alone is not enough.
    final wrongKeyForB = PeerRecord(
      deviceId: b.deviceId,
      publicKey: imposter.keys.publicKey,
      displayName: 'PC',
      addedAtMs: 1,
    );

    final aPending = SessionEstablisher.establish(
        link: links.a, identity: a, peer: wrongKeyForB);
    final bPending = SessionEstablisher.establish(
        link: links.b, identity: b, peer: rosterEntryFor(a));
    // Both handlers are registered before either can complete, so neither
    // failure surfaces as an unhandled async error.
    final aFails =
        expectLater(aPending, throwsA(isA<SessionEstablishmentError>()));
    final bFails =
        expectLater(bPending, throwsA(isA<SessionEstablishmentError>()));

    await aFails;
    // A failed handshake must not leave a link behind for the manager to
    // adopt: the peer is not who the roster says it is.
    expect(links.a.state, LinkState.disconnected);
    await bFails;
  });

  test('a second link for a peer with a live session does not re-handshake',
      () async {
    final e = await engine('Mac');
    final peer = await identity('PC');
    final peerRecord = rosterEntryFor(peer);
    e.mesh.addPeer(peerRecord);
    final engineRecord = rosterEntryFor(e.identity);

    final first = FakeLink.connectedPair();
    final peerFirst = SessionEstablisher.establish(
        link: first.b, identity: peer, peer: engineRecord);
    final s1 = await e.debugAdoptLink(peerRecord, first.a);
    await peerFirst;

    // A second link is adopted with no peer running a handshake on the other
    // end at all. If establishment re-ran, this would hang until its timeout.
    final second = FakeLink.connectedPair();
    final s2 = await e
        .debugAdoptLink(peerRecord, second.a)
        .timeout(const Duration(seconds: 5),
            onTimeout: () =>
                throw StateError('the second link re-ran the handshake'));

    // The same PeerSession, and so necessarily the same AeadSession: a
    // PeerSession takes its crypto once, in its constructor, and never
    // replaces it. The session is keyed to the device pair, not the socket.
    expect(identical(s1, s2), isTrue);
    expect(e.sessions, [s1]);
    // Nothing at all went out on the new link.
    expect(second.a.sent, isEmpty);
    expect(second.b.sent, isEmpty);

    await e.stop();
  });

  test('a dead session is discarded and replaced on the next link', () async {
    final e = await engine('Mac');
    final peer = await identity('PC');
    final peerRecord = rosterEntryFor(peer);
    e.mesh.addPeer(peerRecord);
    final engineRecord = rosterEntryFor(e.identity);

    final first = FakeLink.connectedPair();
    final peerFirst = SessionEstablisher.establish(
        link: first.b, identity: peer, peer: engineRecord);
    final s1 = await e.debugAdoptLink(peerRecord, first.a);
    await peerFirst;

    // A frame that cannot be authenticated kills the session: per the spec a
    // decryption failure forces a fresh handshake, not a counter resync.
    final died = s1.errors.first;
    first.a.deliver(Uint8List(32));
    await died;
    expect(s1.isDead, isTrue);

    final second = FakeLink.connectedPair();
    final peerSecond = SessionEstablisher.establish(
        link: second.b, identity: peer, peer: engineRecord);
    final s2 = await e.debugAdoptLink(peerRecord, second.a);
    final peerCrypto = await peerSecond;

    expect(identical(s1, s2), isFalse);
    // The dead one is gone, not merely shadowed.
    expect(e.sessions, [s2]);
    expect(second.a.sent, isNotEmpty);

    // The replacement is a genuinely working channel, not just a new object:
    // the peer opens what the engine's fresh session seals.
    final peerInbox = StreamIterator<Uint8List>(second.b.inbound);
    final arriving = peerInbox.moveNext();
    await s2.send(MessageType.heartbeat, const {});
    expect(await arriving, isTrue);
    final envelope = decodeEnvelope(await peerCrypto.open(peerInbox.current));
    expect(envelope.senderDeviceId, e.identity.deviceId);
    expect(envelope.type, MessageType.heartbeat);
    await peerInbox.cancel();

    await e.stop();
  });

  test('a link that closes mid-handshake surfaces SessionEstablishmentError',
      () async {
    final a = await identity('Mac');
    final b = await identity('PC');
    final links = FakeLink.connectedPair();

    // The peer is driven by hand so it can go away at the exact moment the
    // device under test is suspended waiting for the key confirmation.
    final peerHandshake = peerHandshakeAgainst(b, a);
    final peerInbox = StreamIterator<Uint8List>(links.b.inbound);
    // Armed before anything is sent: `inbound` is a broadcast stream, and a
    // frame that arrives with no listener attached is simply dropped.
    final firstFromA = peerInbox.moveNext();

    // A generous establishment timeout, so a pass here cannot come from the
    // timeout path; the test's own guard catches a hang instead.
    final pending = SessionEstablisher.establish(
      link: links.a,
      identity: a,
      peer: rosterEntryFor(b),
      timeout: const Duration(seconds: 30),
    ).timeout(
      const Duration(seconds: 5),
      onTimeout: () =>
          throw StateError('establishment hung on a link that closed'),
    );
    final fails =
        expectLater(pending, throwsA(isA<SessionEstablishmentError>()));

    expect(await firstFromA, isTrue);
    await links.b.send(await peerHandshake.start());
    // Stop reading, so the confirmation the device under test is about to
    // send goes nowhere, then tear the link down instead of answering.
    await peerInbox.cancel();
    await links.b.close();

    await fails;
  });

  test('establishment fails within its timeout when the peer never answers',
      () async {
    final a = await identity('Mac');
    final b = await identity('PC');
    // Unpaired: sends succeed and land nowhere, so nothing ever comes back.
    final lonely = FakeLink(id: 'lonely');

    final started = DateTime.now();
    await expectLater(
      SessionEstablisher.establish(
        link: lonely,
        identity: a,
        peer: rosterEntryFor(b),
        timeout: const Duration(milliseconds: 100),
      ),
      throwsA(isA<SessionEstablishmentError>()),
    );
    expect(DateTime.now().difference(started),
        lessThan(const Duration(seconds: 5)));
    expect(lonely.state, LinkState.disconnected);
  });
}
