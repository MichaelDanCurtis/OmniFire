@Tags(['integration'])
library;

import 'dart:convert';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

// ignore_for_file: avoid_print

/// Requires a relay at http://localhost:8787.
/// Start it with: cd relay && npx wrangler dev --port 8787
void main() {
  final base = Uri.parse('http://localhost:8787');
  const meshId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const deviceA = '11111111111111111111111111111111';
  const deviceB = '22222222222222222222222222222222';

  test('two links exchange frames through the live relay', () async {
    final a = await RelayLink.connect(
      relayBase: base,
      meshId: meshId,
      localDeviceId: deviceA,
      peerDeviceId: deviceB,
    );
    final b = await RelayLink.connect(
      relayBase: base,
      meshId: meshId,
      localDeviceId: deviceB,
      peerDeviceId: deviceA,
    );

    final received = b.inbound.first;
    await a.send(utf8.encode('through the relay'));
    expect(utf8.decode(await received), 'through the relay');

    await a.close();
    await b.close();
  });

  test('a full session survives a relay round trip', () async {
    final k1 = List<int>.filled(32, 11);
    final k2 = List<int>.filled(32, 22);
    int clock() => 1753200000000;

    final sa = PeerSession(
      localDeviceId: deviceA,
      peerDeviceId: deviceB,
      crypto: AeadSession(sendKey: k1, receiveKey: k2),
      clock: clock,
    );
    final sb = PeerSession(
      localDeviceId: deviceB,
      peerDeviceId: deviceA,
      crypto: AeadSession(sendKey: k2, receiveKey: k1),
      clock: clock,
    );

    sa.attach(await RelayLink.connect(
      relayBase: base,
      meshId: meshId,
      localDeviceId: deviceA,
      peerDeviceId: deviceB,
    ));
    sb.attach(await RelayLink.connect(
      relayBase: base,
      meshId: meshId,
      localDeviceId: deviceB,
      peerDeviceId: deviceA,
    ));

    final received = sb.inbound.first;
    await sa.send(MessageType.clipboardUpdate, {'text': 'encrypted'});
    expect((await received).payload['text'], 'encrypted');

    await sa.dispose();
    await sb.dispose();
  });

  test(
      'connect fails promptly, not with a timeout, when the relay rejects '
      'a malformed device id before the upgrade', () async {
    final stopwatch = Stopwatch()..start();
    await expectLater(
      RelayLink.connect(
        relayBase: base,
        meshId: meshId,
        localDeviceId: 'not-a-valid-hex-device-id',
        peerDeviceId: deviceB,
        timeout: const Duration(seconds: 10),
      ),
      throwsA(anything),
    );
    stopwatch.stop();
    // The relay answers with a plain HTTP 400 before the WebSocket upgrade
    // completes, so this should fail almost immediately, not after the 10s
    // timeout.
    expect(stopwatch.elapsedMilliseconds, lessThan(3000));
  });

  // ---- Pairing rendezvous (Task 29) ----
  //
  // Every test below runs against the *real* relay deliberately. The
  // rendezvous exists to make two devices that are in nobody's roster meet in
  // a Durable Object derived from the QR's pre-shared key, and the properties
  // that matter — a derived mesh id is a valid routing key, a broadcast
  // reaches every other socket in the DO, a targeted frame reaches only the
  // socket tagged with that device id — are properties of the relay, not of
  // any double this package could write.

  PairingInvite freshInvite() => generateInvite(
        meshId: randomHexId(),
        inviterPublicKey: List<int>.filled(32, 9),
      );

  Future<DeviceIdentity> identity(String name) =>
      loadOrCreateIdentity(store: InMemorySecureStore(), displayName: name);

  test('two rendezvous sides find each other and carry frames both ways',
      () async {
    final invite = freshInvite();

    // Started together. The joiner announces itself on an interval, so it does
    // not matter which of the two reaches the Durable Object first.
    final inviterFuture = PairingRendezvous.awaitJoiner(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final joinerFuture = PairingRendezvous.connectToInviter(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final inviterLink = await inviterFuture;
    final joinerLink = await joinerFuture;

    final atJoiner = joinerLink.inbound.first;
    await inviterLink.send(utf8.encode('inviter to joiner'));
    expect(utf8.decode(await atJoiner), 'inviter to joiner');

    final atInviter = inviterLink.inbound.first;
    await joinerLink.send(utf8.encode('joiner to inviter'));
    expect(utf8.decode(await atInviter), 'joiner to inviter');

    await inviterLink.close();
    await joinerLink.close();
  });

  test('a full pairing completes over the rendezvous', () async {
    final inviterIdentity = await identity('Mac');
    final joinerIdentity = await identity('Phone');
    final inviterMesh = Mesh(meshId: randomHexId());
    final joinerMesh = Mesh(meshId: randomHexId());

    final invite = generateInvite(
      meshId: inviterMesh.meshId,
      inviterPublicKey: inviterIdentity.keys.publicKey,
    );
    // The joiner works from the invite as it comes back off the QR, not from
    // the inviter's own object.
    final scanned = decodeInviteUri(encodeInviteUri(invite));

    final inviterFuture = PairingRendezvous.awaitJoiner(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final joinerFuture = PairingRendezvous.connectToInviter(
      invite: scanned,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final inviterLink = await inviterFuture;
    final joinerLink = await joinerFuture;

    final invitePending = PairingFlow.invite(
      identity: inviterIdentity,
      mesh: inviterMesh,
      invite: invite,
      link: inviterLink,
    );
    final joinPending = PairingFlow.join(
      identity: joinerIdentity,
      invite: scanned,
      link: joinerLink,
    );
    final onInviter = await invitePending;
    final onJoiner = await joinPending;

    print('SAS on the inviter: ${formatSas(onInviter.sas)}');
    print('SAS on the joiner:  ${formatSas(onJoiner.sas)}');
    expect(onInviter.sas, onJoiner.sas);
    expect(onInviter.sas, hasLength(5));

    final inviterOutcome = await onInviter.confirm(true);
    final joinerOutcome = await onJoiner.confirm(true);

    inviterMesh.addPeer(inviterOutcome.peer);
    joinerMesh.addPeer(joinerOutcome.peer);

    expect(inviterMesh.peer(joinerIdentity.deviceId), isNotNull,
        reason: 'the inviter must end holding a roster entry for the joiner');
    expect(joinerMesh.peer(inviterIdentity.deviceId), isNotNull,
        reason: 'the joiner must end holding a roster entry for the inviter');
    expect(joinerOutcome.meshId, inviterMesh.meshId,
        reason: 'the joiner joins the inviter\'s mesh, not one of its own');

    // The sessions the pairing produced really are each other's.
    final sealed = await inviterOutcome.session.seal([4, 2]);
    expect(await joinerOutcome.session.open(sealed), [4, 2]);

    await inviterLink.close();
    await joinerLink.close();
  });

  test('a joiner with the wrong psk lands in a different namespace and times '
      'out', () async {
    final invite = freshInvite();
    final wrong = PairingInvite(
      meshId: invite.meshId,
      inviterPublicKey: invite.inviterPublicKey,
      // One bit off, as a mistyped or relayed code would be.
      psk: [...invite.psk.take(31), invite.psk[31] ^ 1],
    );
    expect(await rendezvousIdFor(wrong.psk),
        isNot(await rendezvousIdFor(invite.psk)));

    final inviterFuture = PairingRendezvous.awaitJoiner(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 6),
    );

    await expectLater(
      PairingRendezvous.connectToInviter(
        invite: wrong,
        relayBase: base,
        timeout: const Duration(seconds: 3),
      ),
      throwsA(isA<RendezvousError>()),
    );
    // And the inviter is still waiting for a joiner that will never arrive: it
    // never saw the wrong-psk device at all.
    await expectLater(inviterFuture, throwsA(isA<RendezvousError>()));
  });

  test('an inviter that no joiner reaches times out and closes its socket',
      () async {
    final invite = freshInvite();
    RelayLink? socket;

    await expectLater(
      PairingRendezvous.awaitJoiner(
        invite: invite,
        relayBase: base,
        timeout: const Duration(seconds: 2),
        debugOnSocket: (s) => socket = s,
      ),
      throwsA(isA<RendezvousError>()),
    );

    // The socket is the point. A timeout that threw but left the WebSocket
    // open would leak it into the Durable Object for the whole idle lifetime
    // of the rendezvous, and the next attempt with the same QR would find a
    // stale, deaf inviter sitting in the namespace.
    expect(socket, isNotNull);
    expect(socket!.state, isNot(LinkState.connected));
  });

  test('a frame sent before the caller subscribes is not dropped', () async {
    // The hazard this whole package keeps being bitten by. The moment a
    // rendezvous returns, the peer's rendezvous has returned too and its
    // caller may already be sending; the local caller does not subscribe until
    // it reaches PairingFlow, which is several suspensions later — an X25519
    // key generation, at least. Over a raw broadcast stream a frame landing in
    // that window is discarded, and the symptom is an intermittent hang with
    // no diagnostic rather than a clean failure.
    final invite = freshInvite();
    final inviterFuture = PairingRendezvous.awaitJoiner(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final joinerFuture = PairingRendezvous.connectToInviter(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final inviterLink = await inviterFuture;
    final joinerLink = await joinerFuture;

    await inviterLink.send(utf8.encode('sent before anyone was listening'));
    // Long enough that the frame has certainly been delivered to the joiner's
    // socket and offered to its inbound stream.
    await Future<void>.delayed(const Duration(milliseconds: 500));

    expect(
      utf8.decode(await joinerLink.inbound.first
          .timeout(const Duration(seconds: 5))),
      'sent before anyone was listening',
    );

    await inviterLink.close();
    await joinerLink.close();
  });

  test('the exchange is addressed to the peer, not fanned out to the '
      'namespace', () async {
    final invite = freshInvite();
    // Anyone who has seen the QR can derive the namespace and sit in it. That
    // is expected and is not what the rendezvous defends — the SAS is. What
    // must not happen is that they are *handed* the exchange: once the two
    // sides have found each other, every frame carries the peer's ephemeral id
    // in its header and the relay routes it to that socket alone.
    final observer = await RelayLink.connect(
      relayBase: base,
      meshId: await rendezvousIdFor(invite.psk),
      localDeviceId: randomHexId(),
      peerDeviceId: broadcastDeviceId,
    );
    final seen = <List<int>>[];
    final watching = observer.inbound.listen(seen.add);

    final inviterFuture = PairingRendezvous.awaitJoiner(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final joinerFuture = PairingRendezvous.connectToInviter(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final inviterLink = await inviterFuture;
    final joinerLink = await joinerFuture;

    // The joiner's announcements are broadcast by design — that is how it is
    // found at all — so the observer legitimately saw those. Nothing after
    // this point may reach it.
    seen.clear();
    await inviterLink.send(utf8.encode('inviter payload'));
    await joinerLink.send(utf8.encode('joiner payload'));
    await Future<void>.delayed(const Duration(milliseconds: 500));
    expect(seen, isEmpty);

    await watching.cancel();
    await observer.close();
    await inviterLink.close();
    await joinerLink.close();
  });

  test('two joiners in one namespace never pair with each other', () async {
    // A joiner announces itself by *broadcast*, so a second joiner at the same
    // rendezvous receives it. Nothing but the role in the hello stops the two
    // of them latching onto each other and running a pairing neither user
    // asked for, while the inviter they both meant to reach waits unanswered.
    final invite = freshInvite();
    final first = PairingRendezvous.connectToInviter(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 3),
    );
    final second = PairingRendezvous.connectToInviter(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 3),
    );
    // Both expectations are registered before either is awaited. The two time
    // out within milliseconds of each other, and a future that fails while
    // nothing is listening to it is reported as an unhandled async error —
    // which fails the test for the wrong reason, intermittently.
    final firstTimedOut = expectLater(first, throwsA(isA<RendezvousError>()));
    final secondTimedOut = expectLater(second, throwsA(isA<RendezvousError>()));
    await firstTimedOut;
    await secondTimedOut;
  });

  test('a second joiner is ignored and the first pairing still completes',
      () async {
    final inviterIdentity = await identity('Mac');
    final joinerIdentity = await identity('Phone');
    final inviterMesh = Mesh(meshId: randomHexId());
    final invite = generateInvite(
      meshId: inviterMesh.meshId,
      inviterPublicKey: inviterIdentity.keys.publicKey,
    );

    final inviterFuture = PairingRendezvous.awaitJoiner(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final firstFuture = PairingRendezvous.connectToInviter(
      invite: invite,
      relayBase: base,
      timeout: const Duration(seconds: 20),
    );
    final inviterLink = await inviterFuture;
    final firstLink = await firstFuture;

    // A second device scans the same QR after the first has been accepted, and
    // announces itself by broadcast for four seconds — so its hellos land on
    // both already-latched sockets, repeatedly, before the pairing below runs.
    await expectLater(
      PairingRendezvous.connectToInviter(
        invite: invite,
        relayBase: base,
        timeout: const Duration(seconds: 4),
      ),
      throwsA(isA<RendezvousError>()),
    );

    // The pairing runs *after* all of that interference, deliberately. It can
    // only succeed if the second joiner changed nothing: the inviter must
    // still be addressing the first joiner (a link re-pointed at the second
    // device is now addressing a socket that has closed, and the handshake
    // never completes), and neither side may have handed a hello to
    // PairingFlow as though it were a handshake message.
    final invitePending = PairingFlow.invite(
      identity: inviterIdentity,
      mesh: inviterMesh,
      invite: invite,
      link: inviterLink,
    );
    final joinPending = PairingFlow.join(
      identity: joinerIdentity,
      invite: invite,
      link: firstLink,
    );
    final onInviter =
        await invitePending.timeout(const Duration(seconds: 10));
    final onJoiner = await joinPending.timeout(const Duration(seconds: 10));
    expect(onInviter.sas, onJoiner.sas);

    await inviterLink.close();
    await firstLink.close();
  });
}
