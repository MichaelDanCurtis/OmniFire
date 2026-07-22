import 'dart:async';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

Future<DeviceIdentity> identity(String name) =>
    loadOrCreateIdentity(store: InMemorySecureStore(), displayName: name);

void main() {
  test('both sides derive the same SAS', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();

    final invite = generateInvite(
      meshId: mesh.meshId,
      inviterPublicKey: inviter.keys.publicKey,
    );

    final invitePending = PairingFlow.invite(
        identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final joinPending =
        PairingFlow.join(identity: joiner, invite: invite, link: links.b);

    final a = await invitePending;
    final b = await joinPending;

    expect(a.sas.length, 5);
    expect(a.sas, b.sas);
  });

  test('confirming on both sides yields matching sessions', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
        meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);

    final aPending = PairingFlow.invite(
        identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final bPending =
        PairingFlow.join(identity: joiner, invite: invite, link: links.b);
    final a = await aPending;
    final b = await bPending;

    final outA = await a.confirm(true);
    final outB = await b.confirm(true);

    expect(outA.peer.deviceId, joiner.deviceId);
    expect(outB.peer.deviceId, inviter.deviceId);
    expect(outB.meshId, mesh.meshId);

    final sealed = await outA.session.seal([1, 2, 3]);
    expect(await outB.session.open(sealed), [1, 2, 3]);
  });

  test('the inviter adds the joiner to the roster on confirm', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
        meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);

    final aPending = PairingFlow.invite(
        identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final bPending =
        PairingFlow.join(identity: joiner, invite: invite, link: links.b);
    final a = await aPending;
    final b = await bPending;

    final outA = await a.confirm(true);
    await b.confirm(true);

    mesh.addPeer(outA.peer);
    expect(mesh.isAuthorized(joiner.deviceId, joiner.keys.publicKey), isTrue);
  });

  test('declining the SAS rejects the pairing', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
        meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);

    final aPending = PairingFlow.invite(
        identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final bPending =
        PairingFlow.join(identity: joiner, invite: invite, link: links.b);
    final a = await aPending;
    final b = await bPending;
    unawaited(b.confirm(true).catchError((Object _) => throw StateError('x')));

    expect(() => a.confirm(false), throwsA(isA<PairingRejectedError>()));
    expect(mesh.peers, isEmpty);
  });

  test('declining closes the link', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
        meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);

    final aPending = PairingFlow.invite(
        identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final bPending =
        PairingFlow.join(identity: joiner, invite: invite, link: links.b);
    final a = await aPending;
    final b = await bPending;

    await expectLater(a.confirm(false), throwsA(isA<PairingRejectedError>()));
    // Declining is not a local no-op: the channel is torn down so the peer
    // cannot go on to confirm a pairing the user has already rejected.
    expect(links.a.state, LinkState.disconnected);
    expect(b.sas, a.sas);
  });

  test('the peer cannot complete a pairing the other side declined', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final inviterMesh = Mesh(meshId: 'a' * 32);
    final joinerMesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
        meshId: inviterMesh.meshId, inviterPublicKey: inviter.keys.publicKey);

    final aPending = PairingFlow.invite(
        identity: inviter, mesh: inviterMesh, invite: invite, link: links.a);
    final bPending =
        PairingFlow.join(identity: joiner, invite: invite, link: links.b);
    final a = await aPending;
    final b = await bPending;

    // The user saw two different words on the two screens and declined on the
    // inviter. Under a man-in-the-middle that is the only signal there is, so
    // the joiner must not be able to complete behind the user's back.
    await expectLater(a.confirm(false), throwsA(isA<PairingRejectedError>()));

    await expectLater(b.confirm(true), throwsA(isA<PairingRejectedError>()));
    expect(inviterMesh.peers, isEmpty);
    expect(joinerMesh.peers, isEmpty);
  });

  test('a decline while the peer awaits a frame is not swallowed', () async {
    final joiner = await identity('PC');
    final inviter = await identity('Mac');
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
        meshId: 'a' * 32, inviterPublicKey: inviter.keys.publicKey);

    // The inviting side is driven by hand so that it can abandon the exchange
    // at the exact moment the joiner is suspended waiting for a frame.
    final handshake = OmniFiHandshakeV1.initiator(
      staticKeys: inviter.keys,
      deviceId: inviter.deviceId,
      expectedPeerStaticPublicKey: null,
      psk: invite.psk,
    );
    final peerFrames = StreamIterator<Uint8List>(links.a.inbound);

    final bPending = PairingFlow.join(
      identity: joiner,
      invite: invite,
      link: links.b,
    ).timeout(
      const Duration(seconds: 5),
      onTimeout: () => throw StateError('the joiner hung on a closed link'),
    );
    // Attached before the link is torn down: the joiner's failure must be
    // caught as it happens, not left to surface as an unhandled async error.
    final joinerFails =
        expectLater(bPending, throwsA(isA<PairingRejectedError>()));

    await links.a.send(await handshake.start());
    expect(await peerFrames.moveNext(), isTrue);
    // The joiner is now blocked awaiting our key confirmation. Instead of
    // sending it, decline: close the link out from under the awaited read.
    await peerFrames.cancel();
    await links.a.close();

    await joinerFails;
  });

  test('a wrong PSK produces a different SAS on each side', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();

    final realInvite = generateInvite(
        meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);
    final wrongPskInvite = PairingInvite(
      meshId: realInvite.meshId,
      inviterPublicKey: realInvite.inviterPublicKey,
      psk: List<int>.filled(32, 0xFF),
    );

    final aPending = PairingFlow.invite(
        identity: inviter, mesh: mesh, invite: realInvite, link: links.a);
    final bPending =
        PairingFlow.join(identity: joiner, invite: wrongPskInvite, link: links.b);
    final a = await aPending;
    final b = await bPending;

    // This is exactly what the user is asked to catch: the two screens
    // disagree, so the pairing is a man-in-the-middle or a mistyped code.
    expect(a.sas, isNot(b.sas));
  });
}
