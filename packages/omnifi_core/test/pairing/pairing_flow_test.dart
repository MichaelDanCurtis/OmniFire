import 'dart:async';

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
