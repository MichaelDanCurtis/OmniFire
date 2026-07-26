import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('rendezvousIdFor is deterministic for one psk', () async {
    final psk = [for (var i = 0; i < 32; i++) i];
    expect(await rendezvousIdFor(psk), await rendezvousIdFor(psk));
    // A fresh list with the same contents, so the answer cannot be coming
    // from identity of the argument.
    expect(await rendezvousIdFor(psk), await rendezvousIdFor(List.of(psk)));
  });

  test('rendezvousIdFor is 32 lowercase hex characters', () async {
    for (final psk in [
      List<int>.filled(32, 0),
      List<int>.filled(32, 255),
      [for (var i = 0; i < 32; i++) (i * 7 + 3) % 256],
    ]) {
      final id = await rendezvousIdFor(psk);
      expect(id, matches(RegExp(r'^[0-9a-f]{32}$')),
          reason: 'the relay routes on a 32-lowercase-hex mesh id and '
              'rejects anything else with an HTTP 400 before the upgrade');
    }
  });

  test('rendezvousIdFor differs for psks that differ in one bit', () async {
    final a = List<int>.filled(32, 0);
    final b = List<int>.filled(32, 0)..[31] = 1;
    expect(await rendezvousIdFor(a), isNot(await rendezvousIdFor(b)));
  });

  test('rendezvousIdFor differs from the psk it was derived from', () async {
    // Guards the derivation actually happening. A "derivation" that hexed the
    // first 16 bytes of the psk straight through would satisfy every other
    // assertion here, and would publish half the pairing secret as a routing
    // key the relay logs.
    final psk = [for (var i = 0; i < 32; i++) i];
    final hexPrefix = [
      for (var i = 0; i < 16; i++) psk[i].toRadixString(16).padLeft(2, '0'),
    ].join();
    expect(await rendezvousIdFor(psk), isNot(hexPrefix));
  });

  test('rendezvousIdFor refuses an empty psk', () async {
    await expectLater(
        rendezvousIdFor(const []), throwsA(isA<RendezvousError>()));
  });

  test('an invite and a copy of it agree on the rendezvous', () async {
    final invite = generateInvite(
      meshId: 'a' * 32,
      inviterPublicKey: List<int>.filled(32, 3),
    );
    // What the joiner actually holds: the invite as it came back off the QR.
    final scanned = decodeInviteUri(encodeInviteUri(invite));
    expect(await rendezvousIdFor(scanned.psk),
        await rendezvousIdFor(invite.psk));
  });
}
