import 'dart:convert';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

Future<({HandshakeResult i, HandshakeResult r})> run({
  List<int> psk = const [],
  bool corruptResponderKey = false,
}) async {
  final ik = await OmniFiHandshakeV1.generateStaticKeys();
  final rk = await OmniFiHandshakeV1.generateStaticKeys();
  final wrong = await OmniFiHandshakeV1.generateStaticKeys();

  final initiator = OmniFiHandshakeV1.initiator(
    staticKeys: ik,
    deviceId: 'aaaa',
    peerStaticPublicKey:
        corruptResponderKey ? wrong.publicKey : rk.publicKey,
    psk: psk,
  );
  final responder = OmniFiHandshakeV1.responder(
    staticKeys: rk,
    deviceId: 'bbbb',
    peerStaticPublicKey: ik.publicKey,
    psk: psk,
  );

  final m1 = await initiator.start();
  final m2 = await responder.start();
  // Each side must ingest the peer message before it can confirm.
  final ic = await initiator.confirmationFor(m2);
  final rc = await responder.confirmationFor(m1);

  return (
    i: await initiator.complete(m2, rc),
    r: await responder.complete(m1, ic),
  );
}

void main() {
  test('both sides derive matching directional keys', () async {
    final out = await run();
    final sealed = await out.i.session.seal(utf8.encode('ping'));
    expect(utf8.decode(await out.r.session.open(sealed)), 'ping');

    final back = await out.r.session.seal(utf8.encode('pong'));
    expect(utf8.decode(await out.i.session.open(back)), 'pong');
  });

  test('both sides derive the same transcript', () async {
    final out = await run();
    expect(out.i.transcript, out.r.transcript);
  });

  test('each side learns the peer static public key', () async {
    final out = await run();
    expect(out.i.peerStaticPublicKey.length, 32);
    expect(out.r.peerStaticPublicKey.length, 32);
  });

  test('a psk changes the derived master secret', () async {
    final withoutPsk = await run();
    final withPsk = await run(psk: List<int>.filled(32, 7));
    expect(withPsk.i.master, isNot(equals(withoutPsk.i.master)));
  });

  test('handshake fails when the responder static key is wrong', () async {
    expect(
      () => run(corruptResponderKey: true),
      throwsA(isA<HandshakeError>()),
    );
  });

  test('two runs with the same static keys derive different sessions',
      () async {
    final first = await run();
    final second = await run();
    expect(first.i.master, isNot(equals(second.i.master)));
  });
}
