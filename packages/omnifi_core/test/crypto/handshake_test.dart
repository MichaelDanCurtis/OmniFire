import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

Future<
    ({
      HandshakeResult i,
      HandshakeResult r,
      StaticKeyPair ik,
      StaticKeyPair rk,
    })> run({
  List<int> psk = const [],
  bool corruptResponderKey = false,
  bool anonymous = false,
}) async {
  final ik = await OmniFiHandshakeV1.generateStaticKeys();
  final rk = await OmniFiHandshakeV1.generateStaticKeys();
  final wrong = await OmniFiHandshakeV1.generateStaticKeys();

  final initiator = OmniFiHandshakeV1.initiator(
    staticKeys: ik,
    deviceId: 'aaaa',
    expectedPeerStaticPublicKey: anonymous
        ? null
        : (corruptResponderKey ? wrong.publicKey : rk.publicKey),
    psk: psk,
  );
  final responder = OmniFiHandshakeV1.responder(
    staticKeys: rk,
    deviceId: 'bbbb',
    expectedPeerStaticPublicKey: anonymous ? null : ik.publicKey,
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
    ik: ik,
    rk: rk,
  );
}

/// The ciphertext body of a sealed frame: [8-byte counter][ct][16-byte mac].
List<int> body(List<int> sealed) =>
    sealed.sublist(AeadSession.counterBytes, sealed.length - AeadSession.macBytes);

List<int> xorBytes(List<int> a, List<int> b) {
  final n = a.length < b.length ? a.length : b.length;
  return List<int>.generate(n, (i) => a[i] ^ b[i]);
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

  test('each side learns the peer static public key from the wire', () async {
    final out = await run();
    expect(out.i.peerStaticPublicKey, out.rk.publicKey);
    expect(out.r.peerStaticPublicKey, out.ik.publicKey);
  });

  test('the learned peer static key is read from the wire when unexpected',
      () async {
    // No expectation configured, so the key cannot be an echo of an argument.
    final out = await run(anonymous: true, psk: List<int>.filled(32, 5));
    expect(out.i.peerStaticPublicKey, out.rk.publicKey);
    expect(out.r.peerStaticPublicKey, out.ik.publicKey);
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

  test('confirmation and the first data frame do not share a keystream',
      () async {
    final ik = await OmniFiHandshakeV1.generateStaticKeys();
    final rk = await OmniFiHandshakeV1.generateStaticKeys();

    final initiator = OmniFiHandshakeV1.initiator(
      staticKeys: ik,
      deviceId: 'aaaa',
      expectedPeerStaticPublicKey: rk.publicKey,
    );
    final responder = OmniFiHandshakeV1.responder(
      staticKeys: rk,
      deviceId: 'bbbb',
      expectedPeerStaticPublicKey: ik.publicKey,
    );

    final m1 = await initiator.start();
    final m2 = await responder.start();
    final ic = await initiator.confirmationFor(m2);
    final rc = await responder.confirmationFor(m1);

    final iOut = await initiator.complete(m2, rc);
    await responder.complete(m1, ic);

    // The initiator's confirmation and its first data frame are both sent
    // i2r. If they are sealed under the same key at the same counter, the
    // keystreams coincide and the public confirmation constant discloses the
    // first bytes of the data frame.
    const confirmPlaintext = 'omnifi-confirm';
    final dataPlaintext = utf8.encode('SECRET-PAYLOAD-0123456789');
    final dataFrame = await iOut.session.seal(dataPlaintext);

    final ksConfirm = xorBytes(body(ic), utf8.encode(confirmPlaintext));
    final ksData = xorBytes(body(dataFrame), dataPlaintext);
    final overlap = ksConfirm.length < ksData.length
        ? ksConfirm.length
        : ksData.length;
    expect(overlap, greaterThan(0));
    expect(
      ksConfirm.sublist(0, overlap),
      isNot(equals(ksData.sublist(0, overlap))),
      reason: 'confirmation and first data frame reuse the same keystream',
    );
  });

  test('pairing (no expected peer static key) with a matching psk succeeds',
      () async {
    final out = await run(anonymous: true, psk: List<int>.filled(32, 3));
    expect(out.i.master, out.r.master);
    final sealed = await out.i.session.seal(utf8.encode('paired'));
    expect(utf8.decode(await out.r.session.open(sealed)), 'paired');
  });

  test('a mismatched expected peer static key is reported as such', () async {
    Object? caught;
    try {
      await run(corruptResponderKey: true);
    } catch (e) {
      caught = e;
    }
    expect(caught, isA<HandshakeError>());
    expect(
      (caught as HandshakeError).reason.toLowerCase(),
      contains('static'),
      reason: 'must name the static-key mismatch, not a confirmation failure',
    );
  });

  test('start() twice on one instance throws', () async {
    final ik = await OmniFiHandshakeV1.generateStaticKeys();
    final hs = OmniFiHandshakeV1.initiator(staticKeys: ik, deviceId: 'aaaa');
    await hs.start();
    expect(hs.start(), throwsA(isA<HandshakeError>()));
  });

  test('complete() with a different peer message than confirmationFor() throws',
      () async {
    final ik = await OmniFiHandshakeV1.generateStaticKeys();
    final rk = await OmniFiHandshakeV1.generateStaticKeys();
    final other = OmniFiHandshakeV1.responder(
        staticKeys: rk, deviceId: 'cccc');
    final otherMessage = await other.start();

    final initiator = OmniFiHandshakeV1.initiator(
        staticKeys: ik, deviceId: 'aaaa');
    final responder = OmniFiHandshakeV1.responder(
        staticKeys: rk, deviceId: 'bbbb');
    final m1 = await initiator.start();
    final m2 = await responder.start();
    final rc = await responder.confirmationFor(m1);
    await initiator.confirmationFor(m2);

    expect(initiator.complete(otherMessage, rc),
        throwsA(isA<HandshakeError>()));
  });

  test('malformed peer messages are rejected', () async {
    final ik = await OmniFiHandshakeV1.generateStaticKeys();
    final peer = await OmniFiHandshakeV1.generateStaticKeys();
    final e32 = List<int>.filled(32, 9);

    Uint8List encode(Map<String, Object?> m) =>
        Uint8List.fromList(cbor.encode(CborValue(m)));

    final cases = <String, Uint8List>{
      'wrong version': encode({
        'v': omnifiProtocolVersion + 1,
        'id': 'bbbb',
        'e': CborBytes(e32),
        's': CborBytes(peer.publicKey),
      }),
      'missing id': encode({
        'v': omnifiProtocolVersion,
        'e': CborBytes(e32),
        's': CborBytes(peer.publicKey),
      }),
      'empty id': encode({
        'v': omnifiProtocolVersion,
        'id': '',
        'e': CborBytes(e32),
        's': CborBytes(peer.publicKey),
      }),
      'short static key': encode({
        'v': omnifiProtocolVersion,
        'id': 'bbbb',
        'e': CborBytes(e32),
        's': CborBytes(List<int>.filled(31, 4)),
      }),
      'missing static key': encode({
        'v': omnifiProtocolVersion,
        'id': 'bbbb',
        'e': CborBytes(e32),
      }),
      'short ephemeral key': encode({
        'v': omnifiProtocolVersion,
        'id': 'bbbb',
        'e': CborBytes(List<int>.filled(31, 4)),
        's': CborBytes(peer.publicKey),
      }),
      'not a map': Uint8List.fromList(cbor.encode(CborValue(<Object?>[1, 2]))),
    };

    for (final entry in cases.entries) {
      final hs = OmniFiHandshakeV1.initiator(staticKeys: ik, deviceId: 'aaaa');
      await hs.start();
      expect(
        hs.confirmationFor(entry.value),
        throwsA(isA<HandshakeError>()),
        reason: 'case: ${entry.key}',
      );
    }
  });
}
