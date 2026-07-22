import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('AEAD known-answer vectors', () {
    test('vector 1: counter 0, empty aad', () async {
      final s = AeadSession(
        sendKey: List<int>.filled(32, 0x01),
        receiveKey: List<int>.filled(32, 0x02),
      );
      final sealed = await s.seal(utf8.encode('omnifi'));
      // Regenerate with: dart test --name 'vector 1' -r expanded
      // and paste the printed value. Do NOT edit this without a
      // deliberate wire-format version bump.
      expect(hex(sealed), _vector1);
    });

    test('vector 2: counter 0, non-empty aad', () async {
      final s = AeadSession(
        sendKey: List<int>.filled(32, 0x01),
        receiveKey: List<int>.filled(32, 0x02),
      );
      final sealed =
          await s.seal(utf8.encode('omnifi'), aad: utf8.encode('bind'));
      expect(hex(sealed), _vector2);
    });

    test('vector 3: counter 5 after five seals', () async {
      final s = AeadSession(
        sendKey: List<int>.filled(32, 0x01),
        receiveKey: List<int>.filled(32, 0x02),
      );
      for (var i = 0; i < 5; i++) {
        await s.seal(utf8.encode('pad'));
      }
      final sealed = await s.seal(utf8.encode('omnifi'));
      expect(hex(sealed), _vector3);
      expect(sealed.sublist(0, 8), [0, 0, 0, 0, 0, 0, 0, 5]);
    });
  });

  test('frame layout is counter || ciphertext || mac', () async {
    final s = AeadSession(
      sendKey: List<int>.filled(32, 0x01),
      receiveKey: List<int>.filled(32, 0x02),
    );
    final plaintext = utf8.encode('twelve bytes');
    final sealed = await s.seal(plaintext);
    expect(sealed.length,
        AeadSession.counterBytes + plaintext.length + AeadSession.macBytes);
  });

  test('handshake message is CBOR with v, id, 32-byte e and 32-byte s',
      () async {
    final keys = await OmniFiHandshakeV1.generateStaticKeys();
    final peer = await OmniFiHandshakeV1.generateStaticKeys();
    final h = OmniFiHandshakeV1.initiator(
      staticKeys: keys,
      deviceId: 'cafebabe',
      expectedPeerStaticPublicKey: peer.publicKey,
    );
    final m = await h.start();
    expect(m, isA<Uint8List>());

    final decoded = cbor.decode(m).toObject();
    expect(decoded, isA<Map<Object?, Object?>>());
    final map = decoded as Map<Object?, Object?>;
    expect(map['id'], 'cafebabe');

    final e = map['e'];
    expect(e, isA<List<int>>());
    expect((e as List<int>).length, 32);

    final s = map['s'];
    expect(s, isA<List<int>>());
    expect((s as List<int>).length, 32);
    expect(s, keys.publicKey);
  });
}

// Filled in by Step 2. These are the pinned wire-format vectors.
const _vector1 =
    '00000000000000006e4a23b8883b53e773c6a31ac48a0e7da87945dd51ce';
const _vector2 =
    '00000000000000006e4a23b8883b7bdc0da19cfef4d3f6435408961da840';
const _vector3 =
    '0000000000000005478c5b19d41daa36a5facb25c64c9a6300e86d799f95';
