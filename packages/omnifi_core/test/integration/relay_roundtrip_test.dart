@Tags(['integration'])
library;

import 'dart:convert';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

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
}
