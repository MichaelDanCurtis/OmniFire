import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('service type is the documented one', () {
    expect(omnifiServiceType, '_omnifi._tcp');
  });

  test('listener binds to an ephemeral port', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    expect(listener.port, greaterThan(0));
    await listener.close();
  });

  test('a dialed link exchanges frames with the accepted link', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;

    final dialed = await LanLink.dial(
      LanEndpoint(
        deviceId: '1' * 32,
        address: InternetAddress.loopbackIPv4,
        port: listener.port,
      ),
      peerDeviceId: '1' * 32,
    );
    final accepted = await acceptedFuture;

    final received = accepted.inbound.first;
    await dialed.send(utf8.encode('over the lan'));
    expect(utf8.decode(await received), 'over the lan');

    await dialed.close();
    await accepted.close();
    await listener.close();
  });

  test('reassembles a frame split across TCP writes', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final socket = await Socket.connect(
        InternetAddress.loopbackIPv4, listener.port);
    final accepted = await acceptedFuture;

    final received = accepted.inbound.first;
    final frame = encodeFrame(utf8.encode('deliberately split'));
    socket.add(frame.sublist(0, 6));
    await socket.flush();
    await Future<void>.delayed(const Duration(milliseconds: 20));
    socket.add(frame.sublist(6));
    await socket.flush();

    expect(utf8.decode(await received), 'deliberately split');

    await socket.close();
    await accepted.close();
    await listener.close();
  });

  test('delivers two frames arriving in one TCP write', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final socket = await Socket.connect(
        InternetAddress.loopbackIPv4, listener.port);
    final accepted = await acceptedFuture;

    final frames = <String>[];
    accepted.inbound.listen((f) => frames.add(utf8.decode(f)));
    socket.add([
      ...encodeFrame(utf8.encode('first')),
      ...encodeFrame(utf8.encode('second')),
    ]);
    await socket.flush();
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(frames, ['first', 'second']);

    await socket.close();
    await accepted.close();
    await listener.close();
  });

  test('reports lan kind and is preferred over relay', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final dialed = await LanLink.dial(
      LanEndpoint(
        deviceId: '1' * 32,
        address: InternetAddress.loopbackIPv4,
        port: listener.port,
      ),
      peerDeviceId: '1' * 32,
    );
    await acceptedFuture;

    expect(dialed.kind, LinkKind.lan);
    expect(dialed.quality.isDirect, isTrue);
    expect(
      dialed.quality.preferenceScore,
      lessThan(const LinkQuality(kind: LinkKind.relay).preferenceScore),
    );

    await dialed.close();
    await listener.close();
  });

  test('peer disconnect moves the link to disconnected', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final dialed = await LanLink.dial(
      LanEndpoint(
        deviceId: '1' * 32,
        address: InternetAddress.loopbackIPv4,
        port: listener.port,
      ),
      peerDeviceId: '1' * 32,
    );
    final accepted = await acceptedFuture;

    await dialed.close();
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(accepted.state, LinkState.disconnected);

    await accepted.close();
    await listener.close();
  });

  test('dialing a closed port fails rather than hanging', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final port = listener.port;
    await listener.close();

    expect(
      () => LanLink.dial(
        LanEndpoint(
          deviceId: '1' * 32,
          address: InternetAddress.loopbackIPv4,
          port: port,
        ),
        peerDeviceId: '1' * 32,
        timeout: const Duration(milliseconds: 500),
      ),
      throwsA(anything),
    );
  });

  test('static discovery yields its configured endpoints', () async {
    final discovery = StaticDiscovery([
      LanEndpoint(
        deviceId: '2' * 32,
        address: InternetAddress.loopbackIPv4,
        port: 9999,
      ),
    ]);
    final found = await discovery.discover().toList();
    expect(found.single.deviceId, '2' * 32);
    expect(found.single.port, 9999);
  });

  test(
      'a peer closing mid-send surfaces LinkClosedError, not a raw '
      'SocketException', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final dialed = await LanLink.dial(
      LanEndpoint(
        deviceId: '1' * 32,
        address: InternetAddress.loopbackIPv4,
        port: listener.port,
      ),
      peerDeviceId: '1' * 32,
    );
    final accepted = await acceptedFuture;

    // Close the remote end abruptly. Per dart:io IOSink semantics, a write
    // failure on the now-dead socket is not thrown synchronously from
    // add() -- it surfaces on the following flush(). Looping a bounded
    // number of times (rather than assuming the very first attempt fails)
    // keeps this portable across platforms/kernels with different timing;
    // each iteration records the link's state immediately before that
    // attempt, so whichever attempt fails, we know whether it started
    // connected.
    await accepted.close();

    Object? caught;
    var stateJustBeforeFailingSend = LinkState.connected;
    for (var attempt = 0; attempt < 20 && caught == null; attempt++) {
      final stateBefore = dialed.state;
      try {
        // A largish frame forces a real write attempt rather than one
        // fully absorbed by internal buffering before ever reaching the
        // OS.
        await dialed.send(List<int>.filled(900000, 0x41));
      } catch (e) {
        caught = e;
        stateJustBeforeFailingSend = stateBefore;
      }
    }

    expect(caught, isA<LinkClosedError>());
    // The point of this test: the failure must come from send() catching
    // the write itself, not from the pre-existing `_state != connected`
    // guard -- otherwise this would already pass without the fix.
    expect(
      stateJustBeforeFailingSend,
      LinkState.connected,
      reason: 'the failing send() must have started while still connected, '
          'proving it reached the write path rather than short-circuiting '
          'on the pre-write state check',
    );
    // And the link must stop looking like a candidate to LinkManager.
    expect(dialed.state, isNot(LinkState.connected));

    await dialed.close();
    await listener.close();
  });

  test(
      'a declared length over the 1 MiB cap tears the link down instead of '
      'buffering', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final socket =
        await Socket.connect(InternetAddress.loopbackIPv4, listener.port);
    final accepted = await acceptedFuture;

    // Write only the raw 4-byte big-endian length prefix, declaring more
    // than the 1 MiB cap -- directly on the socket, bypassing
    // LanLink.send()/encodeFrame() (which refuse to construct such a frame
    // in the first place) so the receive path is exercised exactly as a
    // hostile or buggy peer would drive it. No payload bytes are needed:
    // FrameDecoder rejects an over-cap declared length as soon as it reads
    // the prefix, without ever waiting for that much payload to arrive.
    final prefix = ByteData(4)..setUint32(0, maxFrameBytes + 1);
    socket.add(prefix.buffer.asUint8List());
    await socket.flush();

    await accepted.states
        .firstWhere((s) => s != LinkState.connected)
        .timeout(const Duration(seconds: 2));
    expect(accepted.state, LinkState.disconnected);

    await socket.close();
    socket.destroy();
    await listener.close();
  });
}
