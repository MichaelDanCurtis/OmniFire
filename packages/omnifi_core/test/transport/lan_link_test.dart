import 'dart:convert';
import 'dart:io';

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
}
