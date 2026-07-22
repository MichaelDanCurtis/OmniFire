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

  test('two simultaneous inbound connections get distinct provisional ids',
      () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final linksFuture = listener.incoming.take(2).toList();

    // Both come from loopback, so only the port could possibly tell these
    // two apart in this environment -- which is exactly why this is the
    // right test even though it can't reproduce the cross-host port
    // collision itself: it proves the scheme still disambiguates the one
    // case this test process can actually produce.
    final clientA =
        await Socket.connect(InternetAddress.loopbackIPv4, listener.port);
    final clientB =
        await Socket.connect(InternetAddress.loopbackIPv4, listener.port);

    final links = await linksFuture;

    expect(links[0].id, isNot(equals(links[1].id)));

    clientA.destroy();
    clientB.destroy();
    for (final link in links) {
      await link.close();
    }
    await listener.close();
  });

  test(
      'closing the listener while a connection is being accepted does not '
      'crash or leak the socket', () async {
    // This race is a single-microtask window: LanListener's accept
    // callback runs synchronously up to `await LanLink.fromSocket(...)`,
    // which -- since fromSocket has no internal await of its own --
    // resumes on the very next microtask. In practice that leaves no gap
    // real timing (even thousands of concurrent connections, verified
    // experimentally) can reliably land in from outside: whichever
    // native "new connection" dispatch is currently draining the accept
    // backlog runs to completion, including that one microtask hop,
    // before anything else gets a turn.
    //
    // So the race is forced deterministically instead: a forked Zone
    // intercepts scheduleMicrotask calls made while LanListener's
    // `_server.listen(...)` subscription (registered inside this zone)
    // is handling a connection, and defers forwarding one of them until
    // after listener.close() has FULLY finished -- reproducing "a
    // connection accepted just before close() resumes after
    // _incoming.close()" exactly, no matter how fast or slow this
    // machine's networking stack happens to be.
    //
    // Which microtask is "the" one is an internal-structure detail, not a
    // documented contract: constructing LanLink schedules one microtask
    // of its own (for its inbound socket subscription) before the accept
    // callback's own continuation runs, so it is the second
    // scheduleMicrotask call, not the first -- confirmed by sweeping
    // slots 1-8 against the unfixed callback and observing the target
    // "StateError: Cannot add new events after calling close" appear only
    // at slot 2. (Neighbouring slots were deliberately not left in this
    // test: they intercept microtasks that close() itself depends on to
    // finish, which self-deadlocks rather than exercising anything real.)
    await _raceListenerCloseAgainstAccept(interceptAtSlot: 2);
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

/// Deterministically races [LanListener.close] against a suspended accept
/// callback. See the calling test for why this is necessary rather than
/// racing real timing.
///
/// Forces the accept callback's continuation at microtask [interceptAtSlot]
/// (counting scheduleMicrotask calls inside [listener]'s accept-handling
/// zone from the moment the probe connection is dialed) to resume only
/// after [LanListener.close] has completely finished. Then asserts that
/// resumption neither throws nor leaks the accepted socket, regardless of
/// whether this particular slot happens to be the vulnerable one.
Future<void> _raceListenerCloseAgainstAccept({
  required int interceptAtSlot,
}) async {
  var armed = false;
  var microtaskCount = 0;
  var listenerCloseCalled = false;
  late LanListener listener;
  Object? uncaughtError;
  var linkDeliveredToIncoming = false;
  Socket? client;

  await runZonedGuarded(() async {
    final raceZone = Zone.current.fork(
      specification: ZoneSpecification(
        scheduleMicrotask: (self, parent, zone, f) {
          if (armed && !listenerCloseCalled) {
            microtaskCount++;
            if (microtaskCount == interceptAtSlot) {
              listenerCloseCalled = true;
              unawaited(listener.close().then((_) {
                parent.scheduleMicrotask(zone, f);
              }));
              return;
            }
          }
          parent.scheduleMicrotask(zone, f);
        },
      ),
    );

    // LanListener.bind (and the _server.listen(...) call inside its
    // constructor) must run inside raceZone: Dart binds a stream
    // subscription's callback to the zone active at .listen() time, for
    // the life of that subscription, regardless of what zone later
    // dispatches the underlying event.
    await raceZone.run(() async {
      listener = await LanListener.bind(localDeviceId: '1' * 32);
    });
    unawaited(listener.incoming.first.then(
      (_) => linkDeliveredToIncoming = true,
      onError: (Object _) {},
    ));

    armed = true;
    // Deliberately outside raceZone: this connection's own client-side
    // machinery must not be counted by the interceptor above, which
    // should only see microtasks scheduled by the server's accept path.
    client =
        await Socket.connect(InternetAddress.loopbackIPv4, listener.port);
    // Generous margin for the deferred continuation -- and, if it lost
    // the race, the fix's own close-and-dispose of the losing link -- to
    // run; close() and a loopback socket teardown are not remotely close
    // to this slow.
    await Future<void>.delayed(const Duration(milliseconds: 200));
  }, (e, st) {
    uncaughtError = e;
  });

  expect(uncaughtError, isNull,
      reason: 'slot $interceptAtSlot: the accept callback must not throw '
          'after resuming into an already-closed listener');

  if (!linkDeliveredToIncoming) {
    // Either this slot never actually intercepted anything (fewer than
    // interceptAtSlot microtasks fired) and there is nothing to check, or
    // it is the vulnerable slot and the accepted connection lost the
    // race. Telling those apart doesn't require reaching into
    // LanListener: if the connection was ever accepted at all, the fix
    // must close that socket rather than leak it, and the client sees
    // that as its connection ending. If the connection was never
    // accepted, the client observes the same thing once the server
    // socket underneath it is gone. Either way, "the client's connection
    // ends" is the correct, and only, observable postcondition.
    final ended = Completer<void>();
    client?.listen(
      (_) {},
      onDone: () {
        if (!ended.isCompleted) ended.complete();
      },
      onError: (Object _) {
        if (!ended.isCompleted) ended.complete();
      },
    );
    if (client != null) {
      await ended.future.timeout(
        const Duration(seconds: 2),
        onTimeout: () => fail('slot $interceptAtSlot: the client never saw '
            'its connection end -- the accepted socket was leaked rather '
            'than closed'),
      );
    }
  }

  client?.destroy();
  if (!listenerCloseCalled) {
    await listener.close();
  }
}
