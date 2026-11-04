import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:stream_channel/stream_channel.dart';
import 'package:test/test.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

/// Minimal in-memory WebSocketChannel double.
class FakeChannel extends StreamChannelMixin<Object?>
    implements WebSocketChannel {
  final StreamController<Object?> _incoming =
      StreamController<Object?>.broadcast();
  final List<Object?> sent = [];
  int? _closeCode;
  bool sinkClosed = false;

  void deliver(Object? message) => _incoming.add(message);

  /// Simulates the relay closing the socket with [code], e.g. 1009 when a
  /// frame exceeded the 1 MiB limit, or `null` to simulate a close that
  /// carries no code at all.
  Future<void> deliverClose(int? code) async {
    _closeCode = code;
    await _incoming.close();
  }

  @override
  Stream<Object?> get stream => _incoming.stream;

  @override
  WebSocketSink get sink => _FakeSink(this);

  @override
  int? get closeCode => _closeCode;

  @override
  String? get closeReason => null;

  @override
  String? get protocol => null;

  @override
  Future<void> get ready async {}

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeSink implements WebSocketSink {
  _FakeSink(this._channel);
  final FakeChannel _channel;

  @override
  void add(Object? data) => _channel.sent.add(data);

  @override
  Future<void> close([int? closeCode, String? closeReason]) async {
    _channel.sinkClosed = true;
    await _channel._incoming.close();
  }

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

/// A channel whose handshake never completes, to exercise the connect()
/// timeout path.
class _HangingChannel extends StreamChannelMixin<Object?>
    implements WebSocketChannel {
  final StreamController<Object?> _incoming =
      StreamController<Object?>.broadcast();
  bool sinkClosed = false;

  @override
  Stream<Object?> get stream => _incoming.stream;

  @override
  WebSocketSink get sink => _HangingSink(this);

  @override
  int? get closeCode => null;

  @override
  String? get closeReason => null;

  @override
  String? get protocol => null;

  @override
  Future<void> get ready => Completer<void>().future;

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _HangingSink implements WebSocketSink {
  _HangingSink(this._channel);
  final _HangingChannel _channel;

  @override
  void add(Object? data) {}

  @override
  Future<void> close([int? closeCode, String? closeReason]) async {
    _channel.sinkClosed = true;
  }

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

/// A channel whose `ready` future completes with an error, as
/// web_socket_channel does when the relay rejects the handshake (e.g. an
/// HTTP 400 for a malformed mesh/device id) before the upgrade completes.
class _RejectingChannel extends StreamChannelMixin<Object?>
    implements WebSocketChannel {
  final StreamController<Object?> _incoming =
      StreamController<Object?>.broadcast();
  bool sinkClosed = false;

  @override
  Stream<Object?> get stream => _incoming.stream;

  @override
  WebSocketSink get sink => _HangingSink2(this);

  @override
  int? get closeCode => null;

  @override
  String? get closeReason => null;

  @override
  String? get protocol => null;

  @override
  Future<void> get ready =>
      Future<void>.error(StateError('HTTP 400: malformed device id'));

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _HangingSink2 implements WebSocketSink {
  _HangingSink2(this._channel);
  final _RejectingChannel _channel;

  @override
  void add(Object? data) {}

  @override
  Future<void> close([int? closeCode, String? closeReason]) async {
    _channel.sinkClosed = true;
  }

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

/// A channel whose handshake never completes, like [_HangingChannel], but
/// whose sink also never finishes closing.
///
/// Exists to prove `connect()` does not hang waiting on `sink.close()`
/// while unwinding a handshake failure. The first (broken) fix attempt
/// awaited `channel.sink.close()` before rethrowing: that passed every
/// other test in this file (every other fake's `close()` resolves on its
/// own) and then hung forever against the real relay, because the
/// channel's local side is never wired up to consume a close when `ready`
/// fails before a socket exists. This fake's `close()` never completes, so
/// it reproduces that condition deterministically.
class _HangingCloseChannel extends StreamChannelMixin<Object?>
    implements WebSocketChannel {
  final StreamController<Object?> _incoming =
      StreamController<Object?>.broadcast();

  @override
  Stream<Object?> get stream => _incoming.stream;

  @override
  WebSocketSink get sink => _HangingCloseSink();

  @override
  int? get closeCode => null;

  @override
  String? get closeReason => null;

  @override
  String? get protocol => null;

  @override
  Future<void> get ready => Completer<void>().future;

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _HangingCloseSink implements WebSocketSink {
  @override
  void add(Object? data) {}

  @override
  Future<void> close([int? closeCode, String? closeReason]) =>
      Completer<void>().future;

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  test('builds the relay websocket uri', () {
    final uri = relayWebSocketUri(
      relayBase: Uri.parse('https://relay.example.com'),
      meshId: 'a' * 32,
      deviceId: '1' * 32,
    );
    expect(uri.scheme, 'wss');
    expect(uri.path, '/v1/mesh/${'a' * 32}/ws');
    expect(uri.queryParameters['device'], '1' * 32);
  });

  test('uses ws for an http base', () {
    final uri = relayWebSocketUri(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      deviceId: '1' * 32,
    );
    expect(uri.scheme, 'ws');
    expect(uri.port, 8787);
  });

  test('prefixes a 16-byte destination address', () {
    final framed = addressFrame('2' * 32, utf8.encode('body'));
    expect(framed.length, 16 + 4);
    expect(framed.sublist(0, 16), [
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    ]);
    expect(utf8.decode(framed.sublist(16)), 'body');
  });

  test('strips the address header', () {
    final framed = addressFrame('2' * 32, utf8.encode('payload'));
    expect(utf8.decode(stripAddress(framed)), 'payload');
  });

  test('broadcast address is 16 zero bytes', () {
    expect(broadcastAddress.length, 16);
    expect(broadcastAddress.every((b) => b == 0), isTrue);
  });

  test('rejects a malformed destination device id', () {
    expect(() => addressFrame('not-hex', const []),
        throwsA(isA<ArgumentError>()));
  });

  test('rejects stripping a frame shorter than the header', () {
    expect(() => stripAddress(Uint8List(8)), throwsA(isA<ArgumentError>()));
  });

  test('connects and reports relay kind', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    expect(link.kind, LinkKind.relay);
    expect(link.quality.isDirect, isFalse);
    expect(link.state, LinkState.connected);
  });

  test('sends frames addressed to the peer', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    await link.send(utf8.encode('ciphertext'));
    final sent = fake.sent.single as Uint8List;
    expect(sent.sublist(0, 16).every((b) => b == 0x22), isTrue);
    expect(utf8.decode(sent.sublist(16)), 'ciphertext');
  });

  test('strips the header from inbound frames', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    final received = link.inbound.first;
    fake.deliver(addressFrame('1' * 32, utf8.encode('inbound')));
    expect(utf8.decode(await received), 'inbound');
  });

  test('ignores a text message from the relay', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    var frames = 0;
    link.inbound.listen((_) => frames++);
    fake.deliver('unexpected text');
    await Future<void>.delayed(const Duration(milliseconds: 10));
    expect(frames, 0);
  });

  test('sending after close throws', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    await link.close();
    expect(() => link.send(utf8.encode('x')),
        throwsA(isA<LinkClosedError>()));
  });

  group('id', () {
    test('includes the relay host and port', () async {
      final fake = FakeChannel();
      final link = await RelayLink.connect(
        relayBase: Uri.parse('http://localhost:8787'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        peerDeviceId: '2' * 32,
        channelFactory: (_) => fake,
      );
      expect(link.id, contains('localhost'));
      expect(link.id, contains('8787'));
      expect(link.id, contains('2' * 32));
    });

    test('is stable for an https base with no explicit port', () async {
      final fake = FakeChannel();
      final link = await RelayLink.connect(
        relayBase: Uri.parse('https://relay.example.com'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        peerDeviceId: '2' * 32,
        channelFactory: (_) => fake,
      );
      // Uri.port returns the scheme default (443) when absent, so the id
      // is deterministic across separate calls with the same base.
      final again = await RelayLink.connect(
        relayBase: Uri.parse('https://relay.example.com'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        peerDeviceId: '2' * 32,
        channelFactory: (_) => FakeChannel(),
      );
      expect(link.id, again.id);
    });

    test(
        'two relays on the same host at different ports for the same peer '
        'get distinct ids', () async {
      // This is the local dev setup: two relay backends both on
      // localhost, at different ports, dialed for the same peer at the
      // same time. Before the port was part of the id, both links
      // produced 'relay:localhost:<peer>' and collided in LinkManager's
      // candidate map.
      final linkA = await RelayLink.connect(
        relayBase: Uri.parse('http://localhost:8787'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        peerDeviceId: '2' * 32,
        channelFactory: (_) => FakeChannel(),
      );
      final linkB = await RelayLink.connect(
        relayBase: Uri.parse('http://localhost:8788'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        peerDeviceId: '2' * 32,
        channelFactory: (_) => FakeChannel(),
      );
      expect(linkA.id, isNot(linkB.id));
    });
  });

  group('connect() handshake failures', () {
    test('closes the channel and throws when the handshake times out',
        () async {
      final fake = _HangingChannel();
      await expectLater(
        RelayLink.connect(
          relayBase: Uri.parse('http://localhost:8787'),
          meshId: 'a' * 32,
          localDeviceId: '1' * 32,
          peerDeviceId: '2' * 32,
          timeout: const Duration(milliseconds: 20),
          channelFactory: (_) => fake,
        ),
        throwsA(anything),
      );
      expect(fake.sinkClosed, isTrue);
    });

    test(
        'rejects promptly, without waiting out the timeout, when the relay '
        'rejects the handshake before the upgrade completes', () async {
      // The relay answers a malformed mesh/device id with a plain HTTP 400
      // before the WebSocket upgrade completes, so `ready` fails
      // immediately rather than the socket ever reaching a close event.
      final fake = _RejectingChannel();
      final stopwatch = Stopwatch()..start();
      await expectLater(
        RelayLink.connect(
          relayBase: Uri.parse('http://localhost:8787'),
          meshId: 'a' * 32,
          localDeviceId: '1' * 32,
          peerDeviceId: '2' * 32,
          timeout: const Duration(seconds: 5),
          channelFactory: (_) => fake,
        ),
        throwsA(isA<StateError>()),
      );
      stopwatch.stop();
      // Generous margin so this isn't flaky, but far below the 5s timeout:
      // if connect() were waiting out the timeout instead of surfacing the
      // rejection promptly, this would fail.
      expect(stopwatch.elapsedMilliseconds, lessThan(2000));
      expect(fake.sinkClosed, isTrue);
    });

    test(
        'throws promptly rather than hanging when sink.close() never '
        'completes', () async {
      // Regression test for the first (broken) fix attempt, which awaited
      // `channel.sink.close()` before rethrowing -- see
      // _HangingCloseChannel's doc comment for why that hung against a
      // real relay despite passing every other test here. Bounded with an
      // outer timeout so a regression is a clean failure, not a stalled
      // suite.
      final fake = _HangingCloseChannel();
      await expectLater(
        RelayLink.connect(
          relayBase: Uri.parse('http://localhost:8787'),
          meshId: 'a' * 32,
          localDeviceId: '1' * 32,
          peerDeviceId: '2' * 32,
          timeout: const Duration(milliseconds: 20),
          channelFactory: (_) => fake,
        ),
        throwsA(anything),
      ).timeout(const Duration(seconds: 2));
    });
  });

  group('abnormal close', () {
    test('an explicit normal-closure close (code 1000) reports disconnected',
        () async {
      final fake = FakeChannel();
      final link = await RelayLink.connect(
        relayBase: Uri.parse('http://localhost:8787'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        peerDeviceId: '2' * 32,
        channelFactory: (_) => fake,
      );
      final states = <LinkState>[];
      link.states.listen(states.add);
      await fake.deliverClose(1000);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(link.state, LinkState.disconnected);
      expect(link.closeCode, 1000);
      expect(states, [LinkState.disconnected]);
    });

    test('a close with no code at all also reports disconnected', () async {
      // Exercises the `code == null` half of the close-code mapping's
      // `code == null || code == ws_status.normalClosure` check -- the
      // explicit-1000 test above only ever reaches the second half.
      final fake = FakeChannel();
      final link = await RelayLink.connect(
        relayBase: Uri.parse('http://localhost:8787'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        peerDeviceId: '2' * 32,
        channelFactory: (_) => fake,
      );
      final states = <LinkState>[];
      link.states.listen(states.add);
      await fake.deliverClose(null);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(link.state, LinkState.disconnected);
      expect(link.closeCode, isNull);
      expect(states, [LinkState.disconnected]);
    });

    test('a 1009 close (frame too large) reports failed with the code',
        () async {
      final fake = FakeChannel();
      final link = await RelayLink.connect(
        relayBase: Uri.parse('http://localhost:8787'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        peerDeviceId: '2' * 32,
        channelFactory: (_) => fake,
      );
      final states = <LinkState>[];
      link.states.listen(states.add);
      await fake.deliverClose(1009);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(link.state, LinkState.failed);
      expect(link.closeCode, 1009);
      expect(states, [LinkState.failed]);
    });
  });

  group('retarget', () {
    Future<({RelayLink link, FakeChannel channel})> broadcastLink() async {
      final fake = FakeChannel();
      final link = await RelayLink.connect(
        relayBase: Uri.parse('http://localhost:8787'),
        meshId: 'a' * 32,
        localDeviceId: '1' * 32,
        // How the pairing rendezvous opens a socket: no destination is known
        // yet, so everything sent goes to the whole mesh.
        peerDeviceId: broadcastDeviceId,
        channelFactory: (_) => fake,
      );
      return (link: link, channel: fake);
    }

    test('moves the destination header onto the new peer', () async {
      final f = await broadcastLink();
      await f.link.send([9]);
      expect((f.channel.sent.single as Uint8List).sublist(0, 16),
          broadcastAddress,
          reason: 'before retargeting, frames are broadcast to the mesh');

      f.link.retarget('2' * 32);
      f.channel.sent.clear();
      await f.link.send([9]);
      expect((f.channel.sent.single as Uint8List).sublist(0, 16),
          List<int>.filled(16, 0x22),
          reason: 'after retargeting, the relay routes to that device alone');
    });

    test('leaves the link id alone', () async {
      final f = await broadcastLink();
      final before = f.link.id;
      f.link.retarget('2' * 32);
      // LinkManager keys its candidate map by id; a link that renamed itself
      // mid-flight would strand the entry under the old key.
      expect(f.link.id, before);
    });

    test('rejects a malformed device id without moving the destination',
        () async {
      final f = await broadcastLink();
      expect(() => f.link.retarget('not-hex'), throwsArgumentError);
      await f.link.send([9]);
      expect((f.channel.sent.single as Uint8List).sublist(0, 16),
          broadcastAddress,
          reason: 'a rejected retarget must not half-apply');
    });

    test('rejects the all-zero broadcast id', () async {
      // broadcastDeviceId is 32 lowercase hex characters, so the hex check
      // admits it. A link only ever moves *off* the broadcast address; being
      // retargeted onto it means every subsequent frame — starting with a
      // handshake message carrying this device's real id and static public
      // key — is fanned out to every socket in the Durable Object instead of
      // going to one peer.
      final f = await broadcastLink();
      expect(() => f.link.retarget(broadcastDeviceId), throwsArgumentError);
    });
  });
}
