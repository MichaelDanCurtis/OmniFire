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

  void deliver(Object? message) => _incoming.add(message);

  @override
  Stream<Object?> get stream => _incoming.stream;

  @override
  WebSocketSink get sink => _FakeSink(this);

  @override
  int? get closeCode => null;

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
    await _channel._incoming.close();
  }

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
}
