import 'dart:async';
import 'dart:typed_data';

import 'package:web_socket_channel/web_socket_channel.dart';

import 'link.dart';

const int _addressBytes = 16;

const List<int> broadcastAddress = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

Uri relayWebSocketUri({
  required Uri relayBase,
  required String meshId,
  required String deviceId,
}) {
  final scheme = relayBase.scheme == 'https' ? 'wss' : 'ws';
  return relayBase.replace(
    scheme: scheme,
    path: '/v1/mesh/$meshId/ws',
    queryParameters: {'device': deviceId},
  );
}

Uint8List _deviceIdBytes(String deviceId) {
  if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(deviceId)) {
    throw ArgumentError.value(
        deviceId, 'deviceId', 'must be 32 lowercase hex characters');
  }
  final out = Uint8List(_addressBytes);
  for (var i = 0; i < _addressBytes; i++) {
    out[i] = int.parse(deviceId.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Uint8List addressFrame(String destinationDeviceId, List<int> body) {
  final header = _deviceIdBytes(destinationDeviceId);
  final out = Uint8List(_addressBytes + body.length);
  out.setRange(0, _addressBytes, header);
  out.setRange(_addressBytes, out.length, body);
  return out;
}

Uint8List stripAddress(List<int> framed) {
  if (framed.length < _addressBytes) {
    throw ArgumentError.value(
        framed.length, 'framed', 'shorter than the address header');
  }
  return Uint8List.fromList(framed.sublist(_addressBytes));
}

/// A [Link] that reaches the peer through the Cloudflare relay.
///
/// The relay sees only the 16-byte destination header and the length of
/// the opaque body it forwards.
class RelayLink implements Link {
  RelayLink._({
    required this.id,
    required WebSocketChannel channel,
    required String peerDeviceId,
  })  : _channel = channel,
        _peerDeviceId = peerDeviceId {
    _sub = _channel.stream.listen(
      _onMessage,
      onError: (Object error) {
        _setState(LinkState.failed);
      },
      onDone: () => _setState(LinkState.disconnected),
    );
  }

  static Future<RelayLink> connect({
    required Uri relayBase,
    required String meshId,
    required String localDeviceId,
    required String peerDeviceId,
    Duration timeout = const Duration(seconds: 10),
    WebSocketChannel Function(Uri)? channelFactory,
  }) async {
    final uri = relayWebSocketUri(
      relayBase: relayBase,
      meshId: meshId,
      deviceId: localDeviceId,
    );
    final channel =
        (channelFactory ?? WebSocketChannel.connect)(uri);
    // The relay answers a malformed mesh/device id with a plain HTTP 400
    // *before* the WebSocket upgrade completes, so no socket exists yet and
    // no close frame will ever arrive. That failure surfaces here, as the
    // `ready` future completing with an error, rather than as a close event
    // observed later on `states`.
    await channel.ready.timeout(timeout);
    return RelayLink._(
      // The host is part of the id because two relay backends (Cloudflare
      // and a self-hosted one) can be dialed for the same peer
      // simultaneously. A bare 'relay:<peer>' would collide in
      // LinkManager's candidate map and one backend would silently evict
      // the other.
      id: 'relay:${relayBase.host}:$peerDeviceId',
      channel: channel,
      peerDeviceId: peerDeviceId,
    );
  }

  @override
  final String id;

  final WebSocketChannel _channel;
  final String _peerDeviceId;

  final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  StreamSubscription<Object?>? _sub;
  LinkState _state = LinkState.connected;
  Duration? _rtt;

  @override
  LinkKind get kind => LinkKind.relay;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality => LinkQuality(kind: LinkKind.relay, rtt: _rtt);

  void recordRtt(Duration rtt) => _rtt = rtt;

  void _setState(LinkState next) {
    if (_state == next) return;
    _state = next;
    if (!_states.isClosed) _states.add(next);
  }

  void _onMessage(Object? message) {
    // The relay only ever forwards binary frames; anything else is noise.
    if (message is! List<int>) return;
    if (message.length < _addressBytes) return;
    if (_inbound.isClosed) return;
    _inbound.add(stripAddress(message));
  }

  @override
  Future<void> send(List<int> frame) async {
    if (_state != LinkState.connected) {
      throw LinkClosedError(id);
    }
    _channel.sink.add(addressFrame(_peerDeviceId, frame));
  }

  @override
  Future<void> close() async {
    _setState(LinkState.disconnected);
    await _sub?.cancel();
    await _channel.sink.close();
    if (!_inbound.isClosed) await _inbound.close();
    if (!_states.isClosed) await _states.close();
  }
}
